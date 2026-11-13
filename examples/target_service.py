"""Stand-in for a protected internal application behind the AegisX PEP.

The control plane grants a micro-tunnel to 127.0.0.1:8080 for the
'internal-api' app; run this on that port to have something to reach.

Two modes:
  * default  -- tiny HTTP service (what the manual walkthrough and curl use).
  * --hold    -- raw TCP service that keeps the connection open (HTTP/1.0 would
                 close after each response, which would make it impossible to
                 observe the PEP tearing down an *already-open* tunnel when a
                 session is revoked). Used by scripts/demo_e2e.sh to prove
                 continuous verification.
"""
import argparse
import json
import socket
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer

def hold_banner(port: int) -> bytes:
    """Identify the instance that answered, so a demo can prove *which*
    application a connection reached and not merely that one did."""
    return ("aegisx-demo-target tunnel established on :%d\n" % port).encode()


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = json.dumps(
            {
                "service": "aegisx-demo-target",
                "path": self.path,
                "peer": self.client_address[0],
                # Lets a caller prove *which* instance answered, so a demo can
                # show a tunnel landed on one specific application.
                "port": self.server.server_address[1],
            }
        ).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        print("[target] %s - %s" % (self.client_address[0], fmt % args), flush=True)


def serve_hold(port: int) -> None:
    """Accept connections, announce the tunnel, and never close on our side."""
    srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    srv.bind(("127.0.0.1", port))
    srv.listen(32)
    print("[target] holding-connection mode on :%d" % port, flush=True)

    banner = hold_banner(port)

    def handle(conn: socket.socket) -> None:
        with conn:
            try:
                conn.sendall(banner)
                while True:
                    data = conn.recv(4096)
                    if not data:
                        print("[target] client closed the connection", flush=True)
                        return
                    conn.sendall(b"echo: " + data)
            except OSError:
                print("[target] connection torn down", flush=True)

    while True:
        conn, _ = srv.accept()
        threading.Thread(target=handle, args=(conn,), daemon=True).start()


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8080)
    parser.add_argument(
        "--hold",
        action="store_true",
        help="keep each connection open (for proving live-tunnel revocation)",
    )
    args = parser.parse_args()
    if args.hold:
        serve_hold(args.port)
    else:
        print("[target] listening on :%d" % args.port, flush=True)
        HTTPServer(("127.0.0.1", args.port), Handler).serve_forever()
