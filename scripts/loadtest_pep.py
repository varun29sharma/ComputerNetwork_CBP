#!/usr/bin/env python3
"""Hammer the AegisX PEP with concurrent TCP connections and report latency.

Stdlib only (socket + concurrent.futures + statistics + argparse). Measures
accept-to-close latency: connect(), send a minimal request, read until the PEP
closes. The PEP *cloaks* unauthorized connections (closed with no payload), so
with no login beforehand "closed fast, zero bytes" is the EXPECTED result: it
proves the gate answers (and denies) quickly instead of stalling. Log in first
to measure the authorized path instead.

Usage: python3 scripts/loadtest_pep.py [-n 1000 -c 200] [--port 9000]
"""
import argparse
import socket
import statistics
import time
from collections import Counter
from concurrent.futures import ThreadPoolExecutor

REQUEST = b"GET / HTTP/1.0\r\nHost: loadtest\r\n\r\n"


def probe_once(host, port, timeout):
    """One connection. Returns (latency_seconds, outcome):
    closed (cloak, expected pre-login) | data (a tunnel answered) |
    timeout | error (connect/send failed)."""
    t0 = time.monotonic()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
        sock.settimeout(timeout)
        sock.sendall(REQUEST)
        got_data = False
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            got_data = True
        sock.close()
    except socket.timeout:
        return time.monotonic() - t0, "timeout"
    except OSError:
        return time.monotonic() - t0, "error"
    return time.monotonic() - t0, ("data" if got_data else "closed")


def percentile(sorted_values, pct):
    """Nearest-rank percentile (good enough for a demo harness)."""
    if not sorted_values:
        return 0.0
    index = min(len(sorted_values) - 1, int(pct / 100 * len(sorted_values)))
    return sorted_values[index]


def main():
    parser = argparse.ArgumentParser(description="Load-test the AegisX PEP.")
    parser.add_argument("--host", default="127.0.0.1", help="PEP host (default 127.0.0.1)")
    parser.add_argument("--port", type=int, default=9000, help="PEP port (default 9000, the AEGISX_PEP_PORT default)")
    parser.add_argument("-n", "--connections", type=int, default=200, help="total connections (default 200)")
    parser.add_argument("-c", "--concurrency", type=int, default=50, help="in flight at once (default 50)")
    parser.add_argument("--timeout", type=float, default=5.0, help="per-connection timeout, seconds (default 5)")
    args = parser.parse_args()
    if args.connections < 1 or args.concurrency < 1:
        parser.error("connections and concurrency must both be >= 1")

    t_start = time.monotonic()
    with ThreadPoolExecutor(max_workers=args.concurrency) as pool:
        results = list(pool.map(
            lambda _: probe_once(args.host, args.port, args.timeout),
            range(args.connections)))
    wall = time.monotonic() - t_start

    latencies = sorted(lat for lat, _ in results)
    outcomes = Counter(outcome for _, outcome in results)

    print("PEP %s:%d -- %d connections, %d concurrent, %.2fs wall"
          % (args.host, args.port, args.connections, args.concurrency, wall))
    print("outcomes: %s" % ", ".join("%s=%d" % kv for kv in sorted(outcomes.items())))
    print("latency ms: mean %.1f  p50 %.1f  p99 %.1f  max %.1f" % (
        statistics.mean(latencies) * 1000, percentile(latencies, 50) * 1000,
        percentile(latencies, 99) * 1000, latencies[-1] * 1000))
    print("throughput: %.0f connections/sec" % (args.connections / wall))


if __name__ == "__main__":
    main()
