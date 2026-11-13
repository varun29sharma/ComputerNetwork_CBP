package io.aegisx.ztna;

import io.lettuce.core.RedisClient;
import io.lettuce.core.RedisURI;
import io.lettuce.core.api.StatefulRedisConnection;
import io.lettuce.core.api.async.RedisAsyncCommands;
import io.netty.bootstrap.ServerBootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.ChannelOption;
import io.netty.channel.EventLoopGroup;
import io.netty.channel.nio.NioEventLoopGroup;
import io.netty.channel.socket.nio.NioServerSocketChannel;
import io.netty.channel.socket.SocketChannel;
import io.netty.handler.ssl.ClientAuth;
import io.netty.handler.ssl.SslContext;
import io.netty.handler.ssl.SslContextBuilder;
import java.io.File;
import java.net.HttpURLConnection;
import java.net.URL;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * AegisX Data Plane -- the Policy Enforcement Point (PEP).
 *
 * <p>Listens for client TCP connections and mediates every byte flowing to the
 * protected applications. It makes no trust decisions of its own: the only
 * authority it consults is the {@code route:<client_ip>} record provisioned by
 * the control plane's Policy Administrator. Connections without a record are
 * closed before a single byte of payload is read (SDP "Authenticate-Before-
 * Connect" / cloaking).
 *
 * <p>Fail-closed by design: with no {@code route:} record the gate stays shut
 * (cloaked -- the connection is closed with no reply). That is also what a
 * not-ready control plane means in practice: while the PDP reports
 * {@code /ready} as not ready, no new tunnels are provisioned, so no new
 * connections get in; already-open tunnels keep running until revalidation
 * notices their route is gone.
 *
 * <p>Configuration (env):
 * <ul>
 *   <li>{@code AEGISX_PEP_PORT} (default 9000)</li>
 *   <li>{@code AEGISX_REDIS_URL} (default redis://127.0.0.1:6379)</li>
 *   <li>{@code AEGISX_REVALIDATE_SECONDS} (default 5, 0 disables) --
 *       how often every <em>open</em> tunnel is re-checked against Redis</li>
 *   <li>{@code AEGISX_MTLS} = 1 to require a client certificate, with
 *       {@code AEGISX_MTLS_CERT}, {@code AEGISX_MTLS_KEY},
 *       {@code AEGISX_MTLS_CA} (see scripts/gen_certs.sh)</li>
 *   <li>{@code AEGISX_PEP_REQUIRE_READY} = 1 to wait for the control
 *       plane's {@code /ready} endpoint before binding (default off), with
 *       {@code AEGISX_PDP_URL} (default http://127.0.0.1:8000)</li>
 * </ul>
 */
public final class ZtnaProxyServer {

    private static final Logger log = LoggerFactory.getLogger(ZtnaProxyServer.class);

    public static void main(String[] args) throws Exception {
        int port = Integer.parseInt(env("AEGISX_PEP_PORT", "9000"));
        String redisUri = env("AEGISX_REDIS_URL", "redis://127.0.0.1:6379");
        long revalidate = Long.parseLong(env("AEGISX_REVALIDATE_SECONDS", "5"));

        // Optional startup gate (default off): refuse to bind at all until
        // the control plane reports ready, so a PEP never listens while the
        // PDP cannot provision routes. When the flag is off, no HTTP call
        // is made and startup is exactly as before.
        if ("1".equals(env("AEGISX_PEP_REQUIRE_READY", "0"))) {
            requireControlPlaneReady(env("AEGISX_PDP_URL", "http://127.0.0.1:8000"));
        }

        // One shared, thread-safe async connection; every route lookup returns
        // a RedisFuture instead of blocking an EventLoop thread.
        RedisClient redisClient = RedisClient.create(RedisURI.create(redisUri));
        StatefulRedisConnection<String, String> redisConnection = redisClient.connect();
        RedisAsyncCommands<String, String> redis = redisConnection.async();

        final SslContext sslContext = mtlsEnabled() ? buildServerSslContext() : null;

        EventLoopGroup bossGroup = new NioEventLoopGroup(1);
        EventLoopGroup workerGroup = new NioEventLoopGroup();

        // Sharable: the handler is stateless apart from the shared Redis handle.
        ZtnaAuthHandler authHandler = new ZtnaAuthHandler(redis, revalidate);

        ServerBootstrap bootstrap = new ServerBootstrap()
                .group(bossGroup, workerGroup)
                .channel(NioServerSocketChannel.class)
                // SDP cloak: never read payload until the handler authorizes.
                // With mTLS the TLS handshake itself must be read before any
                // decision is possible, so reads stay enabled there -- the
                // handler then buffers everything that arrives before
                // authorization and releases it only once the tunnel exists,
                // so no payload reaches a protected app unauthorized either way.
                .childOption(ChannelOption.AUTO_READ, sslContext != null)
                .childOption(ChannelOption.TCP_NODELAY, true)
                .childHandler(new ChannelInitializer<SocketChannel>() {
                    @Override
                    protected void initChannel(SocketChannel ch) {
                        if (sslContext != null) {
                            // Require the client certificate; the auth handler
                            // waits for handshake completion before deciding.
                            ch.pipeline().addLast(sslContext.newHandler(ch.alloc()));
                        }
                        ch.pipeline().addLast(authHandler);
                    }
                });

        Channel serverChannel = bootstrap.bind(port).sync().channel();
        log.info("AegisX ZTNA PEP (Policy Enforcement Point) listening on :{} (redis: {}, revalidation: {}, mTLS: {})",
                port, redisUri,
                revalidate > 0 ? revalidate + "s" : "disabled",
                sslContext != null ? "required" : "off");
        log.info("cloak: pre-authorization payload {}",
                sslContext == null ? "never read (AUTO_READ=false)" : "buffered, never forwarded pre-authorization");

        Runtime.getRuntime().addShutdownHook(new Thread(() -> {
            serverChannel.close();
            bossGroup.shutdownGracefully();
            workerGroup.shutdownGracefully();
            redisConnection.close();
            redisClient.shutdown();
        }, "aegisx-shutdown"));

        serverChannel.closeFuture().sync();
    }

    private static boolean mtlsEnabled() {
        return "1".equals(env("AEGISX_MTLS", "0"));
    }

    // -----------------------------------------------------------------------
    // Startup readiness gate: poll the control plane's /ready endpoint
    // before binding. If it never answers 200, exit without listening --
    // a PEP that cannot reach its PDP must not accept connections.
    //
    // LIVE-UNVERIFIED: Java TCP is blocked in this VM -- verify by starting
    // the PEP with Redis down and AEGISX_PEP_REQUIRE_READY=1 on a real machine.
    // -----------------------------------------------------------------------
    private static void requireControlPlaneReady(String pdpUrl) {
        String readyUrl = pdpUrl + "/ready";
        for (int attempt = 1; attempt <= 10; attempt++) {
            if (controlPlaneReady(readyUrl)) {
                log.info("control plane ready at {} (attempt {})", readyUrl, attempt);
                return;
            }
            if (attempt < 10) {
                // Backoff grows 1s, 2s, 3s ... capped at 5s.
                sleepSeconds(Math.min(attempt, 5));
            }
        }
        log.error("control plane never became ready at {} after 10 attempts -- exiting without binding",
                readyUrl);
        System.exit(1);
    }

    /** One readiness probe: true only on HTTP 200, false on any failure. */
    private static boolean controlPlaneReady(String readyUrl) {
        HttpURLConnection connection = null;
        try {
            connection = (HttpURLConnection) new URL(readyUrl).openConnection();
            connection.setConnectTimeout(2000);
            connection.setReadTimeout(2000);
            connection.setRequestMethod("GET");
            return connection.getResponseCode() == 200;
        } catch (Exception e) {
            log.debug("readiness probe failed for {}: {}", readyUrl, e.toString());
            return false;
        } finally {
            if (connection != null) {
                connection.disconnect();
            }
        }
    }

    private static void sleepSeconds(long seconds) {
        try {
            Thread.sleep(seconds * 1000L);
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
        }
    }

    /** Server context that demands a certificate signed by the AegisX demo CA. */
    private static SslContext buildServerSslContext() throws Exception {
        String cert = required("AEGISX_MTLS_CERT");
        String key = required("AEGISX_MTLS_KEY");
        String ca = required("AEGISX_MTLS_CA");
        log.info("mTLS enabled: cert={} ca={}", cert, ca);
        return SslContextBuilder
                .forServer(new File(cert), new File(key))
                .trustManager(new File(ca))
                .clientAuth(ClientAuth.REQUIRE)
                .build();
    }

    private static String required(String name) {
        String value = System.getenv(name);
        if (value == null || value.isBlank()) {
            throw new IllegalStateException(name + " must be set when AEGISX_MTLS=1");
        }
        return value;
    }

    private static String env(String name, String fallback) {
        String value = System.getenv(name);
        return (value == null || value.isBlank()) ? fallback : value;
    }
}
