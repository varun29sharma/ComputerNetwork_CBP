package io.aegisx.ztna;

import io.lettuce.core.api.async.RedisAsyncCommands;
import io.netty.bootstrap.Bootstrap;
import io.netty.channel.Channel;
import io.netty.channel.ChannelFuture;
import io.netty.channel.ChannelHandler;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.channel.ChannelInitializer;
import io.netty.channel.socket.nio.NioSocketChannel;
import io.netty.handler.ssl.SslHandler;
import io.netty.util.AttributeKey;
import io.netty.util.ReferenceCountUtil;
import io.netty.util.concurrent.ScheduledFuture;
import java.net.InetSocketAddress;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * The Policy Enforcement Point's "zero-trust bouncer".
 *
 * <p>The server channel is accepted with {@code AUTO_READ=false}, so no client
 * payload is ever pulled into application memory before authorization. On
 * {@code channelActive} the handler extracts the source address and looks up
 * {@code route:<source_ip>} in Redis.
 *
 * <p>Five enforcement properties:
 * <ol>
 *   <li><b>Cloaking</b> -- unauthorized connections are closed with no reply,
 *       so the gateway is indistinguishable from a closed port.</li>
 *   <li><b>Non-blocking</b> -- Lettuce's asynchronous API ({@code RedisFuture})
 *       is used instead of blocking Jedis: a blocking call inside
 *       {@code channelActive} would stall a shared EventLoop thread and starve
 *       every other connection multiplexed onto it.</li>
 *   <li><b>Continuous verification</b> -- an authorized tunnel is re-checked
 *       against Redis every {@code AEGISX_REVALIDATE_SECONDS}. Revoking a
 *       session (logout, admin force-revoke, TTL expiry) therefore kills
 *       connections that are <em>already open</em>, not just future ones.</li>
 *   <li><b>Handshake first</b> -- when mTLS is enabled the route lookup waits
 *       for the TLS handshake, so an unauthenticated peer can never cause an
 *       outbound connection to a protected application.</li>
 *   <li><b>Revocation</b> -- for certificate-bound sessions the route lookup
 *       is followed by a check of {@code cert:deny:<CN>}: a revoked
 *       certificate is denied even if its route record still exists.</li>
 * </ol>
 *
 * <p>Telemetry: allow/deny/active counters ({@code pep:*}) and an append-only
 * audit stream ({@code audit:events}) shared with the control plane.
 */
@ChannelHandler.Sharable
public final class ZtnaAuthHandler extends ChannelInboundHandlerAdapter {

    private static final Logger log = LoggerFactory.getLogger(ZtnaAuthHandler.class);

    static final String ROUTE_KEY_PREFIX = "route:";
    /** Authorization namespace for certificate-bound sessions: route:device:<CN>. */
    static final String DEVICE_PREFIX = "device:";
    /** Revoked certificates, written by the control plane: cert:deny:<CN>. */
    static final String CERT_DENY_PREFIX = "cert:deny:";
    static final String AUDIT_STREAM = "audit:events";

    private static final AttributeKey<Boolean> AUTHORIZED = AttributeKey.valueOf("aegisx.authorized");
    private static final AttributeKey<ScheduledFuture<?>> REVALIDATION =
            AttributeKey.valueOf("aegisx.revalidation");
    private static final AttributeKey<String> DEVICE = AttributeKey.valueOf("aegisx.device");
    private static final AttributeKey<List<Object>> PENDING =
            AttributeKey.valueOf("aegisx.pending-payload");

    private final RedisAsyncCommands<String, String> redis;
    private final long revalidateSeconds;

    public ZtnaAuthHandler(RedisAsyncCommands<String, String> redis, long revalidateSeconds) {
        this.redis = redis;
        this.revalidateSeconds = revalidateSeconds;
    }

    // -----------------------------------------------------------------------
    // 1. Auth check: with mTLS, wait for the handshake and the verified
    //    client certificate before anything else is decided.
    // -----------------------------------------------------------------------
    @Override
    public void channelActive(ChannelHandlerContext ctx) {
        // With mTLS the client certificate must be verified before we look
        // anything up: no handshake, no route lookup, no backend connection.
        SslHandler ssl = ctx.pipeline().get(SslHandler.class);
        if (ssl != null) {
            ssl.handshakeFuture().addListener(future ->
                    ctx.channel().eventLoop().execute(() -> {
                        try {
                            if (!future.isSuccess()) {
                                log.warn("TLS handshake failed for {}: {}",
                                        remoteIp(ctx.channel()), future.cause().toString());
                                deny(ctx, remoteIp(ctx.channel()), "tls-handshake-failed");
                                return;
                            }
                            String device = clientCertCommonName(ssl);
                            if (device == null || device.isBlank()) {
                                // A verified certificate we cannot name is useless
                                // as an identity: fail closed rather than key on IP.
                                deny(ctx, remoteIp(ctx.channel()), "client-certificate-without-cn");
                                return;
                            }
                            ctx.channel().attr(DEVICE).set(device);
                            beginAuthorization(ctx, device);
                        } catch (Throwable t) {
                            log.error("Post-handshake processing failed -- failing closed", t);
                            ctx.close();
                        }
                    }));
            return;
        }
        beginAuthorization(ctx, null);
    }

    // -----------------------------------------------------------------------
    // 2. Redis lookup: does the PDP's authorization record exist for this
    //    identity? No record (or a Redis error) means deny -- fail closed.
    // -----------------------------------------------------------------------
    /**
     * Resolve the authorization identity for this connection.
     *
     * <p>When the peer presented a verified client certificate, authorization is
     * keyed on that certificate's Common Name ({@code route:device:<CN>}) and the
     * source address is irrelevant -- so a second process on the same host, or
     * the same host with a different credential, cannot inherit the tunnel.
     * Without a certificate (plaintext mode) the source address is the identity.
     */
    private void beginAuthorization(ChannelHandlerContext ctx, String device) {
        String remoteIp = remoteIp(ctx.channel());
        String routeKey = ROUTE_KEY_PREFIX + identity(device, remoteIp);

        redis.get(routeKey).whenComplete((target, error) ->
                ctx.channel().eventLoop().execute(() -> {
                    if (error != null) {
                        // Fail closed: a state-store outage must never open the gate.
                        log.error("Redis lookup failed for {} -- closing {}", routeKey, remoteIp);
                        deny(ctx, remoteIp, "state-store-error");
                        return;
                    }
                    if (target == null || target.isBlank()) {
                        deny(ctx, remoteIp, device != null
                                ? "no-device-route" : "no-route-record");
                        return;
                    }
                    if (device != null) {
                        // Certificate-bound session: a route is not enough --
                        // the certificate itself must not have been revoked.
                        checkCertNotRevoked(ctx, remoteIp, device, routeKey, target);
                        return;
                    }
                    authorize(ctx, remoteIp, routeKey, target);
                }));
    }

    // -----------------------------------------------------------------------
    // 2b. Revocation check: a revoked certificate never opens a tunnel, even
    //     when its route record still exists. Plaintext (IP) sessions skip
    //     this entirely -- there is no certificate to revoke.
    //
    //     LIVE-UNVERIFIED: Java TCP is blocked in this VM -- verify with
    //     scripts/demo_mtls.sh plus a revoked cert on a real machine.
    // -----------------------------------------------------------------------
    /**
     * Async check of {@code cert:deny:<CN>}, written by the control plane when
     * an admin revokes a device. Key present means deny (cloaked, audited);
     * a Redis error fails closed exactly like the route lookup above.
     */
    private void checkCertNotRevoked(ChannelHandlerContext ctx, String remoteIp,
            String device, String routeKey, String target) {
        String denyKey = CERT_DENY_PREFIX + device;
        redis.exists(denyKey).whenComplete((count, error) ->
                ctx.channel().eventLoop().execute(() -> {
                    if (error != null) {
                        // Fail closed: a state-store outage must never open the gate.
                        log.error("Redis revocation lookup failed for {} -- closing {}",
                                denyKey, remoteIp);
                        deny(ctx, remoteIp, "state-store-error");
                        return;
                    }
                    if (count != null && count > 0) {
                        // The CN is named in the audit detail so the deny is
                        // traceable to the revoked device, not just the IP.
                        deny(ctx, remoteIp, "cert-revoked:" + device);
                        return;
                    }
                    authorize(ctx, remoteIp, routeKey, target);
                }));
    }

    // -----------------------------------------------------------------------
    // 3. Tunnel open: the route exists, so connect to the protected app,
    //    swap this handler for the byte relays, and start revalidation.
    // -----------------------------------------------------------------------
    private void authorize(ChannelHandlerContext ctx, String remoteIp, String routeKey, String rawTarget) {
        final RouteTarget target;
        try {
            target = RouteTarget.parse(rawTarget);
        } catch (RuntimeException e) {
            log.error("Malformed route value '{}' for {} -- closing", rawTarget, remoteIp);
            deny(ctx, remoteIp, "malformed-route");
            return;
        }

        // Outbound connection to the protected app shares the client channel's
        // EventLoop, so the two channels are always handled by the same thread.
        Bootstrap outbound = new Bootstrap()
                .group(ctx.channel().eventLoop())
                .channel(NioSocketChannel.class)
                .handler(new ChannelInitializer<Channel>() {
                    @Override
                    protected void initChannel(Channel ch) {
                        ch.pipeline().addLast(new BackendToFrontendHandler(ctx.channel()));
                    }
                });

        outbound.connect(target.host(), target.port()).addListener((ChannelFuture future) -> {
            if (!future.isSuccess()) {
                log.warn("Authorized but unreachable target {} for {}: {}",
                        target, remoteIp, future.cause().toString());
                deny(ctx, remoteIp, "target-unreachable");
                return;
            }
            Channel backend = future.channel();
            Channel client = ctx.channel();

            client.attr(AUTHORIZED).set(true);
            ctx.pipeline().remove(this);
            ctx.pipeline().addLast(new FrontendToBackendHandler(backend));
            // Authorization granted: let the client's parked bytes flow.
            client.config().setAutoRead(true);
            replayPending(client, backend);

            incr("pep:allow");
            incr("pep:active");
            audit("pep.allow", remoteIp, target.toString(), client.attr(DEVICE).get(), null);
            scheduleRevalidation(client, remoteIp, routeKey, rawTarget);
            client.closeFuture().addListener(closed -> closeTunnel(client, remoteIp, target.toString()));

            log.info("ALLOW  {} [key {}] -> {} (route value: {})",
                    remoteIp, routeKey, target, rawTarget);
        });
    }

    // -----------------------------------------------------------------------
    // 4. Revalidation: an open tunnel is re-checked against Redis on a
    //    timer, so a logout or admin revoke kills it mid-connection.
    // -----------------------------------------------------------------------
    /**
     * Continuous verification: while the tunnel is open, re-read the route
     * record. Missing (revoked/expired) or changed means the session no longer
     * exists in the PDP's view, so the open tunnel is torn down immediately.
     */
    private void scheduleRevalidation(Channel client, String remoteIp, String routeKey, String expectedTarget) {
        if (revalidateSeconds <= 0) {
            return;
        }
        ScheduledFuture<?> task = client.eventLoop().scheduleAtFixedRate(() -> {
            if (!client.isActive()) {
                return;
            }
            redis.get(routeKey).whenComplete((current, error) ->
                    client.eventLoop().execute(() -> {
                        if (!client.isActive()) {
                            return;
                        }
                        if (error != null) {
                            log.error("Revalidation lookup failed for {}: {}", routeKey, error.toString());
                            revokeOpenTunnel(client, remoteIp, "state-store-error");
                        } else if (current == null || current.isBlank()) {
                            revokeOpenTunnel(client, remoteIp, "session-revoked");
                        } else if (!current.equals(expectedTarget)) {
                            revokeOpenTunnel(client, remoteIp, "route-changed");
                        }
                    }));
        }, revalidateSeconds, revalidateSeconds, TimeUnit.SECONDS);
        client.attr(REVALIDATION).set(task);
    }

    private void revokeOpenTunnel(Channel client, String remoteIp, String reason) {
        log.warn("REVOKE {} -- {} (revalidation)", remoteIp, reason);
        audit("pep.revoke", remoteIp, null, client.attr(DEVICE).get(), reason);
        incr("pep:revoked");
        client.close();
    }

    // -----------------------------------------------------------------------
    // 5. Close: stop the revalidation timer, drop the counters, and (for a
    //    deny) release any parked payload without forwarding a byte.
    // -----------------------------------------------------------------------
    private void closeTunnel(Channel client, String remoteIp, String target) {
        ScheduledFuture<?> task = client.attr(REVALIDATION).getAndSet(null);
        if (task != null) {
            task.cancel(false);
        }
        if (Boolean.TRUE.equals(client.attr(AUTHORIZED).getAndSet(false))) {
            decr("pep:active");
            incr("pep:closed");
            audit("tunnel.closed", remoteIp, target, client.attr(DEVICE).get(), null);
        }
    }

    private void deny(ChannelHandlerContext ctx, String remoteIp, String reason) {
        incr("pep:deny");
        audit("pep.deny", remoteIp, null, ctx.channel().attr(DEVICE).get(), reason);
        releasePending(ctx.channel());
        log.info("DENY  {} ({}) -- closing without reaching any application", remoteIp, reason);
        ctx.close();
    }

    // -----------------------------------------------------------------------
    // Pre-authorization payload: in mTLS mode reads are enabled so the
    // handshake can complete, so bytes may arrive before the decision.
    // They are parked here, replayed into the tunnel only on allow, and
    // released (never forwarded) on deny.
    // -----------------------------------------------------------------------
    /**
     * Holds payload that arrived before the authorization decision (possible in
     * mTLS mode, where reads are enabled so the handshake can complete). It is
     * released to the protected app only after the route check succeeds, so an
     * unauthorized client still cannot deliver a byte to anything.
     */
    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        if (Boolean.TRUE.equals(ctx.channel().attr(AUTHORIZED).get())) {
            ctx.fireChannelRead(msg);
            return;
        }
        List<Object> pending = ctx.channel().attr(PENDING).get();
        if (pending == null) {
            pending = new ArrayList<>();
            ctx.channel().attr(PENDING).set(pending);
        }
        pending.add(msg);
    }

    private void replayPending(Channel client, Channel backend) {
        List<Object> pending = client.attr(PENDING).getAndSet(null);
        if (pending == null || pending.isEmpty()) {
            return;
        }
        log.debug("replaying {} pre-authorization message(s) into the tunnel", pending.size());
        for (Object msg : pending) {
            backend.write(msg);
        }
        backend.flush();
    }

    private void releasePending(Channel client) {
        List<Object> pending = client.attr(PENDING).getAndSet(null);
        if (pending != null) {
            for (Object msg : pending) {
                ReferenceCountUtil.release(msg);
            }
        }
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        log.debug("Closing channel after exception: {}", cause.toString());
        ctx.close();
    }

    // -----------------------------------------------------------------------
    // Telemetry (fire-and-forget; failures must not affect enforcement)
    // -----------------------------------------------------------------------
    private void incr(String key) {
        redis.incr(key).whenComplete((value, error) -> {
            if (error != null) {
                log.debug("counter {} not updated: {}", key, error.toString());
            }
        });
    }

    private void decr(String key) {
        redis.decr(key).whenComplete((value, error) -> {
            if (error != null) {
                log.debug("counter {} not updated: {}", key, error.toString());
            }
        });
    }

    private void audit(String event, String remoteIp, String target, String device, String reason) {
        Map<String, String> body = new LinkedHashMap<>();
        body.put("event", event);
        body.put("ts", String.valueOf(System.currentTimeMillis() / 1000L));
        body.put("layer", "pep");
        if (remoteIp != null) {
            body.put("client_ip", remoteIp);
        }
        if (target != null) {
            body.put("target", target);
        }
        if (device != null && !device.isBlank()) {
            body.put("device", device);
        }
        if (reason != null) {
            body.put("detail", reason);
        }
        redis.xadd(AUDIT_STREAM, body).whenComplete((id, error) -> {
            if (error != null) {
                log.debug("audit event {} not recorded: {}", event, error.toString());
            }
        });
    }

    /** Common Name of the verified client certificate (cryptographic identity). */
    private static String clientCertCommonName(SslHandler ssl) {
        try {
            java.security.cert.Certificate[] chain =
                    ssl.engine().getSession().getPeerCertificates();
            if (chain.length > 0 && chain[0] instanceof X509Certificate cert) {
                String subjectDn = cert.getSubjectX500Principal().getName();
                for (String rdnPart : subjectDn.split(",")) {
                    String trimmed = rdnPart.trim();
                    if (trimmed.startsWith("CN=")) {
                        return trimmed.substring(3);
                    }
                }
                return subjectDn;
            }
        } catch (Exception e) {
            log.debug("no client certificate identity available: {}", e.toString());
        }
        return null;
    }

    /** The Redis authorization identity for this connection. */
    static String identity(String device, String remoteIp) {
        return (device != null && !device.isBlank()) ? DEVICE_PREFIX + device : remoteIp;
    }

    /** Source IP, normalized so IPv4-mapped IPv6 addresses match Redis keys. */
    static String remoteIp(Channel channel) {
        InetSocketAddress remote = (InetSocketAddress) channel.remoteAddress();
        String host = remote.getAddress().getHostAddress();
        if (host.startsWith("::ffff:")) {
            host = host.substring("::ffff:".length());
        }
        return host;
    }
}
