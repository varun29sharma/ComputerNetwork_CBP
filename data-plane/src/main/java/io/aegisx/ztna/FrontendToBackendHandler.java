package io.aegisx.ztna;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Relays bytes client -&gt; backend for an authorized tunnel.
 *
 * <p>The frontend (client-facing) channel runs with {@code AUTO_READ=false}
 * until authorization completes, so pre-authorization bytes stay parked in the
 * kernel socket buffer and are only read once the tunnel exists.
 */
final class FrontendToBackendHandler extends ChannelInboundHandlerAdapter {

    private static final Logger log = LoggerFactory.getLogger(FrontendToBackendHandler.class);

    private final Channel backend;

    FrontendToBackendHandler(Channel backend) {
        this.backend = backend;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        backend.writeAndFlush(msg);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        backend.close();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        log.debug("Frontend closed after exception: {}", cause.toString());
        ctx.close();
    }
}
