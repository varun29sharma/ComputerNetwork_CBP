package io.aegisx.ztna;

import io.netty.channel.Channel;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/** Relays bytes backend -&gt; client for an authorized tunnel. */
final class BackendToFrontendHandler extends ChannelInboundHandlerAdapter {

    private static final Logger log = LoggerFactory.getLogger(BackendToFrontendHandler.class);

    private final Channel frontend;

    BackendToFrontendHandler(Channel frontend) {
        this.frontend = frontend;
    }

    @Override
    public void channelRead(ChannelHandlerContext ctx, Object msg) {
        frontend.writeAndFlush(msg);
    }

    @Override
    public void channelInactive(ChannelHandlerContext ctx) {
        frontend.close();
    }

    @Override
    public void exceptionCaught(ChannelHandlerContext ctx, Throwable cause) {
        log.debug("Backend closed after exception: {}", cause.toString());
        ctx.close();
    }
}
