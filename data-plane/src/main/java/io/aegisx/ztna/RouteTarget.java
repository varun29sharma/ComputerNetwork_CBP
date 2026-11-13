package io.aegisx.ztna;

/**
 * The authorized micro-tunnel destination parsed out of a Redis route value
 * (format: {@code host:port}, e.g. {@code 10.0.0.50:8080}).
 *
 * <p>Parsing is strict on purpose: a malformed route value must fail loudly
 * (the auth handler then closes the connection) rather than being guessed at,
 * because guessing a destination could send a client to the wrong application.
 */
public record RouteTarget(String host, int port) {

    public static RouteTarget parse(String value) {
        int idx = value.lastIndexOf(':');
        if (idx <= 0 || idx == value.length() - 1) {
            throw new IllegalArgumentException("malformed route value: " + value);
        }
        String host = value.substring(0, idx);
        int port = Integer.parseInt(value.substring(idx + 1));
        if (port < 1 || port > 65535) {
            throw new IllegalArgumentException("port out of range in route value: " + value);
        }
        return new RouteTarget(host, port);
    }

    @Override
    public String toString() {
        return host + ":" + port;
    }
}
