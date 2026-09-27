package com.gatekeeper.ratelimit;

import java.nio.charset.StandardCharsets;

/**
 * Whose bucket a request counts against: a tenant, or else a client, or else an API key. The
 * M5 design, section 4.
 *
 * <p>{@link #key()} is the Redis-safe form, {@code <kind>:<name>}. The name is percent-encoded
 * outside {@code [A-Za-z0-9._-]}. No caller can choose an identity — every part comes from a
 * signed token or from introspection — but an odd name must still never break the key's
 * structure or the {@code {…}} hash tag it is wrapped in.
 */
public record RateLimitIdentity(Kind kind, String name) {

    public enum Kind {
        TENANT("tenant"),
        CLIENT("client"),
        API_KEY("apikey");

        private final String prefix;

        Kind(String prefix) {
            this.prefix = prefix;
        }
    }

    public String key() {
        return kind.prefix + ":" + encode(name);
    }

    static String encode(String raw) {
        StringBuilder encoded = new StringBuilder();
        for (byte b : raw.getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xFF;
            boolean plain = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '.' || c == '_' || c == '-';
            if (plain) {
                encoded.append((char) c);
            } else {
                encoded.append('%').append(String.format("%02X", c));
            }
        }
        return encoded.toString();
    }
}
