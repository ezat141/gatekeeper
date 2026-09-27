package com.gatekeeper.ratelimit;

import com.gatekeeper.apikey.ApiKeyAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.nio.charset.StandardCharsets;
import java.util.List;
import java.util.Objects;
import java.util.Optional;

/**
 * Whose bucket a request counts against: a tenant, or else a client, or else an API key. The
 * M5 design, section 4.
 *
 * <p>{@link #key()} is the Redis-safe form, {@code <kind>:<name>}. The name is percent-encoded
 * outside {@code [A-Za-z0-9._-]}. A caller cannot name an arbitrary identity — every part comes
 * from a signed token or from introspection — but an odd name must still never break the key's
 * structure or the {@code {…}} hash tag it is wrapped in.
 */
public record RateLimitIdentity(Kind kind, String name) {

    public RateLimitIdentity {
        Objects.requireNonNull(kind, "kind");
        Objects.requireNonNull(name, "name");
    }

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

    /**
     * Derives the identity of an authenticated caller.
     *
     * <ul>
     *   <li>A JWT carrying a non-blank {@code tenant} — every user token — is its tenant. Every
     *       user of a tenant shares the tenant's plan, which is what a plan means for a tenant.
     *       A blank tenant is treated as absent here, so such a token is limited by its client;
     *       {@code TenantAuthorizationManager} and {@code IdentityStampFilter} treat only a
     *       missing claim as absent. AuthCore never issues a blank tenant, so the two cannot
     *       disagree on a real token.</li>
     *   <li>A tenant-less JWT — client credentials — is its client: the first {@code aud}, which
     *       Spring Authorization Server sets to the client id, else {@code sub}, which on a
     *       client-credentials token is that same client id. {@code aud} is <em>read</em> as
     *       identity here, not validated: AuthCore's {@code aud} names the client, not a resource
     *       server, so there is nothing to validate it against. It is signed, so a caller cannot
     *       name an arbitrary bucket. One exception is recorded as an open item: an OIDC ID
     *       token, which also carries the client as {@code aud} and no {@code tenant}, would
     *       count against its client rather than its tenant — see the handoff. See the M5
     *       design, section 4.</li>
     *   <li>An API key is its name, from introspection.</li>
     * </ul>
     *
     * Anything else has no identity. Every routed request is authenticated, so that is not
     * expected to happen.
     */
    public static Optional<RateLimitIdentity> of(Authentication authentication) {
        if (authentication instanceof JwtAuthenticationToken jwtAuthentication) {
            Jwt token = jwtAuthentication.getToken();
            String tenant = token.getClaimAsString("tenant");
            if (tenant != null && !tenant.isBlank()) {
                return Optional.of(new RateLimitIdentity(Kind.TENANT, tenant));
            }
            List<String> audience = token.getAudience();
            String audienceClient = audience != null && !audience.isEmpty() ? audience.get(0) : null;
            String client = audienceClient != null && !audienceClient.isBlank() ? audienceClient : token.getSubject();
            return client != null && !client.isBlank()
                    ? Optional.of(new RateLimitIdentity(Kind.CLIENT, client))
                    : Optional.empty();
        }
        if (authentication instanceof ApiKeyAuthenticationToken apiKey && apiKey.isAuthenticated()) {
            return Optional.ofNullable(apiKey.getName()).map(name -> new RateLimitIdentity(Kind.API_KEY, name));
        }
        return Optional.empty();
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
