package com.gatekeeper.apikey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Validates an API key against a short-TTL cache in front of AuthCore's introspection
 * endpoint, and turns its scopes into authorities.
 *
 * <p>Scopes become {@code SCOPE_*}, the shape Spring derives from a JWT's {@code scope}
 * claim. That is the whole composability property: each scope rule in {@code
 * com.gatekeeper.authz.RouteScopeAuthorizationManager} accepts either credential without
 * branching on how the caller authenticated. AuthCore made the same choice internally.
 */
public class ApiKeyReactiveAuthenticationManager implements ReactiveAuthenticationManager {

    private static final Logger log = LoggerFactory.getLogger(ApiKeyReactiveAuthenticationManager.class);

    /** A caller holding this scope would be the gateway itself. See refuseSelfIntrospection. */
    static final String INTROSPECTION_SCOPE = "apikeys:introspect";

    private final ApiKeyCache cache;
    private final IntrospectionClient client;
    private final ApiKeyProperties properties;

    public ApiKeyReactiveAuthenticationManager(
            ApiKeyCache cache, IntrospectionClient client, ApiKeyProperties properties) {
        this.cache = cache;
        this.client = client;
        this.properties = properties;
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        String rawKey = (String) authentication.getCredentials();
        String keyHash = sha256(rawKey);

        return cache.get(keyHash)
                .switchIfEmpty(Mono.defer(() -> introspectAndCache(rawKey, keyHash)))
                .flatMap(ApiKeyReactiveAuthenticationManager::toAuthentication)
                // Defence in depth. AuthenticationWebFilter currently turns an empty manager
                // result into IllegalStateException("No provider found for ..."), which
                // surfaces as a 500. This makes the failure say what it actually is, so it
                // answers 503 once that mapping lands, and it does not depend on the
                // framework continuing to fail closed here. IntrospectionClient already
                // refuses to complete empty; this holds regardless of what it does later.
                .switchIfEmpty(Mono.error(new IntrospectionUnavailableException(
                        "Introspection produced no answer", null)));
    }

    private Mono<ApiKeyIntrospection> introspectAndCache(String rawKey, String keyHash) {
        return client.introspect(rawKey)
                .flatMap(result -> {
                    Duration ttl = ttlFor(result);
                    // A zero TTL is not "expire immediately" to Redis — Spring Data Redis turns
                    // it into a SET with no expiry at all, so the entry would outlive the key it
                    // describes and never be re-introspected. An answer already past its own
                    // expiry must not be cached.
                    if (ttl.isZero() || ttl.isNegative()) {
                        return Mono.just(result);
                    }
                    return cache.put(keyHash, result, ttl).thenReturn(result);
                });
    }

    /**
     * Never cache past the key's own expiry. Without the clamp a key expiring in two
     * seconds, cached for sixty, would keep authenticating for fifty-eight seconds after
     * it died.
     */
    private Duration ttlFor(ApiKeyIntrospection result) {
        if (!result.active()) {
            return properties.negativeCacheTtl();
        }
        Duration configured = properties.cacheTtl();
        if (result.expiresAt() == null) {
            return configured;
        }
        Duration untilExpiry = Duration.between(Instant.now(), result.expiresAt());
        if (untilExpiry.isNegative() || untilExpiry.isZero()) {
            return Duration.ZERO;
        }
        return untilExpiry.compareTo(configured) < 0 ? untilExpiry : configured;
    }

    private static Mono<Authentication> toAuthentication(ApiKeyIntrospection result) {
        if (!result.active()) {
            return Mono.error(new BadCredentialsException("API key is not valid"));
        }
        if (result.scopes().contains(INTROSPECTION_SCOPE)) {
            return refuseSelfIntrospection(result.name());
        }

        Set<SimpleGrantedAuthority> authorities = result.scopes().stream()
                .map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope))
                .collect(Collectors.toSet());

        return Mono.just(new ApiKeyAuthenticationToken(result.name(), authorities));
    }

    /**
     * The gateway's own introspection key is a valid key, so introspection reports it
     * active. Accepting it here would let anyone who obtained it authenticate <em>as the
     * gateway</em> by replaying the credential the gateway itself puts on the wire.
     * Refused with the same message as any other bad key — a caller learns nothing about
     * why — but logged server-side by name, both because presenting this key is a security
     * event worth a record and because it turns "a legitimate key was accidentally granted
     * this scope" from an inexplicable 401 into a one-line diagnosis. Never the raw key or
     * its hash: those are credentials, and a log is not where they belong.
     */
    private static Mono<Authentication> refuseSelfIntrospection(String name) {
        log.warn("Refused a caller presenting the gateway's own introspection key (name={})", name);
        return Mono.error(new BadCredentialsException("API key is not valid"));
    }

    static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is required but unavailable", ex);
        }
    }
}
