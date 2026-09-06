package com.gatekeeper.apikey;

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
 * claim. That is the whole composability property: M4 writes one
 * {@code hasAuthority("SCOPE_payments:read")} rule that accepts either credential without
 * branching on how the caller authenticated. AuthCore made the same choice internally.
 */
public class ApiKeyReactiveAuthenticationManager implements ReactiveAuthenticationManager {

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
                .switchIfEmpty(introspectAndCache(rawKey, keyHash))
                .flatMap(ApiKeyReactiveAuthenticationManager::toAuthentication)
                // Defence in depth. AuthenticationWebFilter reads an empty Mono from a
                // manager as "no authentication attempted" and CONTINUES the chain, so an
                // empty completion anywhere above would silently become the JWT fallthrough
                // that the precedence rule forbids. IntrospectionClient already refuses to
                // complete empty; this guarantees it regardless of what it does later.
                .switchIfEmpty(Mono.error(new IntrospectionUnavailableException(
                        "Introspection produced no answer", null)));
    }

    private Mono<ApiKeyIntrospection> introspectAndCache(String rawKey, String keyHash) {
        return client.introspect(rawKey)
                .flatMap(result -> cache.put(keyHash, result, ttlFor(result)).thenReturn(result));
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
            return refuseSelfIntrospection();
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
     * why.
     */
    private static Mono<Authentication> refuseSelfIntrospection() {
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
