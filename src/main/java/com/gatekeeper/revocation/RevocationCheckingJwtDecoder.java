package com.gatekeeper.revocation;

import com.gatekeeper.redis.RedisCircuitBreaker;
import com.gatekeeper.redis.RedisCircuitBreaker.Permit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtClaimNames;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;

import java.time.Duration;

/**
 * Refuses a revoked token, however valid its signature. The M6 design, sections 3 to 8.
 *
 * <p><strong>After every other check.</strong> The inner decoder verifies the signature against the
 * JWKS and validates {@code exp}, {@code nbf} and the pinned {@code iss} first. Only a token that
 * passes all of it reaches Redis, so a forged or expired token — whose {@code jti} an outsider picks
 * freely — cannot generate Redis load.
 *
 * <p><strong>A revoked token is an invalid token:</strong> a {@link BadJwtException}, which
 * Spring Security answers with the same 401 as an expired or forged one. So is a token with no
 * {@code jti}, or a blank one: it could never be revoked, so it does not pass a gateway that enforces
 * revocation (section 6).
 *
 * <p><strong>Fails closed, fast.</strong> A Redis error, a timeout, an empty answer, or an open
 * breaker is a {@link RevocationUnavailableException}: 503, never an admitted request. An open
 * breaker means <em>refuse</em> — the rate limiter's breaker means "skip Redis and forward", and
 * copying that here would fail open. Only the store call is mapped to a failure: a revoked token is
 * Redis answering, and must not count towards opening the breaker.
 */
public class RevocationCheckingJwtDecoder implements ReactiveJwtDecoder {

    private static final Logger log = LoggerFactory.getLogger(RevocationCheckingJwtDecoder.class);

    private final ReactiveJwtDecoder delegate;
    private final RevocationStore store;
    private final RedisCircuitBreaker breaker;
    private final Duration timeout;

    public RevocationCheckingJwtDecoder(ReactiveJwtDecoder delegate, RevocationStore store,
                                        RedisCircuitBreaker breaker, Duration timeout) {
        this.delegate = delegate;
        this.store = store;
        this.breaker = breaker;
        this.timeout = timeout;
    }

    @Override
    public Mono<Jwt> decode(String token) throws JwtException {
        return delegate.decode(token).flatMap(this::check);
    }

    private Mono<Jwt> check(Jwt jwt) {
        String jti = jwt.getId();
        if (!StringUtils.hasText(jti)) {
            // Only the issuer can sign a token without one, so this is an issuer bug, and an
            // outsider cannot flood this line.
            log.warn("Refused a validly signed token with no jti, which could never be revoked: sub={}, iss={}",
                    jwt.getSubject(), jwt.getClaimAsString(JwtClaimNames.ISS));
            return Mono.error(new BadJwtException("The token has no jti, so it cannot be revoked"));
        }
        return Mono.defer(() -> isRevoked(jti))
                .flatMap(revoked -> {
                    if (revoked) {
                        // DEBUG: a holder can replay a revoked token as fast as they like, and the
                        // limiter never sees it. Counting these is M8's audit event.
                        log.debug("Refused revoked token {}", jti);
                        return Mono.error(new BadJwtException("The token has been revoked"));
                    }
                    return Mono.just(jwt);
                });
    }

    /** The store call alone, behind the breaker and the timeout; its failures, and only its, map to 503. */
    private Mono<Boolean> isRevoked(String jti) {
        // Taken when the check runs, not when the decode was assembled (section 7).
        Permit permit = breaker.allowCall();
        if (permit == Permit.DENIED) {
            log.debug("Revocation check's breaker is open; refusing token {}", jti);
            return Mono.error(new RevocationUnavailableException("the revocation check's breaker is open", null));
        }
        return store.isRevoked(jti)
                .timeout(timeout)
                .switchIfEmpty(Mono.error(() -> new IllegalStateException("the revocation store answered nothing")))
                // The permit taken before the call, not the breaker's state now: only a probe's
                // success may close it.
                .doOnNext(answer -> breaker.recordSuccess(permit))
                .onErrorMap(error -> {
                    breaker.recordFailure(permit, error);
                    log.debug("Revocation check could not be completed for token {}: {}", jti, error.toString());
                    return new RevocationUnavailableException("the revocation check could not be completed", error);
                });
    }
}
