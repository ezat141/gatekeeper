package com.gatekeeper.revocation;

import com.gatekeeper.redis.RedisConnectionStep;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import reactor.core.publisher.Mono;

/**
 * Reads AuthCore's deny-list. The contract is AuthCore's {@code RevocationService}: it writes
 * {@code authcore:revoked:jti:<jti>}, value {@code "revoked"}, with a TTL equal to the token's
 * remaining lifetime, so an entry disappears exactly when the token would have expired anyway. One
 * {@code EXISTS} answers the question; the value is never read. The M6 design, section 2.
 *
 * <p>Connects through the shared {@link RedisConnectionStep}, so a silent Redis cannot block an event
 * loop or leak a connection per timed-out request (the M5 design, section 7). The timeout and the
 * breaker are the caller's: {@code RevocationCheckingJwtDecoder}.
 */
public class RedisRevocationStore implements RevocationStore {

    private static final String KEY_PREFIX = "authcore:revoked:jti:";

    private final ReactiveStringRedisTemplate redis;
    private final RedisConnectionStep connection;

    public RedisRevocationStore(ReactiveStringRedisTemplate redis, RedisConnectionStep connection) {
        this.redis = redis;
        this.connection = connection;
    }

    static String key(String jti) {
        return KEY_PREFIX + jti;
    }

    @Override
    public Mono<Boolean> isRevoked(String jti) {
        return connection.ready().then(Mono.defer(() -> redis.hasKey(key(jti))));
    }
}
