package com.gatekeeper.apikey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import reactor.core.publisher.Mono;
import tools.jackson.databind.ObjectMapper;

import java.time.Duration;

/**
 * Caches introspection answers under the SHA-256 of the key, never the key itself. The
 * database stores a hash for the same reason: a dump of this store must not hand anybody a
 * working credential.
 */
public class RedisApiKeyCache implements ApiKeyCache {

    private static final Logger log = LoggerFactory.getLogger(RedisApiKeyCache.class);

    private static final String KEY_PREFIX = "gatekeeper:apikey:";

    private final ReactiveStringRedisTemplate redis;
    private final ObjectMapper objectMapper;

    public RedisApiKeyCache(ReactiveStringRedisTemplate redis, ObjectMapper objectMapper) {
        this.redis = redis;
        this.objectMapper = objectMapper;
    }

    @Override
    public Mono<ApiKeyIntrospection> get(String keyHash) {
        return redis.opsForValue().get(KEY_PREFIX + keyHash)
                .flatMap(this::deserialize);
    }

    @Override
    public Mono<Void> put(String keyHash, ApiKeyIntrospection introspection, Duration ttl) {
        return Mono.fromCallable(() -> objectMapper.writeValueAsString(introspection))
                .flatMap(json -> redis.opsForValue().set(KEY_PREFIX + keyHash, json, ttl))
                .then();
    }

    /**
     * A cached entry this process cannot read is treated as a miss, not as a failure. The
     * shape could change across a rolling deploy, and a stale entry must not turn into a
     * 503 for a caller holding a perfectly good key.
     */
    private Mono<ApiKeyIntrospection> deserialize(String json) {
        return Mono.fromCallable(() -> objectMapper.readValue(json, ApiKeyIntrospection.class))
                .onErrorResume(error -> {
                    log.warn("Unreadable cached API-key introspection entry; treating as a miss", error);
                    return Mono.empty();
                });
    }
}
