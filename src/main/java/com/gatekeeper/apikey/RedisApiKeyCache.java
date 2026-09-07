package com.gatekeeper.apikey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import reactor.core.publisher.Mono;
import tools.jackson.databind.ObjectMapper;
import tools.jackson.databind.json.JsonMapper;

import java.time.Duration;

/**
 * Caches introspection answers under the SHA-256 of the key, never the key itself. The
 * database stores a hash for the same reason: a dump of this store must not hand anybody a
 * working credential.
 */
public class RedisApiKeyCache implements ApiKeyCache {

    private static final Logger log = LoggerFactory.getLogger(RedisApiKeyCache.class);

    private static final String KEY_PREFIX = "gatekeeper:apikey:";

    /**
     * Deliberately not the application's {@code ObjectMapper} bean. What this class writes
     * and reads is a private wire format between GateKeeper and itself — nothing outside this
     * class ever sees it — not a document exchanged with a caller, so it has no business
     * moving when someone retunes {@code spring.jackson.*} for an unrelated reason (a new
     * downstream client's date-format expectations, say). Sharing the app-wide bean would
     * make this cache's ability to read its own writes hostage to configuration this class
     * does not own and cannot see change. Built once, statically: it is stateless and
     * thread-safe, and every instance of this class must serialize and deserialize the exact
     * same way regardless of how many get constructed.
     */
    private static final ObjectMapper WIRE_MAPPER = JsonMapper.builder().build();

    private final ReactiveStringRedisTemplate redis;

    public RedisApiKeyCache(ReactiveStringRedisTemplate redis) {
        this.redis = redis;
    }

    @Override
    public Mono<ApiKeyIntrospection> get(String keyHash) {
        return redis.opsForValue().get(KEY_PREFIX + keyHash)
                .flatMap(this::deserialize);
    }

    @Override
    public Mono<Void> put(String keyHash, ApiKeyIntrospection introspection, Duration ttl) {
        return Mono.fromCallable(() -> WIRE_MAPPER.writeValueAsString(introspection))
                .flatMap(json -> redis.opsForValue().set(KEY_PREFIX + keyHash, json, ttl))
                .then();
    }

    /**
     * A cached entry this process cannot read is treated as a miss, not as a failure. The
     * shape could change across a rolling deploy, and a stale entry must not turn into a
     * 503 for a caller holding a perfectly good key.
     */
    private Mono<ApiKeyIntrospection> deserialize(String json) {
        return Mono.fromCallable(() -> WIRE_MAPPER.readValue(json, ApiKeyIntrospection.class))
                .onErrorResume(error -> {
                    log.warn("Unreadable cached API-key introspection entry; treating as a miss", error);
                    return Mono.empty();
                });
    }
}
