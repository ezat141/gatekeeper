package com.gatekeeper.apikey;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import reactor.test.StepVerifier;
import tools.jackson.databind.ObjectMapper;

import java.time.Duration;
import java.time.Instant;
import java.util.Set;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * This is the integration test named in {@link ApiKeyCache}'s class comment — the manager
 * (Task 10) is unit-tested against a fake instead. Requires Redis: the same Docker container
 * AuthCore uses, started with {@code docker compose up -d postgres redis} from the authcore
 * repo if it is not already running.
 *
 * <p>Each test uses a freshly random key rather than a fixed string, and deletes what it wrote
 * afterward, so tests cannot pollute each other or leave litter in a Redis instance shared with
 * AuthCore.
 */
@SpringBootTest
class RedisApiKeyCacheTest {

    private static final String KEY_PREFIX = "gatekeeper:apikey:";

    @Autowired
    ReactiveStringRedisTemplate redis;

    RedisApiKeyCache cache;

    @BeforeEach
    void setUp() {
        // Not the bean Task 11 wires up in GatewaySecurityConfig — a plain ObjectMapper keeps
        // this test independent of configuration that does not exist yet.
        cache = new RedisApiKeyCache(redis, new ObjectMapper());
    }

    @Test
    void storesAndReadsBackAnIntrospection() {
        String hash = UUID.randomUUID().toString();
        ApiKeyIntrospection stored = new ApiKeyIntrospection(
                true, "reporting", Set.of("payments:read"), Instant.now().plusSeconds(3600));

        try {
            StepVerifier.create(cache.put(hash, stored, Duration.ofSeconds(60)).then(cache.get(hash)))
                    .assertNext(read -> {
                        assertThat(read.active()).isTrue();
                        assertThat(read.name()).isEqualTo("reporting");
                        assertThat(read.scopes()).containsExactly("payments:read");
                    })
                    .verifyComplete();
        } finally {
            delete(hash);
        }
    }

    @Test
    void returnsEmptyForAHashItHasNeverSeen() {
        StepVerifier.create(cache.get(UUID.randomUUID().toString())).verifyComplete();
    }

    /**
     * The stored key must be the hash, never the credential. A Redis dump or a {@code KEYS}
     * scan must not yield anything usable — see {@link RedisApiKeyCache}'s class comment.
     */
    @Test
    void namesTheRedisKeyByHashAndNotByCredential() {
        String hash = UUID.randomUUID().toString();
        try {
            cache.put(hash, ApiKeyIntrospection.inactive(), Duration.ofSeconds(30)).block();

            StepVerifier.create(redis.hasKey(KEY_PREFIX + hash))
                    .expectNext(true)
                    .verifyComplete();
        } finally {
            delete(hash);
        }
    }

    /**
     * Jackson 3 folds {@code java.time} support directly into databind — there is no separate
     * module to register, and if that support were subtly broken this round trip is exactly
     * what would catch it, so it earns its own test rather than being assumed from the general
     * one above. Nanosecond precision stresses it harder than a real {@code expiresAt} ever
     * would.
     */
    @Test
    void preservesAnInstantAcrossTheRoundTrip() {
        String hash = UUID.randomUUID().toString();
        Instant expiresAt = Instant.parse("2026-09-02T12:34:56.123456789Z");
        ApiKeyIntrospection stored = new ApiKeyIntrospection(true, "reporting", Set.of(), expiresAt);

        try {
            StepVerifier.create(cache.put(hash, stored, Duration.ofSeconds(60)).then(cache.get(hash)))
                    .assertNext(read -> assertThat(read.expiresAt()).isEqualTo(expiresAt))
                    .verifyComplete();
        } finally {
            delete(hash);
        }
    }

    private void delete(String keyHash) {
        redis.delete(KEY_PREFIX + keyHash).block();
    }
}
