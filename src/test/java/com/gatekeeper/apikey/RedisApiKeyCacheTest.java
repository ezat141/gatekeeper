package com.gatekeeper.apikey;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import reactor.test.StepVerifier;

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

    // RedisApiKeyCache used to take an ObjectMapper constructor argument, and this test built
    // it a bare `new ObjectMapper()` "to keep this test independent of configuration that does
    // not exist yet" — independent enough that this whole class kept passing while production,
    // wired to Boot's configured bean instead, silently never served a cache hit for a key
    // with a non-null expiresAt. The two mappers were not equivalent, and nothing here ever
    // exercised the one production actually used.
    //
    // RedisApiKeyCache now owns a fixed internal mapper (see its WIRE_MAPPER field) rather
    // than accepting one from outside, precisely so this class of gap cannot recur: there is
    // no longer an external mapper to inject, correctly or otherwise, so every test below is
    // automatically exercising the exact serializer production uses.
    @BeforeEach
    void setUp() {
        cache = new RedisApiKeyCache(redis);
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
     * An entry this process cannot parse is a miss by design, not a failure: the shape can
     * drift across a rolling deploy, and a value written by a differently-shaped version of
     * this service must not turn a caller holding a perfectly good key into a 503. Proven here
     * by writing unparseable bytes straight into Redis, bypassing {@link #cache} entirely, so
     * this exercises {@link RedisApiKeyCache}'s {@code deserialize} error path rather than
     * anything {@code put} would have prevented.
     */
    @Test
    void treatsAnUnparseableCachedEntryAsAMiss() {
        String hash = UUID.randomUUID().toString();
        try {
            redis.opsForValue().set(KEY_PREFIX + hash, "{not valid json").block();

            StepVerifier.create(cache.get(hash)).verifyComplete();
        } finally {
            delete(hash);
        }
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
