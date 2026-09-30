package com.gatekeeper.revocation;

import com.gatekeeper.redis.RedisConnectionStep;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The store against the real Redis, reading exactly the key AuthCore's {@code RevocationService}
 * writes. The M6 design, sections 2 and 9.
 *
 * <p>This Redis is shared with AuthCore and every other test: each test uses a fresh {@code jti} and
 * deletes its key afterwards.
 */
@SpringBootTest
class RedisRevocationStoreTest {

    @Autowired
    ReactiveStringRedisTemplate redis;

    @Autowired
    RedisConnectionStep connection;

    private final List<String> written = new ArrayList<>();

    @AfterEach
    void deleteKeys() {
        written.forEach(key -> redis.delete(key).block());
    }

    @Test
    void readsAuthCoresKey() {
        assertThat(RedisRevocationStore.key("abc")).isEqualTo("authcore:revoked:jti:abc");
    }

    @Test
    void aDenyListedJtiIsRevoked() {
        String jti = revoke(Duration.ofMinutes(1));

        assertThat(store().isRevoked(jti).block()).isTrue();
    }

    @Test
    void anUnknownJtiIsNotRevoked() {
        assertThat(store().isRevoked(UUID.randomUUID().toString()).block()).isFalse();
    }

    /** AuthCore's entries expire with the token: an expired entry is no longer a revocation. */
    @Test
    void anExpiredEntryIsNotRevoked() throws InterruptedException {
        String jti = revoke(Duration.ofMillis(100));
        Thread.sleep(300);

        assertThat(store().isRevoked(jti).block()).isFalse();
    }

    @Test
    void waitsOnTheConnectionStep() {
        RedisConnectionStep refused = new RedisConnectionStep(
                () -> Mono.error(new IllegalStateException("connection refused")));

        assertThatThrownBy(() -> new RedisRevocationStore(redis, refused).isRevoked("any").block())
                .hasMessageContaining("connection refused");
    }

    private RedisRevocationStore store() {
        return new RedisRevocationStore(redis, connection);
    }

    /** Writes the entry the way AuthCore's RevocationService does: value "revoked", with a TTL. */
    private String revoke(Duration ttl) {
        String jti = UUID.randomUUID().toString();
        String key = RedisRevocationStore.key(jti);
        written.add(key);
        redis.opsForValue().set(key, "revoked", ttl).block();
        return jti;
    }
}