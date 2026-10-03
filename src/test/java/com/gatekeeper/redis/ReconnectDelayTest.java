package com.gatekeeper.redis;

import io.lettuce.core.resource.Delay;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;

import java.time.Duration;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Lettuce reconnects within 2 s of Redis returning, not after its default backoff of up to 30 s.
 * The M7 design, section 3: in M6's live run the revocation check refused every bearer token for
 * 17.8 s after Redis was back, waiting for that backoff.
 */
@SpringBootTest
class ReconnectDelayTest {

    @Autowired
    LettuceConnectionFactory connectionFactory;

    @Test
    void neverWaitsMoreThanTwoSecondsNorLessThanAHundredMillis() {
        for (long attempt = 1; attempt <= 40; attempt++) {
            Duration delay = RedisConfig.RECONNECT_DELAY.createDelay(attempt);
            assertThat(delay).as("attempt %d", attempt)
                    .isBetween(Duration.ofMillis(100), Duration.ofSeconds(2));
        }
    }

    /** Exponential: the first attempt is quick, later ones back off to at least half the cap. */
    @Test
    void backsOffExponentially() {
        assertThat(RedisConfig.RECONNECT_DELAY.createDelay(1)).isEqualTo(Duration.ofMillis(100));
        assertThat(RedisConfig.RECONNECT_DELAY.createDelay(20)).isGreaterThanOrEqualTo(Duration.ofSeconds(1));
    }

    /** Jitter, so several gateway instances do not all reconnect in the same instant. */
    @Test
    void isJittered() {
        Set<Duration> seen = new HashSet<>();
        for (int i = 0; i < 200; i++) {
            seen.add(RedisConfig.RECONNECT_DELAY.createDelay(10));
        }
        assertThat(seen).hasSizeGreaterThan(1);
    }

    /** The client actually in use carries it, not Lettuce's default. */
    @Test
    void isTheDelayTheClientUses() {
        Delay inUse = connectionFactory.getClientResources().reconnectDelay();

        assertThat(inUse.getClass().getSimpleName()).isEqualTo("FullJitterDelay");
        assertThat(inUse.createDelay(40)).isLessThanOrEqualTo(Duration.ofSeconds(2));
    }
}
