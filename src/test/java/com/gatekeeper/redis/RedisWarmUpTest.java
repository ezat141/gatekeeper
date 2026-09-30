package com.gatekeeper.redis;

import org.junit.jupiter.api.Test;
import org.springframework.data.redis.RedisConnectionFailureException;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.function.Supplier;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

/**
 * The startup warm-up waits a bounded time on the shared connection step and never fails the
 * boot. The M5 design, section 7.
 */
class RedisWarmUpTest {

    /**
     * A ping that blocks inside subscribe, as Lettuce does while it opens its shared connection on
     * a Redis that accepts and never answers. Without the step's worker thread the timeout would
     * never start; without the timeout the wait would never end.
     */
    @Test
    void returnsWithinTheBoundWhenRedisNeverAnswers() {
        CountDownLatch never = new CountDownLatch(1);
        RedisWarmUp warmUp = warmUp(() -> Mono.fromCallable(() -> {
            never.await();
            return "PONG";
        }));

        assertTimeoutPreemptively(Duration.ofSeconds(3), warmUp::afterSingletonsInstantiated);
    }

    @Test
    void returnsQuietlyWhenThePingFails() {
        RedisWarmUp warmUp = warmUp(() -> Mono.error(new RedisConnectionFailureException("connection refused")));

        assertTimeoutPreemptively(Duration.ofSeconds(3), warmUp::afterSingletonsInstantiated);
    }

    @Test
    void pingsOnceAndReturnsWhenRedisAnswers() {
        AtomicInteger pings = new AtomicInteger();
        RedisWarmUp warmUp = warmUp(() -> Mono.fromCallable(() -> {
            pings.incrementAndGet();
            return "PONG";
        }));

        assertTimeoutPreemptively(Duration.ofSeconds(3), warmUp::afterSingletonsInstantiated);

        assertThat(pings).hasValue(1);
    }

    /** The real composition: the warm-up on a connection step whose ping stands in for Redis. */
    private static RedisWarmUp warmUp(Supplier<Mono<?>> ping) {
        return new RedisWarmUp(new RedisConnectionStep(ping));
    }
}
