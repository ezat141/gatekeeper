package com.gatekeeper.ratelimit;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

/**
 * The store's connection step: one attempt at a time, which no caller can cancel; a success kept
 * for good, a failure not kept at all. The M5 design, section 7.
 */
class RedisRateLimitStoreConnectTest {

    final AtomicInteger pings = new AtomicInteger();

    @Test
    void callersWhoGiveUpNeitherCancelNorRepeatTheAttempt() throws InterruptedException {
        CountDownLatch answer = new CountDownLatch(1);
        AtomicInteger interrupted = new AtomicInteger();
        RedisRateLimitStore store = new RedisRateLimitStore(null, () -> Mono.fromCallable(() -> {
            pings.incrementAndGet();
            try {
                // blocks inside subscribe, as Lettuce's connect does
                answer.await();
            } catch (InterruptedException ex) {
                interrupted.incrementAndGet();
                throw ex;
            }
            return "PONG";
        }));

        // Preemptive, so a step that blocked its caller inside subscribe fails rather than hangs.
        assertTimeoutPreemptively(Duration.ofSeconds(3), () -> {
            for (int i = 0; i < 3; i++) {
                assertThatThrownBy(() -> store.connect().timeout(Duration.ofMillis(50)).block())
                        .hasCauseInstanceOf(TimeoutException.class);
            }
        });
        CountDownLatch connected = new CountDownLatch(1);
        store.connect().subscribe(null, error -> { }, connected::countDown);
        answer.countDown();

        assertThat(connected.await(2, TimeUnit.SECONDS)).isTrue();
        assertThat(pings).hasValue(1);
        assertThat(interrupted).hasValue(0);
    }

    @Test
    void keepsASuccess() {
        RedisRateLimitStore store = new RedisRateLimitStore(null, () -> Mono.fromCallable(() -> {
            pings.incrementAndGet();
            return "PONG";
        }));

        store.connect().block(Duration.ofSeconds(2));
        store.connect().block(Duration.ofSeconds(2));

        assertThat(pings).hasValue(1);
    }

    @Test
    void triesAgainAfterAFailure() {
        RedisRateLimitStore store = new RedisRateLimitStore(null, () -> Mono.fromCallable(() -> {
            if (pings.incrementAndGet() == 1) {
                throw new IllegalStateException("connection refused");
            }
            return "PONG";
        }));

        assertThatThrownBy(() -> store.connect().block(Duration.ofSeconds(2)))
                .hasMessageContaining("connection refused");
        store.connect().block(Duration.ofSeconds(2));

        assertThat(pings).hasValue(2);
    }
}
