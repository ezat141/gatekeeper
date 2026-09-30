package com.gatekeeper.redis;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.NoSuchElementException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

/**
 * The shared connection step: one attempt at a time, which no caller can cancel; a success kept
 * for good, a failure not kept at all. The M5 design, section 7; shared since M6 (its section 7).
 */
class RedisConnectionStepTest {

    final AtomicInteger pings = new AtomicInteger();

    @Test
    void callersWhoGiveUpNeitherCancelNorRepeatTheAttempt() throws InterruptedException {
        CountDownLatch answer = new CountDownLatch(1);
        AtomicInteger interrupted = new AtomicInteger();
        RedisConnectionStep step = new RedisConnectionStep(() -> Mono.fromCallable(() -> {
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
                assertThatThrownBy(() -> step.ready().timeout(Duration.ofMillis(50)).block())
                        .hasCauseInstanceOf(TimeoutException.class);
            }
        });
        CountDownLatch connected = new CountDownLatch(1);
        step.ready().subscribe(null, error -> { }, connected::countDown);
        answer.countDown();

        assertThat(connected.await(2, TimeUnit.SECONDS)).isTrue();
        assertThat(pings).hasValue(1);
        assertThat(interrupted).hasValue(0);
    }

    @Test
    void keepsASuccess() {
        RedisConnectionStep step = new RedisConnectionStep(() -> Mono.fromCallable(() -> {
            pings.incrementAndGet();
            return "PONG";
        }));

        step.ready().block(Duration.ofSeconds(2));
        step.ready().block(Duration.ofSeconds(2));

        assertThat(pings).hasValue(1);
    }

    /** An empty ping is not a success: it must not be cached, so the next caller pings again. */
    @Test
    void anEmptyPingIsRetried() {
        RedisConnectionStep step = new RedisConnectionStep(() -> {
            int attempt = pings.incrementAndGet();
            return attempt == 1 ? Mono.empty() : Mono.just("PONG");
        });

        assertThatThrownBy(() -> step.ready().block(Duration.ofSeconds(2)))
                .isInstanceOf(NoSuchElementException.class);
        step.ready().block(Duration.ofSeconds(2));

        assertThat(pings).hasValue(2);
    }

    @Test
    void triesAgainAfterAFailure() {
        RedisConnectionStep step = new RedisConnectionStep(() -> Mono.fromCallable(() -> {
            if (pings.incrementAndGet() == 1) {
                throw new IllegalStateException("connection refused");
            }
            return "PONG";
        }));

        assertThatThrownBy(() -> step.ready().block(Duration.ofSeconds(2)))
                .hasMessageContaining("connection refused");
        step.ready().block(Duration.ofSeconds(2));

        assertThat(pings).hasValue(2);
    }
}
