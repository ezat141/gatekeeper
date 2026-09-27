package com.gatekeeper.ratelimit;

import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;

/** The limiter's breaker, on a fake clock. The M5 design, section 7. */
class RedisCircuitBreakerTest {

    static final Duration WINDOW = Duration.ofSeconds(5);

    final AtomicLong now = new AtomicLong(1_000_000_000L);
    final RedisCircuitBreaker breaker = new RedisCircuitBreaker(WINDOW, now::get);

    @Test
    void allowsEveryCallWhileClosed() {
        assertThat(breaker.allowCall()).isTrue();
        assertThat(breaker.allowCall()).isTrue();
    }

    @Test
    void aFailureOpensItForTheWindow() {
        breaker.recordFailure(new IllegalStateException("redis down"));

        assertThat(breaker.allowCall()).isFalse();
        advance(WINDOW.minusMillis(1));
        assertThat(breaker.allowCall()).isFalse();
    }

    @Test
    void afterTheWindowExactlyOneCallerProbes() {
        breaker.recordFailure(new IllegalStateException("redis down"));
        advance(WINDOW);

        assertThat(breaker.allowCall()).isTrue();
        assertThat(breaker.allowCall()).isFalse();
        assertThat(breaker.allowCall()).isFalse();
    }

    @Test
    void aSuccessfulProbeClosesIt() {
        breaker.recordFailure(new IllegalStateException("redis down"));
        advance(WINDOW);
        assertThat(breaker.allowCall()).isTrue();

        assertThat(breaker.recordSuccess()).isTrue();

        assertThat(breaker.allowCall()).isTrue();
        assertThat(breaker.allowCall()).isTrue();
    }

    @Test
    void aFailedProbeReopensItForAnotherWindow() {
        breaker.recordFailure(new IllegalStateException("redis down"));
        advance(WINDOW);
        assertThat(breaker.allowCall()).isTrue();

        breaker.recordFailure(new IllegalStateException("still down"));

        advance(WINDOW.minusMillis(1));
        assertThat(breaker.allowCall()).isFalse();
        advance(Duration.ofMillis(1));
        assertThat(breaker.allowCall()).isTrue();
    }

    @Test
    void aSuccessWhileClosedIsNotARecovery() {
        assertThat(breaker.recordSuccess()).isFalse();
        assertThat(breaker.allowCall()).isTrue();
    }

    private void advance(Duration by) {
        now.addAndGet(by.toNanos());
    }
}
