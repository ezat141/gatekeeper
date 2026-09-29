package com.gatekeeper.ratelimit;

import com.gatekeeper.ratelimit.RedisCircuitBreaker.Permit;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;

/** The limiter's breaker, on a fake clock. The M5 design, section 7. */
class RedisCircuitBreakerTest {

    static final Duration WINDOW = Duration.ofSeconds(5);
    static final IllegalStateException DOWN = new IllegalStateException("redis down");

    final AtomicLong now = new AtomicLong(1_000_000_000L);
    final RedisCircuitBreaker breaker = new RedisCircuitBreaker(WINDOW, now::get);

    @Test
    void allowsEveryCallWhileClosed() {
        assertThat(breaker.allowCall()).isEqualTo(Permit.CLOSED);
        assertThat(breaker.allowCall()).isEqualTo(Permit.CLOSED);
    }

    @Test
    void aFailureOpensItForTheWindow() {
        assertThat(breaker.recordFailure(breaker.allowCall(), DOWN)).isTrue();

        assertThat(breaker.allowCall()).isEqualTo(Permit.DENIED);
        advance(WINDOW.minusMillis(1));
        assertThat(breaker.allowCall()).isEqualTo(Permit.DENIED);
    }

    @Test
    void afterTheWindowExactlyOneCallerProbes() {
        breaker.recordFailure(breaker.allowCall(), DOWN);
        advance(WINDOW);

        assertThat(breaker.allowCall()).isEqualTo(Permit.PROBE);
        assertThat(breaker.allowCall()).isEqualTo(Permit.DENIED);
        assertThat(breaker.allowCall()).isEqualTo(Permit.DENIED);
    }

    @Test
    void onlyTheProbeClosesIt() {
        breaker.recordFailure(breaker.allowCall(), DOWN);
        advance(WINDOW);
        Permit probe = breaker.allowCall();
        assertThat(probe).isEqualTo(Permit.PROBE);
        assertThat(breaker.allowCall()).isEqualTo(Permit.DENIED);

        assertThat(breaker.recordSuccess(probe)).isTrue();

        assertThat(breaker.allowCall()).isEqualTo(Permit.CLOSED);
        assertThat(breaker.allowCall()).isEqualTo(Permit.CLOSED);
    }

    /** A request already in flight when the breaker opened answers late: that is not a recovery. */
    @Test
    void aLateSuccessFromBeforeTheOpeningDoesNotCloseIt() {
        Permit inFlight = breaker.allowCall();
        assertThat(inFlight).isEqualTo(Permit.CLOSED);
        breaker.recordFailure(breaker.allowCall(), DOWN);

        assertThat(breaker.recordSuccess(inFlight)).isFalse();

        assertThat(breaker.allowCall()).isEqualTo(Permit.DENIED);
    }

    @Test
    void aFailedProbeReopensItForAnotherWindow() {
        breaker.recordFailure(breaker.allowCall(), DOWN);
        advance(WINDOW);
        Permit probe = breaker.allowCall();
        assertThat(probe).isEqualTo(Permit.PROBE);

        assertThat(breaker.recordFailure(probe, new IllegalStateException("still down"))).isFalse();

        advance(WINDOW.minusMillis(1));
        assertThat(breaker.allowCall()).isEqualTo(Permit.DENIED);
        advance(Duration.ofMillis(1));
        assertThat(breaker.allowCall()).isEqualTo(Permit.PROBE);
    }

    @Test
    void aSuccessWhileClosedIsNotARecovery() {
        assertThat(breaker.recordSuccess(breaker.allowCall())).isFalse();
        assertThat(breaker.allowCall()).isEqualTo(Permit.CLOSED);
    }

    /**
     * A Redis answering around the timeout: requests from before the opening keep succeeding and
     * failing late. Only one opening may come of it — not one per late success.
     */
    @Test
    void lateAnswersAroundTheTimeoutOpenItOnlyOnce() {
        int openings = breaker.recordFailure(breaker.allowCall(), DOWN) ? 1 : 0;

        for (int i = 0; i < 100; i++) {
            breaker.recordSuccess(Permit.CLOSED);
            if (breaker.recordFailure(Permit.CLOSED, DOWN)) {
                openings++;
            }
        }

        assertThat(openings).isEqualTo(1);
        assertThat(breaker.allowCall()).isEqualTo(Permit.DENIED);
    }

    private void advance(Duration by) {
        now.addAndGet(by.toNanos());
    }
}
