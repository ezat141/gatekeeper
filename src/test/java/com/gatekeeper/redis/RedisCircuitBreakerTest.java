package com.gatekeeper.redis;

import com.gatekeeper.redis.RedisCircuitBreaker.Permit;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicLong;

import static org.assertj.core.api.Assertions.assertThat;

/** The breaker, on a fake clock. The M5 design, section 7; the M6 design, section 7. */
@ExtendWith(OutputCaptureExtension.class)
class RedisCircuitBreakerTest {

    static final Duration WINDOW = Duration.ofSeconds(5);
    static final IllegalStateException DOWN = new IllegalStateException("redis down");

    final AtomicLong now = new AtomicLong(1_000_000_000L);
    final RedisCircuitBreaker breaker = new RedisCircuitBreaker("Test consumer", "doing the test thing",
            WINDOW, RedisCircuitBreaker.FAILURES_TO_OPEN, now::get);

    @Test
    void allowsEveryCallWhileClosed() {
        assertThat(breaker.allowCall()).isEqualTo(Permit.CLOSED);
        assertThat(breaker.allowCall()).isEqualTo(Permit.CLOSED);
    }

    /** A single timeout may be the gateway's own slowness: it affects only its own request, no more. */
    @Test
    void oneFailureDoesNotOpenIt() {
        assertThat(breaker.recordFailure(breaker.allowCall(), DOWN)).isFalse();

        assertThat(breaker.allowCall()).isEqualTo(Permit.CLOSED);
    }

    @Test
    void threeConsecutiveFailuresOpenIt() {
        assertThat(breaker.recordFailure(breaker.allowCall(), DOWN)).isFalse();
        assertThat(breaker.recordFailure(breaker.allowCall(), DOWN)).isFalse();
        assertThat(breaker.recordFailure(breaker.allowCall(), DOWN)).isTrue();

        assertThat(breaker.allowCall()).isEqualTo(Permit.DENIED);
    }

    @Test
    void aSuccessResetsTheCount() {
        breaker.recordFailure(breaker.allowCall(), DOWN);
        breaker.recordFailure(breaker.allowCall(), DOWN);
        assertThat(breaker.recordSuccess(breaker.allowCall())).isFalse();
        assertThat(breaker.recordFailure(breaker.allowCall(), DOWN)).isFalse();
        assertThat(breaker.recordFailure(breaker.allowCall(), DOWN)).isFalse();

        assertThat(breaker.allowCall()).isEqualTo(Permit.CLOSED);

        assertThat(breaker.recordFailure(breaker.allowCall(), DOWN)).isTrue();
        assertThat(breaker.allowCall()).isEqualTo(Permit.DENIED);
    }

    @Test
    void itStaysOpenForTheWindow() {
        open();

        assertThat(breaker.allowCall()).isEqualTo(Permit.DENIED);
        advance(WINDOW.minusMillis(1));
        assertThat(breaker.allowCall()).isEqualTo(Permit.DENIED);
    }

    @Test
    void afterTheWindowExactlyOneCallerProbes() {
        open();
        advance(WINDOW);

        assertThat(breaker.allowCall()).isEqualTo(Permit.PROBE);
        assertThat(breaker.allowCall()).isEqualTo(Permit.DENIED);
        assertThat(breaker.allowCall()).isEqualTo(Permit.DENIED);
    }

    @Test
    void onlyTheProbeClosesIt() {
        open();
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
        open();

        assertThat(breaker.recordSuccess(inFlight)).isFalse();

        assertThat(breaker.allowCall()).isEqualTo(Permit.DENIED);
    }

    @Test
    void aFailedProbeReopensItForAnotherWindow() {
        open();
        advance(WINDOW);
        Permit probe = breaker.allowCall();
        assertThat(probe).isEqualTo(Permit.PROBE);

        assertThat(breaker.recordFailure(probe, new IllegalStateException("still down"))).isFalse();

        advance(WINDOW.minusMillis(1));
        assertThat(breaker.allowCall()).isEqualTo(Permit.DENIED);
        advance(Duration.ofMillis(1));
        assertThat(breaker.allowCall()).isEqualTo(Permit.PROBE);
    }

    /**
     * The evidence is already in: one failed probe re-opens the breaker for a window from its
     * failure, without waiting for three. The probe fails a while after it was let through, as a
     * probe that times out does, so the window cannot be the one its permit started.
     */
    @Test
    void aFailedProbeReopensAtOnce() {
        open();
        advance(WINDOW);
        Permit probe = breaker.allowCall();
        assertThat(probe).isEqualTo(Permit.PROBE);
        advance(Duration.ofMillis(200));

        breaker.recordFailure(probe, new IllegalStateException("still down"));

        assertThat(breaker.allowCall()).isEqualTo(Permit.DENIED);
        advance(WINDOW.minusMillis(1));
        assertThat(breaker.allowCall()).isEqualTo(Permit.DENIED);
        advance(Duration.ofMillis(1));
        assertThat(breaker.allowCall()).isEqualTo(Permit.PROBE);
    }

    @Test
    void theCountStartsAgainAfterItCloses() {
        open();
        advance(WINDOW);
        assertThat(breaker.recordSuccess(breaker.allowCall())).isTrue();

        assertThat(breaker.recordFailure(breaker.allowCall(), DOWN)).isFalse();

        assertThat(breaker.allowCall()).isEqualTo(Permit.CLOSED);
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
        int openings = 0;
        for (int i = 0; i < RedisCircuitBreaker.FAILURES_TO_OPEN; i++) {
            if (breaker.recordFailure(breaker.allowCall(), DOWN)) {
                openings++;
            }
        }

        for (int i = 0; i < 100; i++) {
            breaker.recordSuccess(Permit.CLOSED);
            // enough late failures to reach the threshold if the success had wrongly closed it
            for (int j = 0; j < RedisCircuitBreaker.FAILURES_TO_OPEN; j++) {
                if (breaker.recordFailure(Permit.CLOSED, DOWN)) {
                    openings++;
                }
            }
        }

        assertThat(openings).isEqualTo(1);
        assertThat(breaker.allowCall()).isEqualTo(Permit.DENIED);
    }

    /**
     * Two consumers share this class: each line must say whose Redis, and what happens meanwhile.
     * The output is captured for the whole class, so each log test uses a name no other test does.
     */
    @Test
    void itsOpeningNamesItsConsumerAndWhatHappensWhileOpen(CapturedOutput output) {
        RedisCircuitBreaker own = new RedisCircuitBreaker("Opening consumer", "doing the test thing",
                WINDOW, RedisCircuitBreaker.FAILURES_TO_OPEN, now::get);

        for (int i = 0; i < RedisCircuitBreaker.FAILURES_TO_OPEN; i++) {
            own.recordFailure(own.allowCall(), DOWN);
        }

        assertThat(output).contains(
                "Opening consumer: Redis failed 3 times in a row; doing the test thing for 5 s at a time until it answers");
    }

    @Test
    void itsClosingNamesItsConsumer(CapturedOutput output) {
        RedisCircuitBreaker own = new RedisCircuitBreaker("Closing consumer", "doing the test thing",
                WINDOW, RedisCircuitBreaker.FAILURES_TO_OPEN, now::get);
        for (int i = 0; i < RedisCircuitBreaker.FAILURES_TO_OPEN; i++) {
            own.recordFailure(own.allowCall(), DOWN);
        }
        advance(WINDOW);

        assertThat(own.recordSuccess(own.allowCall())).isTrue();

        assertThat(output).contains("Closing consumer: Redis answered again; breaker closed");
    }

    /** Opens it the only way it opens: consecutive failures, the last of which reports the opening. */
    private void open() {
        for (int i = 1; i < RedisCircuitBreaker.FAILURES_TO_OPEN; i++) {
            assertThat(breaker.recordFailure(breaker.allowCall(), DOWN)).isFalse();
        }
        assertThat(breaker.recordFailure(breaker.allowCall(), DOWN)).isTrue();
    }

    private void advance(Duration by) {
        now.addAndGet(by.toNanos());
    }
}
