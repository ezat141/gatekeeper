package com.gatekeeper.redis;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

/**
 * Stops one consumer asking a Redis that is not answering. The M5 design, section 7; used by the
 * rate limiter and, since M6, by the revocation check (the M6 design, section 7), one instance each.
 *
 * <p>After {@link #FAILURES_TO_OPEN} consecutive failures or timeouts the breaker opens: for
 * {@link #OPEN_FOR} its consumer does not call Redis at all. What the consumer does instead is its
 * own decision — the rate limiter forwards unlimited, the revocation check refuses — and the breaker
 * only reports it, in its log lines. Then exactly one call probes; its success closes the breaker,
 * its failure opens it for another window at once. This bounds what the consumer adds to Lettuce's
 * unbounded reconnect buffer to about one command per window, and turns an outage into one warning
 * when the breaker opens and one line when it closes, instead of a stack trace per request.
 *
 * <p><strong>Why three, not one.</strong> The timeout is measured in the gateway, so a single one may
 * be the gateway's own slowness — a GC pause, or CPU starved by a flood — rather than Redis's.
 * Opening on one would switch the consumer's Redis off for everyone under overload. So an isolated
 * failure affects only its own request, any success while closed resets the count, and it takes
 * three in a row to open. A hard outage still reaches three within the first few requests; a failed
 * probe needs no such count, because the evidence is already in.
 *
 * <p><strong>Only the probe closes it.</strong> Each call takes a {@link Permit} before it asks
 * Redis and reports its outcome with that permit. A request already in flight when the breaker
 * opened holds a {@link Permit#CLOSED} permit; its late success says nothing about Redis now, so
 * it does not close the breaker. Otherwise a Redis answering around the timeout would open and
 * close it hundreds of times a second.
 *
 * <p>The cost: once the breaker opens, its consumer stays without Redis for up to one window even if
 * Redis recovers sooner.
 */
public class RedisCircuitBreaker {

    public static final Duration OPEN_FOR = Duration.ofSeconds(5);
    /** Consecutive failures, while closed, that open the breaker. */
    public static final int FAILURES_TO_OPEN = 3;

    private static final Logger log = LoggerFactory.getLogger(RedisCircuitBreaker.class);

    /** What a caller may do, decided once per call, and reported back with its outcome. */
    public enum Permit {
        /** The breaker was closed: call Redis. */
        CLOSED,
        /** The breaker was open and its window had passed: call Redis as the one probe. */
        PROBE,
        /** The breaker is open: do not call Redis. */
        DENIED
    }

    private final String name;
    private final String whileOpen;
    private final Duration openFor;
    private final long openForNanos;
    private final int failuresToOpen;
    private final LongSupplier nanoTime;
    private final AtomicBoolean open = new AtomicBoolean();
    private final AtomicLong openUntil = new AtomicLong();
    private final AtomicInteger consecutiveFailures = new AtomicInteger();

    /**
     * @param name      the consumer, as its log lines name it: "Rate limiter", "Revocation check"
     * @param whileOpen what the consumer does while the breaker is open, as the opening warning says
     *                  it: "forwarding requests unlimited", "refusing bearer-token requests with 503"
     */
    public RedisCircuitBreaker(String name, String whileOpen, Duration openFor, int failuresToOpen,
                               LongSupplier nanoTime) {
        this.name = name;
        this.whileOpen = whileOpen;
        this.openFor = openFor;
        this.openForNanos = openFor.toNanos();
        this.failuresToOpen = failuresToOpen;
        this.nanoTime = nanoTime;
    }

    /**
     * {@link Permit#CLOSED} while closed. While open, {@link Permit#DENIED} until the window has
     * passed; then {@link Permit#PROBE} for exactly one caller — the one that claims the next window
     * — and {@link Permit#DENIED} for the rest.
     */
    public Permit allowCall() {
        if (!open.get()) {
            return Permit.CLOSED;
        }
        long until = openUntil.get();
        long now = nanoTime.getAsLong();
        if (now - until < 0) {
            return Permit.DENIED;
        }
        return openUntil.compareAndSet(until, now + openForNanos) ? Permit.PROBE : Permit.DENIED;
    }

    /**
     * While closed, resets the count of consecutive failures. While open, closes the breaker, but
     * only for the probe's success; a late success from before the opening does nothing. True only
     * when this call closed it.
     */
    public boolean recordSuccess(Permit permit) {
        if (permit == Permit.PROBE) {
            // Reset again before closing, in case a failure was counted just as the breaker opened:
            // the first failure after the closing counts from zero, and none after it is lost.
            consecutiveFailures.set(0);
            if (open.compareAndSet(true, false)) {
                log.info("{}: Redis answered again; breaker closed", name);
                return true;
            }
        } else if (permit == Permit.CLOSED && !open.get()) {
            consecutiveFailures.set(0);
        }
        return false;
    }

    /**
     * While closed, counts the failure, and opens the breaker for a window from now when it is the
     * {@link #FAILURES_TO_OPEN}th in a row, warning with the cause. While open — a failed probe, or
     * a late failure from before the opening — re-opens it for a window from now, at once. True only
     * when this call opened it.
     */
    public boolean recordFailure(Permit permit, Throwable error) {
        if (permit == Permit.CLOSED && !open.get()) {
            int failures = consecutiveFailures.incrementAndGet();
            if (failures < failuresToOpen) {
                log.debug("{}: Redis failed, {} of {} consecutive failures: {}",
                        name, failures, failuresToOpen, error.toString());
                return false;
            }
        }
        openUntil.set(nanoTime.getAsLong() + openForNanos);
        if (open.compareAndSet(false, true)) {
            // The count describes only the stretch while closed.
            consecutiveFailures.set(0);
            log.warn("{}: Redis failed {} times in a row; {} for {} s at a time until it answers",
                    name, failuresToOpen, whileOpen, openFor.toSeconds(), error);
            return true;
        }
        log.debug("{}: Redis still failing ({} call): {}", name, permit, error.toString());
        return false;
    }
}
