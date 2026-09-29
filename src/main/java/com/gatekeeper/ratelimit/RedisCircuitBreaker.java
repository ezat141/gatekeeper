package com.gatekeeper.ratelimit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

/**
 * Stops the limiter asking a Redis that is not answering. The M5 design, section 7.
 *
 * <p>After a store failure or timeout the breaker opens: for {@link #OPEN_FOR} no request calls
 * Redis, and each is forwarded unlimited. Then exactly one request probes; its success closes the
 * breaker, its failure opens it for another window. This bounds what the limiter adds to Lettuce's
 * unbounded reconnect buffer to about one command per window, and turns an outage into one
 * warning when the breaker opens and one line when it closes, instead of a stack trace per request.
 *
 * <p><strong>Only the probe closes it.</strong> Each call takes a {@link Permit} before it asks
 * Redis and reports its outcome with that permit. A request already in flight when the breaker
 * opened holds a {@link Permit#CLOSED} permit; its late success says nothing about Redis now, so
 * it does not close the breaker. Otherwise a Redis answering around the timeout would open and
 * close it hundreds of times a second.
 *
 * <p>The cost: after any Redis failure, limiting stays suspended for up to one window even if Redis
 * recovers sooner.
 */
public class RedisCircuitBreaker {

    static final Duration OPEN_FOR = Duration.ofSeconds(5);

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

    private final Duration openFor;
    private final long openForNanos;
    private final LongSupplier nanoTime;
    private final AtomicBoolean open = new AtomicBoolean();
    private final AtomicLong openUntil = new AtomicLong();

    public RedisCircuitBreaker(Duration openFor, LongSupplier nanoTime) {
        this.openFor = openFor;
        this.openForNanos = openFor.toNanos();
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

    /** Closes the breaker, but only for the probe's success. True only when this call closed it. */
    public boolean recordSuccess(Permit permit) {
        if (permit == Permit.PROBE && open.compareAndSet(true, false)) {
            log.info("Rate limiter's Redis answered again; limiting resumed");
            return true;
        }
        return false;
    }

    /**
     * Opens the breaker for a window from now, or, if it is already open — a failed probe, or a
     * late failure from before the opening — extends it. Warns, with the cause, only on the
     * opening. True only when this call opened it.
     */
    public boolean recordFailure(Permit permit, Throwable error) {
        openUntil.set(nanoTime.getAsLong() + openForNanos);
        if (open.compareAndSet(false, true)) {
            log.warn("Rate limiter's Redis failed; forwarding requests unlimited for {} s at a time until it answers",
                    openFor.toSeconds(), error);
            return true;
        }
        log.debug("Rate limiter's Redis still failing ({} call): {}", permit, error.toString());
        return false;
    }
}
