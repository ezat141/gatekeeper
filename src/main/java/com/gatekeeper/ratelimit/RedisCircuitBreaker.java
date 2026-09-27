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
 * <p>The cost: after any Redis failure, limiting stays suspended for up to one window even if Redis
 * recovers sooner.
 */
public class RedisCircuitBreaker {

    static final Duration OPEN_FOR = Duration.ofSeconds(5);

    private static final Logger log = LoggerFactory.getLogger(RedisCircuitBreaker.class);

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
     * True while closed. While open, false until the window has passed; then true for exactly one
     * caller — the probe, which claims the next window — and false for the rest.
     */
    public boolean allowCall() {
        if (!open.get()) {
            return true;
        }
        long until = openUntil.get();
        long now = nanoTime.getAsLong();
        if (now - until < 0) {
            return false;
        }
        return openUntil.compareAndSet(until, now + openForNanos);
    }

    /** Closes the breaker. True only when this call closed an open breaker. */
    public boolean recordSuccess() {
        if (open.compareAndSet(true, false)) {
            log.info("Rate limiter's Redis answered again; limiting resumed");
            return true;
        }
        return false;
    }

    /** Opens the breaker for a window from now. Warns, with the cause, only when it was closed. */
    public void recordFailure(Throwable error) {
        openUntil.set(nanoTime.getAsLong() + openForNanos);
        if (open.compareAndSet(false, true)) {
            log.warn("Rate limiter's Redis failed; forwarding requests unlimited for {} s at a time until it answers",
                    openFor.toSeconds(), error);
        } else {
            log.debug("Rate limiter's Redis still failing: {}", error.toString());
        }
    }
}
