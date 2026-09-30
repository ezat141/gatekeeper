package com.gatekeeper.redis;

import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Duration;
import java.util.function.Supplier;

/**
 * Connects to Redis once, by one attempt no caller can cancel. The M5 design, section 7; shared by
 * the rate limiter and the revocation check since M6 (its section 7).
 *
 * <p>Lettuce opens its shared connection with a blocking wait inside {@code subscribe()}, before any
 * timeout downstream has started. So every consumer connects through this single cached step: a
 * ping, subscribed on a worker thread so the wait never holds an event loop, whose success is kept
 * for good and whose failure is not kept at all, so the next caller tries again. A caller waits on
 * the step within its own timeout, and timing out stops the caller waiting, never the attempt. That
 * matters: cancelling the worker interrupts it, and Lettuce then abandons its connection attempt
 * rather than cancelling it — each timed-out request against a silent Redis used to leave one
 * connection behind, all of them going live when Redis answered again.
 *
 * <p>Once connected, a consumer makes no thread hop: Lettuce's commands are non-blocking on an
 * established connection, and it reconnects in the background.
 */
public class RedisConnectionStep {

    /** Keep a successful connection for good: exactly the value Reactor treats as "never expire". */
    private static final Duration FOREVER = Duration.ofMillis(Long.MAX_VALUE);

    private final Mono<Boolean> connected;

    public RedisConnectionStep(ReactiveStringRedisTemplate redis) {
        this(() -> redis.execute(connection -> connection.ping()).next());
    }

    /** For tests: any ping, to stand in for a Redis that answers, fails or never answers. */
    public RedisConnectionStep(Supplier<Mono<?>> ping) {
        // cache(value, error, empty): a success is kept forever, an error or an empty answer not at
        // all; and unlike cacheInvalidateIf, subscribers cancelling never cancel the attempt.
        //
        // "Forever" is the factory's lifetime. That holds because LettuceConnectionFactory drops its
        // shared connection only in resetConnection() — called by stop() and initConnection(), or by
        // validateConnection() when setValidateConnection(true), which Spring Boot does not set —
        // and normal operation calls none of them; Lettuce itself reconnects in the background.
        // After a lifecycle stop and restart, the first check would connect on the calling thread.
        //
        // .single() turns an empty ping into an error too, so it is not cached as success either —
        // cache's own "empty" branch only covers a Mono that completes with no error and no value
        // reaching thenReturn, which never happens once thenReturn always supplies one.
        this.connected = Mono.defer(ping)
                .subscribeOn(Schedulers.boundedElastic())
                .single()
                .thenReturn(Boolean.TRUE)
                .cache(ok -> FOREVER, error -> Duration.ZERO, () -> Duration.ZERO);
    }

    /** Completes once Redis has answered a ping; fails, uncached, if this attempt did not. */
    public Mono<Void> ready() {
        return connected.then();
    }
}
