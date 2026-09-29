package com.gatekeeper.ratelimit;

import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.List;
import java.util.function.Supplier;

/**
 * One atomic script per request against two hashes per identity: the bucket and the daily
 * quota. The M5 design, section 6.
 *
 * <p>Both keys carry the identity as a {@code {…}} hash tag, so they share a Redis Cluster slot,
 * which a multi-key script requires. The day is a field of the quota hash, not part of its name:
 * a script must declare its keys before it runs, and the day is known only from Redis's clock,
 * read inside the script.
 *
 * <p><strong>Connected once, by one attempt no caller can cancel.</strong> The M5 design, section 7.
 * Lettuce opens its shared connection with a blocking wait inside {@code subscribe()}, before any
 * timeout downstream has started. So the store connects through a single cached step: a ping,
 * subscribed on a worker thread so the wait never holds an event loop, whose success is kept for
 * good and whose failure is not kept at all, so the next caller tries again. A caller waits on the
 * step within its own timeout, and timing out stops the caller waiting, never the attempt. That
 * matters: cancelling the worker interrupts it, and Lettuce then abandons its connection attempt
 * rather than cancelling it — each timed-out request against a silent Redis used to leave one
 * connection behind, all of them going live when Redis answered again.
 *
 * <p>Once connected, a check makes no thread hop: Lettuce's commands are non-blocking on an
 * established connection, and it reconnects in the background.
 */
public class RedisRateLimitStore implements RateLimitStore {

    @SuppressWarnings("rawtypes")
    private static final RedisScript<List> SCRIPT = RedisScript.of(loadScript(), List.class);

    /**
     * The text, loaded once. A script built from a {@code Resource} re-checks the resource's
     * modification time on every execution — blocking I/O on the event loop, under a lock
     * shared by every request.
     */
    private static String loadScript() {
        try {
            return new ClassPathResource("ratelimit/check.lua").getContentAsString(StandardCharsets.UTF_8);
        } catch (IOException ex) {
            throw new UncheckedIOException("the rate-limit script is missing from the classpath", ex);
        }
    }

    /** Keep a successful connection for good: exactly the value Reactor treats as "never expire". */
    private static final Duration FOREVER = Duration.ofMillis(Long.MAX_VALUE);

    private final ReactiveStringRedisTemplate redis;
    private final Mono<Boolean> connected;

    public RedisRateLimitStore(ReactiveStringRedisTemplate redis) {
        this(redis, () -> redis.execute(connection -> connection.ping()).next());
    }

    /** For tests: any ping, to stand in for a Redis that answers, fails or never answers. */
    RedisRateLimitStore(ReactiveStringRedisTemplate redis, Supplier<Mono<?>> ping) {
        this.redis = redis;
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

    /** Completes once Redis has answered a ping; the startup warm-up waits on it. */
    public Mono<Void> connect() {
        return connected.then();
    }

    static String bucketKey(RateLimitIdentity identity) {
        return "gatekeeper:rl:{" + identity.key() + "}";
    }

    static String quotaKey(RateLimitIdentity identity) {
        return "gatekeeper:quota:{" + identity.key() + "}";
    }

    @Override
    public Mono<Decision> check(RateLimitIdentity identity, Plan plan) {
        return run(identity, plan, "");
    }

    /** For tests only: a fixed {@code now}, so time-dependent behaviour is exact. */
    Mono<Decision> check(RateLimitIdentity identity, Plan plan, double now) {
        return run(identity, plan, Double.toString(now));
    }

    private Mono<Decision> run(RateLimitIdentity identity, Plan plan, String now) {
        return connected
                .then(Mono.defer(() -> redis.execute(SCRIPT,
                                List.of(bucketKey(identity), quotaKey(identity)),
                                List.of(Integer.toString(plan.requestsPerSecond()),
                                        Long.toString(plan.burst()),
                                        Long.toString(plan.dailyQuota()),
                                        now))
                        .next()))
                .map(RedisRateLimitStore::toDecision);
    }

    private static Decision toDecision(List<?> result) {
        long reason = number(result, 1);
        return new Decision(
                number(result, 0) == 1,
                reason == 1 ? RateLimitReason.RATE_LIMITED : reason == 2 ? RateLimitReason.QUOTA_EXCEEDED : null,
                number(result, 2),
                number(result, 3),
                number(result, 4),
                number(result, 5));
    }

    private static long number(List<?> result, int index) {
        return ((Number) result.get(index)).longValue();
    }
}
