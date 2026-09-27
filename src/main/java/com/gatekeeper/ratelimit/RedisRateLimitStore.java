package com.gatekeeper.ratelimit;

import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.util.List;

/**
 * One atomic script per request against two hashes per identity: the bucket and the daily
 * quota. The M5 design, section 6.
 *
 * <p>Both keys carry the identity as a {@code {…}} hash tag, so they share a Redis Cluster slot,
 * which a multi-key script requires. The day is a field of the quota hash, not part of its name:
 * a script must declare its keys before it runs, and the day is known only from Redis's clock,
 * read inside the script.
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

    private final ReactiveStringRedisTemplate redis;

    public RedisRateLimitStore(ReactiveStringRedisTemplate redis) {
        this.redis = redis;
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

    /**
     * Subscribes on a worker thread. Lettuce opens its shared connection with a blocking wait
     * inside {@code subscribe()}, before any timeout downstream has started — up to its 60-second
     * handshake timeout on a Redis that accepts and never answers. On a worker, that wait holds a
     * worker, never the event loop, and the filter's timeout always applies. {@code defer} makes
     * the {@code execute} call itself, and so the subscribe where Lettuce blocks, happen on the
     * worker. The M5 design, section 7.
     */
    private Mono<Decision> run(RateLimitIdentity identity, Plan plan, String now) {
        return Mono.defer(() -> redis.execute(SCRIPT,
                                List.of(bucketKey(identity), quotaKey(identity)),
                                List.of(Integer.toString(plan.requestsPerSecond()),
                                        Long.toString(plan.burst()),
                                        Long.toString(plan.dailyQuota()),
                                        now))
                        .next())
                .subscribeOn(Schedulers.boundedElastic())
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
