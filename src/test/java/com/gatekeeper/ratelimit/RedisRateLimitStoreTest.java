package com.gatekeeper.ratelimit;

import com.gatekeeper.ratelimit.RateLimitIdentity.Kind;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The script against the real Redis, with a fixed {@code now}, so that refill, Retry-After and
 * the midnight rollover are exact assertions rather than sleeps. The M5 design, section 6.
 *
 * <p><strong>{@code now} is always in the future.</strong> The quota key expires with
 * {@code EXPIREAT} at the next UTC midnight plus an hour, computed from {@code now}; a {@code now}
 * in the past would make Redis delete the key the moment it was written.
 *
 * <p>Every test uses a fresh tenant and deletes its keys afterwards: this Redis is shared with
 * AuthCore and with every other test.
 */
@SpringBootTest
class RedisRateLimitStoreTest {

    static final double DAY = 86_400;

    /** Noon, UTC, two days from now. */
    static final double NOON = (Math.floor(System.currentTimeMillis() / 1000.0 / DAY) + 2) * DAY + DAY / 2;

    @Autowired
    ReactiveStringRedisTemplate redis;

    private final List<RateLimitIdentity> used = new ArrayList<>();

    @AfterEach
    void deleteKeys() {
        for (RateLimitIdentity identity : used) {
            redis.delete(RedisRateLimitStore.bucketKey(identity), RedisRateLimitStore.quotaKey(identity)).block();
        }
    }

    @Test
    void allowsTheBurstAndRefusesTheNextRequest() {
        RateLimitIdentity caller = fresh();
        Plan plan = new Plan("t", 1, 3, 100);

        for (long remaining = 2; remaining >= 0; remaining--) {
            Decision allowed = check(caller, plan, NOON);
            assertThat(allowed.allowed()).isTrue();
            assertThat(allowed.tokensRemaining()).isEqualTo(remaining);
        }
        Decision refused = check(caller, plan, NOON);

        assertThat(refused.allowed()).isFalse();
        assertThat(refused.reason()).isEqualTo(RateLimitReason.RATE_LIMITED);
        assertThat(refused.tokensRemaining()).isZero();
        assertThat(refused.retryAfterSeconds()).isEqualTo(1);
    }

    @Test
    void refillsAtThePlansRate() {
        RateLimitIdentity caller = fresh();
        Plan plan = new Plan("t", 2, 4, 100);
        for (int i = 0; i < 4; i++) {
            check(caller, plan, NOON);
        }

        // 1.5 s at 2 tokens/s refills 3; the request takes one.
        Decision decision = check(caller, plan, NOON + 1.5);

        assertThat(decision.allowed()).isTrue();
        assertThat(decision.tokensRemaining()).isEqualTo(2);
    }

    @Test
    void neverRefillsBeyondTheBurst() {
        RateLimitIdentity caller = fresh();
        Plan plan = new Plan("t", 10, 3, 100);
        check(caller, plan, NOON);

        Decision decision = check(caller, plan, NOON + 3600);

        assertThat(decision.tokensRemaining()).isEqualTo(2);
    }

    @Test
    void refusesOnceTheDailyQuotaIsUsedUpUntilUtcMidnight() {
        RateLimitIdentity caller = fresh();
        Plan plan = new Plan("t", 1000, 1000, 2);
        assertThat(check(caller, plan, NOON).quotaRemaining()).isEqualTo(1);
        assertThat(check(caller, plan, NOON).quotaRemaining()).isZero();

        Decision refused = check(caller, plan, NOON);

        assertThat(refused.allowed()).isFalse();
        assertThat(refused.reason()).isEqualTo(RateLimitReason.QUOTA_EXCEEDED);
        assertThat(refused.retryAfterSeconds()).isEqualTo(43_200);
        assertThat(refused.quotaResetSeconds()).isEqualTo(43_200);
    }

    /** The bucket is checked first, so a request refused for speed spends none of the day. */
    @Test
    void aRateRefusalSpendsNoQuota() {
        RateLimitIdentity caller = fresh();
        Plan plan = new Plan("t", 1, 1, 5);
        check(caller, plan, NOON);
        assertThat(check(caller, plan, NOON).reason()).isEqualTo(RateLimitReason.RATE_LIMITED);

        Decision next = check(caller, plan, NOON + 1);

        assertThat(next.allowed()).isTrue();
        assertThat(next.quotaRemaining()).isEqualTo(3);
    }

    /** A request refused for the quota takes no token. */
    @Test
    void aQuotaRefusalTakesNoToken() {
        RateLimitIdentity caller = fresh();
        Plan plan = new Plan("t", 1, 5, 1);
        check(caller, plan, NOON);

        Decision refused = check(caller, plan, NOON);

        assertThat(refused.reason()).isEqualTo(RateLimitReason.QUOTA_EXCEEDED);
        assertThat(refused.tokensRemaining()).isEqualTo(4);
        assertThat(redis.opsForHash().get(RedisRateLimitStore.bucketKey(caller), "tokens").block())
                .asString().startsWith("4");
    }

    @Test
    void resetsTheQuotaAtUtcMidnight() {
        RateLimitIdentity caller = fresh();
        Plan plan = new Plan("t", 1000, 1000, 1);
        double midnight = NOON + DAY / 2;

        assertThat(check(caller, plan, midnight - 0.5).allowed()).isTrue();
        Decision refused = check(caller, plan, midnight - 0.4);
        assertThat(refused.reason()).isEqualTo(RateLimitReason.QUOTA_EXCEEDED);
        assertThat(refused.retryAfterSeconds()).isEqualTo(1);

        assertThat(check(caller, plan, midnight + 0.1).allowed()).isTrue();
    }

    @Test
    void namesAndExpiresItsKeysAsSpecified() {
        RateLimitIdentity caller = fresh();
        check(caller, new Plan("t", 5, 10, 100), NOON);

        assertThat(RedisRateLimitStore.bucketKey(caller)).isEqualTo("gatekeeper:rl:{" + caller.key() + "}");
        assertThat(RedisRateLimitStore.quotaKey(caller)).isEqualTo("gatekeeper:quota:{" + caller.key() + "}");

        // ceil(burst / rate * 2) = ceil(10 / 5 * 2) = 4 s.
        Duration bucketTtl = redis.getExpire(RedisRateLimitStore.bucketKey(caller)).block();
        assertThat(bucketTtl).isBetween(Duration.ofSeconds(1), Duration.ofSeconds(4));

        // Next UTC midnight after NOON, plus an hour, measured from the real clock.
        double expireAt = NOON + DAY / 2 + 3600;
        double expected = expireAt - System.currentTimeMillis() / 1000.0;
        Duration quotaTtl = redis.getExpire(RedisRateLimitStore.quotaKey(caller)).block();
        assertThat((double) quotaTtl.toSeconds()).isBetween(expected - 5, expected + 5);
    }

    /** Production passes no time: Redis's own clock is used, so the call works end to end. */
    @Test
    void usesRedisTimeWhenNoTimeIsGiven() {
        RateLimitIdentity caller = fresh();

        Decision decision = new RedisRateLimitStore(redis).check(caller, new Plan("t", 5, 10, 100)).block();

        assertThat(decision.allowed()).isTrue();
        assertThat(decision.tokensRemaining()).isEqualTo(9);
        assertThat(decision.quotaResetSeconds()).isBetween(1L, 86_400L);
    }

    private Decision check(RateLimitIdentity caller, Plan plan, double now) {
        return new RedisRateLimitStore(redis).check(caller, plan, now).block();
    }

    private RateLimitIdentity fresh() {
        RateLimitIdentity identity = new RateLimitIdentity(Kind.TENANT, "t-" + UUID.randomUUID());
        used.add(identity);
        return identity;
    }
}
