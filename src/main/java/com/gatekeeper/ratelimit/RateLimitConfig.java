package com.gatekeeper.ratelimit;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;

@Configuration
public class RateLimitConfig {

    @Bean
    public PlanResolver planResolver(RateLimitProperties properties) {
        return new ConfiguredPlanResolver(properties);
    }

    /** Declared as the concrete type so {@link RedisWarmUp} can use its connection step. */
    @Bean
    public RedisRateLimitStore rateLimitStore(ReactiveStringRedisTemplate redis) {
        return new RedisRateLimitStore(redis);
    }

    @Bean
    public RedisCircuitBreaker redisCircuitBreaker() {
        return new RedisCircuitBreaker(RedisCircuitBreaker.OPEN_FOR, RedisCircuitBreaker.FAILURES_TO_OPEN,
                System::nanoTime);
    }
}
