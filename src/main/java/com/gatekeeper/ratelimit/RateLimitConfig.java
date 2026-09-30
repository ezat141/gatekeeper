package com.gatekeeper.ratelimit;

import com.gatekeeper.redis.RedisCircuitBreaker;
import com.gatekeeper.redis.RedisConnectionStep;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;

@Configuration
public class RateLimitConfig {

    @Bean
    public PlanResolver planResolver(RateLimitProperties properties) {
        return new ConfiguredPlanResolver(properties);
    }

    @Bean
    public RedisRateLimitStore rateLimitStore(ReactiveStringRedisTemplate redis, RedisConnectionStep connection) {
        return new RedisRateLimitStore(redis, connection);
    }

    /** The limiter's own breaker; the revocation check has another. Injected by this name. */
    @Bean
    public RedisCircuitBreaker rateLimitBreaker() {
        return new RedisCircuitBreaker("Rate limiter", "forwarding requests unlimited",
                RedisCircuitBreaker.OPEN_FOR, RedisCircuitBreaker.FAILURES_TO_OPEN, System::nanoTime);
    }
}
