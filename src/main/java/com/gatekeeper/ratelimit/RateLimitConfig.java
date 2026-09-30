package com.gatekeeper.ratelimit;

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

    @Bean
    public RedisCircuitBreaker redisCircuitBreaker() {
        return new RedisCircuitBreaker(RedisCircuitBreaker.OPEN_FOR, RedisCircuitBreaker.FAILURES_TO_OPEN,
                System::nanoTime);
    }
}
