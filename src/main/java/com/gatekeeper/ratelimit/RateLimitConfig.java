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

    @Bean
    public RateLimitStore rateLimitStore(ReactiveStringRedisTemplate redis) {
        return new RedisRateLimitStore(redis);
    }
}
