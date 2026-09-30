package com.gatekeeper.redis;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;

@Configuration
public class RedisConfig {

    /** One step for every consumer, so one Redis costs one connection attempt at a time. */
    @Bean
    public RedisConnectionStep redisConnectionStep(ReactiveStringRedisTemplate redis) {
        return new RedisConnectionStep(redis);
    }
}
