package com.gatekeeper.revocation;

import com.gatekeeper.redis.RedisCircuitBreaker;
import com.gatekeeper.redis.RedisConnectionStep;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;

@Configuration
public class RevocationConfig {

    @Bean
    public RevocationStore revocationStore(ReactiveStringRedisTemplate redis, RedisConnectionStep connection) {
        return new RedisRevocationStore(redis, connection);
    }

    /**
     * The revocation check's own breaker; the limiter has another (the M6 design, section 7). Open,
     * it refuses. Injected by this name.
     */
    @Bean
    public RedisCircuitBreaker revocationBreaker() {
        return new RedisCircuitBreaker("Revocation check", "refusing bearer-token requests with 503",
                RedisCircuitBreaker.OPEN_FOR, RedisCircuitBreaker.FAILURES_TO_OPEN, System::nanoTime);
    }
}
