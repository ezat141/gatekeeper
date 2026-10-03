package com.gatekeeper.redis;

import io.lettuce.core.resource.Delay;
import org.springframework.boot.data.redis.autoconfigure.ClientResourcesBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

@Configuration
public class RedisConfig {

    /**
     * How long Lettuce waits between reconnect attempts: exponential from 100 ms, capped at 2 s, with
     * jitter. The M7 design, section 3.
     *
     * <p>Lettuce's default is exponential up to 30 s. In M6's live run the gateway reconnected 17 s
     * after Redis was back, and the revocation check refused every bearer token until then. With a
     * 2 s cap it reconnects within about 2 s, and the revocation breaker's next probe — at most one
     * 5 s window later — closes it. Client-wide: the rate limiter and the API-key cache recover faster
     * too. Jitter keeps several instances from reconnecting in the same instant. A Redis that accepts
     * and never answers is unchanged: each attempt is still bounded by Lettuce's handshake timeout.
     *
     * <p>{@code fullJitter} is stateless, so one instance serves every connection.
     */
    static final Delay RECONNECT_DELAY =
            Delay.fullJitter(Duration.ofMillis(100), Duration.ofSeconds(2), 100, TimeUnit.MILLISECONDS);

    /** One step for every consumer, so one Redis costs one connection attempt at a time. */
    @Bean
    public RedisConnectionStep redisConnectionStep(ReactiveStringRedisTemplate redis) {
        return new RedisConnectionStep(redis);
    }

    @Bean
    public ClientResourcesBuilderCustomizer reconnectQuickly() {
        return builder -> builder.reconnectDelay(RECONNECT_DELAY);
    }
}
