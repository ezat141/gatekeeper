package com.gatekeeper.ratelimit;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Duration;
import java.util.function.Supplier;

/**
 * Connects to Redis once at startup, before the web server accepts traffic. The M5 design,
 * section 7.
 *
 * <p>Lettuce opens its shared connection on first use. Without this, the first rate-limited
 * request after boot would pay for the connection and the script load, exceed the limiter's
 * timeout, and go through unlimited. {@code afterSingletonsInstantiated} runs while the context
 * refreshes, before the web server binds its port.
 *
 * <p><strong>Bounded, and never fails the boot.</strong> It waits at most {@link #WARM_UP_TIMEOUT},
 * off the calling thread — Lettuce's connect blocks inside {@code subscribe()} — and a Redis that
 * is down or silent only logs a warning: the limiter fails open until Redis answers, as it would
 * for any Redis outage.
 */
@Component
public class RedisWarmUp implements SmartInitializingSingleton {

    static final Duration WARM_UP_TIMEOUT = Duration.ofSeconds(2);

    private static final Logger log = LoggerFactory.getLogger(RedisWarmUp.class);

    private final Supplier<Mono<?>> ping;

    @Autowired
    public RedisWarmUp(ReactiveStringRedisTemplate redis) {
        this(() -> redis.execute(connection -> connection.ping()).next());
    }

    /** For tests: any ping, to stand in for a Redis that answers, fails or never answers. */
    RedisWarmUp(Supplier<Mono<?>> ping) {
        this.ping = ping;
    }

    @Override
    public void afterSingletonsInstantiated() {
        Mono.defer(ping)
                .subscribeOn(Schedulers.boundedElastic())
                .timeout(WARM_UP_TIMEOUT)
                .onErrorResume(error -> {
                    log.warn("Redis did not answer the startup warm-up; the rate limiter will fail open until it does",
                            error);
                    return Mono.empty();
                })
                .block();
    }
}
