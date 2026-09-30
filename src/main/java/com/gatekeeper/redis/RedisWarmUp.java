package com.gatekeeper.redis;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Duration;

/**
 * Connects to Redis once at startup, before the web server accepts traffic. The M5 design,
 * section 7.
 *
 * <p>Lettuce opens its shared connection on first use. Without this, the first request after boot
 * would pay for opening that connection and exceed its consumer's timeout. This only opens the
 * connection, not the rate limiter's script: the first request still pays one extra round trip,
 * {@code EVALSHA} answered {@code NOSCRIPT} then {@code EVAL}, which is small.
 * {@code afterSingletonsInstantiated} runs while the context refreshes, before the web server binds
 * its port.
 *
 * <p><strong>Bounded, and never fails the boot.</strong> It waits on the shared connection step —
 * which already runs on a worker thread — for at most {@link #WARM_UP_TIMEOUT}. Giving up stops the
 * waiting, not the attempt, which the first requests then share. A Redis that is down or silent
 * only logs a warning.
 */
@Component
public class RedisWarmUp implements SmartInitializingSingleton {

    static final Duration WARM_UP_TIMEOUT = Duration.ofSeconds(2);

    private static final Logger log = LoggerFactory.getLogger(RedisWarmUp.class);

    private final RedisConnectionStep connection;

    public RedisWarmUp(RedisConnectionStep connection) {
        this.connection = connection;
    }

    @Override
    public void afterSingletonsInstantiated() {
        connection.ready()
                .timeout(WARM_UP_TIMEOUT)
                .onErrorResume(error -> {
                    log.warn("Redis did not answer the startup warm-up; the rate limiter will fail open until it does",
                            error);
                    return Mono.empty();
                })
                .block();
    }
}
