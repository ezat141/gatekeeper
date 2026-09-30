package com.gatekeeper.revocation;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * {@code gatekeeper.revocation}. The M6 design, section 10.
 *
 * <p>Strictly bound: an unknown key under the prefix fails the boot rather than silently leaving the
 * real one unset. There is no default in code, as for the rate limiter: {@code application.yml}
 * supplies it, and a missing value fails the boot.
 *
 * @param redisTimeout how long the revocation check waits for Redis before refusing with 503
 */
@ConfigurationProperties(prefix = "gatekeeper.revocation", ignoreUnknownFields = false)
public record RevocationProperties(Duration redisTimeout) {

    public RevocationProperties {
        if (redisTimeout == null || redisTimeout.isZero() || redisTimeout.isNegative()) {
            throw new IllegalArgumentException("gatekeeper.revocation.redis-timeout must be a positive duration");
        }
    }
}
