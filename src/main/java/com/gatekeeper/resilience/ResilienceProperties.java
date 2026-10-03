package com.gatekeeper.resilience;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.Map;

/**
 * {@code gatekeeper.resilience}. The M7 design, sections 4 to 12.
 *
 * <p>Strictly bound: an unknown key fails the boot. That is why the breakers and bulkheads are
 * configured from here rather than from Resilience4j's own {@code resilience4j.*} properties, which
 * would also bind but ignore a misspelt key and leave the breaker on its defaults. No defaults in code:
 * {@code application.yml} supplies every value, and a missing one fails the boot.
 *
 * @param jwksTimeout           connect and response timeout for fetching AuthCore's key set (1 ms to 60 s)
 * @param responseTimeoutMillis each route's response timeout, by route id, in milliseconds. Plain
 *                              milliseconds because the routes' {@code metadata} refers to these values,
 *                              and Spring Cloud Gateway parses a route's {@code response-timeout} with
 *                              {@code Long.parseLong}, silently ignoring anything else
 * @param breaker               the circuit breaker each downstream gets
 * @param bulkhead              the bulkhead each downstream gets
 */
@ConfigurationProperties(prefix = "gatekeeper.resilience", ignoreUnknownFields = false)
public record ResilienceProperties(
        Duration jwksTimeout,
        Map<String, Long> responseTimeoutMillis,
        Breaker breaker,
        Bulkhead bulkhead) {

    public ResilienceProperties {
        if (jwksTimeout == null || jwksTimeout.isZero() || jwksTimeout.isNegative()) {
            throw new IllegalArgumentException("gatekeeper.resilience.jwks-timeout must be a positive duration");
        }
        // Netty takes whole milliseconds as an int, and treats a connect timeout of 0 as none at all.
        if (jwksTimeout.compareTo(Duration.ofMillis(1)) < 0 || jwksTimeout.compareTo(Duration.ofSeconds(60)) > 0) {
            throw new IllegalArgumentException(
                    "gatekeeper.resilience.jwks-timeout must be between 1ms and 60s, was " + jwksTimeout);
        }
        if (responseTimeoutMillis == null || responseTimeoutMillis.isEmpty()) {
            throw new IllegalArgumentException("gatekeeper.resilience.response-timeout-millis must name every route");
        }
        responseTimeoutMillis.forEach((route, millis) -> {
            if (millis == null || millis <= 0) {
                throw new IllegalArgumentException(
                        "gatekeeper.resilience.response-timeout-millis." + route + " must be positive");
            }
        });
        if (breaker == null) {
            throw new IllegalArgumentException("gatekeeper.resilience.breaker is required");
        }
        if (bulkhead == null) {
            throw new IllegalArgumentException("gatekeeper.resilience.bulkhead is required");
        }
        responseTimeoutMillis = Map.copyOf(responseTimeoutMillis);
    }

    /**
     * @param slidingWindowSize    how many of the latest calls the failure rate is judged over
     * @param minimumCalls         how many calls the window needs before it judges at all
     * @param failureRateThreshold the failure percentage, 1 to 100, at which it opens
     * @param openFor              how long it stays open before letting trial calls through
     * @param trialCalls           how many trial calls decide whether it closes again
     */
    public record Breaker(int slidingWindowSize, int minimumCalls, float failureRateThreshold,
                          Duration openFor, int trialCalls) {

        public Breaker {
            if (slidingWindowSize < 1) {
                throw new IllegalArgumentException("gatekeeper.resilience.breaker.sliding-window-size must be at least 1");
            }
            if (minimumCalls < 1 || minimumCalls > slidingWindowSize) {
                throw new IllegalArgumentException(
                        "gatekeeper.resilience.breaker.minimum-calls must be between 1 and sliding-window-size");
            }
            if (failureRateThreshold < 1 || failureRateThreshold > 100) {
                throw new IllegalArgumentException(
                        "gatekeeper.resilience.breaker.failure-rate-threshold must be between 1 and 100");
            }
            if (openFor == null || openFor.isZero() || openFor.isNegative()) {
                throw new IllegalArgumentException("gatekeeper.resilience.breaker.open-for must be a positive duration");
            }
            if (trialCalls < 1) {
                throw new IllegalArgumentException("gatekeeper.resilience.breaker.trial-calls must be at least 1");
            }
        }
    }

    /** @param maxConcurrentCalls how many requests may be in flight to one downstream at once */
    public record Bulkhead(int maxConcurrentCalls) {

        public Bulkhead {
            if (maxConcurrentCalls < 1) {
                throw new IllegalArgumentException(
                        "gatekeeper.resilience.bulkhead.max-concurrent-calls must be at least 1");
            }
        }
    }
}
