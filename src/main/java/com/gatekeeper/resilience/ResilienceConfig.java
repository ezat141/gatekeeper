package com.gatekeeper.resilience;

import io.github.resilience4j.bulkhead.BulkheadFullException;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.event.CircuitBreakerOnStateTransitionEvent;
import io.github.resilience4j.timelimiter.TimeLimiterConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.circuitbreaker.resilience4j.ReactiveResilience4JCircuitBreakerFactory;
import org.springframework.cloud.client.circuitbreaker.Customizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * The downstreams' breakers, from {@link ResilienceProperties}. The M7 design, sections 6, 7 and 14.
 *
 * <p>One per downstream service — {@link #AUTHCORE}, shared by both AuthCore routes, and {@link #LEDGER}
 * — named by each route's {@code CircuitBreaker} filter in {@code application.yml}. What counts as a
 * failure is decided there ({@code statusCodes}: 502, 503, 504) and by the errors that reach the breaker
 * (connect errors, timeouts); a downstream 500 is neither, so it never counts. A full bulkhead's
 * refusal is ignored: the downstream did not fail, the gateway chose not to call it.
 *
 * <p>The TimeLimiter is disabled by {@code spring.cloud.circuitbreaker.resilience4j.disable-time-limiter};
 * the {@code timeLimiterConfig} given here is required by the builder and never applied.
 */
@Configuration
public class ResilienceConfig {

    public static final String AUTHCORE = "authcore";
    public static final String LEDGER = "ledger";

    private static final Logger log = LoggerFactory.getLogger(ResilienceConfig.class);

    @Bean
    public Customizer<ReactiveResilience4JCircuitBreakerFactory> downstreamBreakers(ResilienceProperties properties) {
        ResilienceProperties.Breaker breaker = properties.breaker();
        CircuitBreakerConfig config = CircuitBreakerConfig.custom()
                .slidingWindowType(CircuitBreakerConfig.SlidingWindowType.COUNT_BASED)
                .slidingWindowSize(breaker.slidingWindowSize())
                .minimumNumberOfCalls(breaker.minimumCalls())
                .failureRateThreshold(breaker.failureRateThreshold())
                .waitDurationInOpenState(breaker.openFor())
                .permittedNumberOfCallsInHalfOpenState(breaker.trialCalls())
                .ignoreExceptions(BulkheadFullException.class)
                .build();
        return factory -> {
            factory.configure(builder -> builder
                    .circuitBreakerConfig(config)
                    .timeLimiterConfig(TimeLimiterConfig.ofDefaults()), AUTHCORE, LEDGER);
            // Once per breaker: the factory runs its customizers on every call (verified in 5.0.2), so
            // without once(...) each request would add another listener.
            factory.addCircuitBreakerCustomizer(Customizer.once(
                    circuitBreaker -> circuitBreaker.getEventPublisher()
                            .onStateTransition(event -> logTransition(event, circuitBreaker)),
                    CircuitBreaker::getName), AUTHCORE, LEDGER);
        };
    }

    /** WARN when one opens, INFO otherwise; never per request. The M7 design, section 14. */
    private static void logTransition(CircuitBreakerOnStateTransitionEvent event, CircuitBreaker circuitBreaker) {
        CircuitBreaker.StateTransition transition = event.getStateTransition();
        if (transition.getToState() == CircuitBreaker.State.OPEN) {
            log.warn("Downstream {}: circuit breaker opened ({} -> OPEN) at a {}% failure rate; its requests are"
                            + " refused 503 until a trial call succeeds",
                    event.getCircuitBreakerName(), transition.getFromState(),
                    circuitBreaker.getMetrics().getFailureRate());
        } else {
            log.info("Downstream {}: circuit breaker {} -> {}",
                    event.getCircuitBreakerName(), transition.getFromState(), transition.getToState());
        }
    }
}
