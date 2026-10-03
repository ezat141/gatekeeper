package com.gatekeeper.resilience;

import io.github.resilience4j.bulkhead.BulkheadConfig;
import io.github.resilience4j.bulkhead.BulkheadFullException;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.event.CircuitBreakerOnStateTransitionEvent;
import io.github.resilience4j.timelimiter.TimeLimiterConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.circuitbreaker.resilience4j.ReactiveResilience4JCircuitBreakerFactory;
import org.springframework.cloud.circuitbreaker.resilience4j.ReactiveResilience4jBulkheadProvider;
import org.springframework.cloud.client.circuitbreaker.Customizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

/**
 * The downstreams' breakers, from {@link ResilienceProperties}. The M7 design, sections 6, 7 and 14.
 *
 * <p>One per downstream service — {@link #AUTHCORE}, shared by both AuthCore routes, and {@link #LEDGER}
 * — named by each route's {@code CircuitBreaker} filter in {@code application.yml}.
 *
 * <p>The breaker records only availability failures, by {@link DownstreamFailures#isAvailabilityFailure}:
 * a connect error, a response timeout, and a downstream 502, 503 or 504 (the routes' {@code statusCodes}).
 * It ignores everything else (a bulkhead refusal, a caller's own error), so they count neither for nor
 * against the downstream. Successful responses, including a passed-through 500, are successes.
 *
 * <p>Both halves matter. Resilience4j records every exception thrown inside the chain unless told
 * otherwise, so without the record predicate a caller's own failure, such as a claim Netty refuses to
 * forward (answered 401), would count, and enough of them would cut the downstream off for everyone. And
 * an exception it neither records nor ignores counts as a success (verified in 2.3.0's
 * {@code CircuitBreakerStateMachine}), so without the ignore predicate the same failure would inflate the
 * success count and, in half-open, could close the breaker without the downstream ever being reached. A
 * full bulkhead's refusal is also ignored explicitly: the downstream did not fail, the gateway chose not
 * to call it. Resilience4j ORs the two ignore rules.
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
                .recordException(DownstreamFailures::isAvailabilityFailure)
                .ignoreException(error -> !DownstreamFailures.isAvailabilityFailure(error))
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

    /**
     * A semaphore bulkhead per downstream, inside its breaker (Spring Cloud CircuitBreaker applies it
     * there, keyed by the breaker's name — verified in 5.0.2). Beyond the limit a request is refused at
     * once, without waiting: 503 DOWNSTREAM_BUSY. The breaker ignores the refusal. The M7 design,
     * section 10.
     */
    @Bean
    public Customizer<ReactiveResilience4jBulkheadProvider> downstreamBulkheads(ResilienceProperties properties) {
        BulkheadConfig config = BulkheadConfig.custom()
                .maxConcurrentCalls(properties.bulkhead().maxConcurrentCalls())
                .maxWaitDuration(Duration.ZERO)
                .build();
        return provider -> provider.configure(builder -> builder.bulkheadConfig(config), AUTHCORE, LEDGER);
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
