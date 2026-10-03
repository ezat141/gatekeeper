package com.gatekeeper.resilience;

import io.github.resilience4j.bulkhead.BulkheadConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.circuitbreaker.resilience4j.ReactiveResilience4JCircuitBreakerFactory;
import org.springframework.cloud.circuitbreaker.resilience4j.ReactiveResilience4jBulkheadProvider;
import org.springframework.cloud.circuitbreaker.resilience4j.Resilience4JConfigurationProperties;
import org.springframework.cloud.gateway.config.GatewayProperties;
import org.springframework.cloud.gateway.config.HttpClientProperties;
import org.springframework.cloud.gateway.filter.FilterDefinition;
import org.springframework.cloud.gateway.route.RouteDefinition;
import org.springframework.core.env.Environment;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The values the repo owner agreed, read from the real application.yml with no test overrides, so the
 * small values the other tests use can never hide a production change. The M7 design, section 11.
 */
@SpringBootTest
class ProductionValuesTest {

    @Autowired
    GatewayProperties gateway;

    @Autowired
    HttpClientProperties httpClient;

    @Autowired
    ResilienceProperties resilience;

    @Autowired
    Resilience4JConfigurationProperties resilience4j;

    @Autowired
    ReactiveResilience4JCircuitBreakerFactory breakers;

    @Autowired
    ReactiveResilience4jBulkheadProvider bulkheads;

    @Autowired
    Environment environment;

    @Test
    void timeouts() {
        assertThat(httpClient.getConnectTimeout()).isEqualTo(2000);
        assertThat(httpClient.getResponseTimeout()).isEqualTo(Duration.ofSeconds(5));
        assertThat(resilience.jwksTimeout()).isEqualTo(Duration.ofSeconds(2));
        for (RouteDefinition route : gateway.getRoutes()) {
            Object timeout = route.getMetadata().get("response-timeout");
            // Plain milliseconds, or Spring Cloud Gateway silently ignores it.
            assertThat(Long.parseLong(String.valueOf(timeout))).as(route.getId()).isEqualTo(5000L);
        }
    }

    @Test
    void everyRouteHasItsBreakerBeforeItsRetry() {
        Map<String, String> breakerNames = Map.of(
                "authcore-accounts", "authcore", "authcore-machine", "authcore", "ledger", "ledger");
        assertThat(gateway.getRoutes()).extracting(RouteDefinition::getId)
                .containsExactlyInAnyOrderElementsOf(breakerNames.keySet());

        for (RouteDefinition route : gateway.getRoutes()) {
            List<String> names = route.getFilters().stream().map(FilterDefinition::getName).toList();
            assertThat(names.indexOf("CircuitBreaker")).as(route.getId()).isZero();
            assertThat(names.indexOf("Retry")).as(route.getId()).isEqualTo(1);

            Map<String, String> breaker = args(route, "CircuitBreaker");
            assertThat(breaker.get("name")).isEqualTo(breakerNames.get(route.getId()));
            assertThat(breaker.get("statusCodes")).isEqualTo("BAD_GATEWAY,SERVICE_UNAVAILABLE,GATEWAY_TIMEOUT");

            Map<String, String> retry = args(route, "Retry");
            assertThat(retry.get("retries")).isEqualTo("1");
            assertThat(retry.get("methods")).isEqualTo("GET");
            assertThat(retry.get("statuses")).isEqualTo("BAD_GATEWAY,SERVICE_UNAVAILABLE");
            assertThat(retry.get("exceptions")).isEqualTo("java.net.ConnectException");
            // Once, after 100 ms: the nested backoff binds as dotted keys.
            assertThat(retry.get("backoff.firstBackoff")).isEqualTo("100ms");
            assertThat(retry.get("backoff.maxBackoff")).isEqualTo("100ms");
            assertThat(retry.get("backoff.factor")).isEqualTo("1");
            assertThat(retry.get("backoff.basedOnPreviousValue")).isEqualTo("false");
            // Present and empty, so only the listed statuses are retried: absent, the filter's default
            // series would retry the whole 5xx range.
            assertThat(retry).containsKey("series");
            assertThat(retry.get("series")).isEmpty();
        }
    }

    @Test
    void theBreakersAndBulkheads() {
        assertThat(resilience4j.isDisableTimeLimiter()).isTrue();
        // Only the reactive factory is used; the blocking one must not run first for a downstream's name.
        assertThat(environment.getProperty("spring.cloud.circuitbreaker.resilience4j.blocking.enabled"))
                .isEqualTo("false");
        for (String name : List.of(ResilienceConfig.AUTHCORE, ResilienceConfig.LEDGER)) {
            // Run one call through, so the factory creates the breaker and bulkhead from its configuration.
            breakers.create(name).run(Mono.just("ok"), null).block();

            CircuitBreakerConfig breaker = breakers.getCircuitBreakerRegistry().find(name).orElseThrow()
                    .getCircuitBreakerConfig();
            assertThat(breaker.getSlidingWindowSize()).isEqualTo(20);
            assertThat(breaker.getMinimumNumberOfCalls()).isEqualTo(10);
            assertThat(breaker.getFailureRateThreshold()).isEqualTo(50f);
            assertThat(breaker.getPermittedNumberOfCallsInHalfOpenState()).isEqualTo(3);
            // Resilience4j 2.3.0 stores the open window as an interval function (milliseconds by attempt).
            assertThat(breaker.getWaitIntervalFunctionInOpenState().apply(1)).isEqualTo(10_000L);

            BulkheadConfig bulkhead = bulkheads.getBulkheadRegistry().find(name).orElseThrow().getBulkheadConfig();
            assertThat(bulkhead.getMaxConcurrentCalls()).isEqualTo(50);
            assertThat(bulkhead.getMaxWaitDuration()).isEqualTo(Duration.ZERO);
        }
        assertThat(resilience.breaker().openFor()).isEqualTo(Duration.ofSeconds(10));
    }

    private static Map<String, String> args(RouteDefinition route, String filter) {
        return route.getFilters().stream()
                .filter(definition -> definition.getName().equals(filter))
                .findFirst().orElseThrow()
                .getArgs().entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }
}
