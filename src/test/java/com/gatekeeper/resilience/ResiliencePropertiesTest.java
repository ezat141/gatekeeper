package com.gatekeeper.resilience;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/** Bound strictly and validated at startup, as in M5 and M6. The M7 design, section 12. */
class ResiliencePropertiesTest {

    static final String[] VALID = {
            "gatekeeper.resilience.jwks-timeout=2s",
            "gatekeeper.resilience.response-timeout-millis.authcore-accounts=5000",
            "gatekeeper.resilience.response-timeout-millis.authcore-machine=5000",
            "gatekeeper.resilience.response-timeout-millis.ledger=5000",
            "gatekeeper.resilience.breaker.sliding-window-size=20",
            "gatekeeper.resilience.breaker.minimum-calls=10",
            "gatekeeper.resilience.breaker.failure-rate-threshold=50",
            "gatekeeper.resilience.breaker.open-for=10s",
            "gatekeeper.resilience.breaker.trial-calls=3",
            "gatekeeper.resilience.bulkhead.max-concurrent-calls=50",
    };

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(TestConfig.class);

    @Test
    void bindsAValidConfiguration() {
        runner.withPropertyValues(VALID).run(context -> {
            assertThat(context).hasNotFailed();
            ResilienceProperties properties = context.getBean(ResilienceProperties.class);
            assertThat(properties.jwksTimeout()).isEqualTo(Duration.ofSeconds(2));
            assertThat(properties.responseTimeoutMillis()).containsEntry("ledger", 5000L);
            assertThat(properties.breaker().openFor()).isEqualTo(Duration.ofSeconds(10));
            assertThat(properties.breaker().failureRateThreshold()).isEqualTo(50f);
            assertThat(properties.bulkhead().maxConcurrentCalls()).isEqualTo(50);
        });
    }

    @Test
    void refusesAMissingBlock() {
        runner.run(context -> assertThat(messageChain(context.getStartupFailure()))
                .contains("gatekeeper.resilience"));
    }

    @Test
    void refusesANonPositiveRouteTimeout() {
        refuses("gatekeeper.resilience.response-timeout-millis.ledger=0", "response-timeout-millis");
    }

    @Test
    void refusesMinimumCallsAboveTheWindow() {
        refuses("gatekeeper.resilience.breaker.minimum-calls=21", "minimum-calls");
    }

    @Test
    void refusesAFailureRateOutsideOneToAHundred() {
        refuses("gatekeeper.resilience.breaker.failure-rate-threshold=0", "failure-rate-threshold");
        refuses("gatekeeper.resilience.breaker.failure-rate-threshold=101", "failure-rate-threshold");
    }

    @Test
    void refusesAZeroBulkhead() {
        refuses("gatekeeper.resilience.bulkhead.max-concurrent-calls=0", "max-concurrent-calls");
    }

    /** A typo fails the boot rather than leaving the breaker on Resilience4j's defaults. */
    @Test
    void refusesAnUnknownKey() {
        refuses("gatekeeper.resilience.breaker.open-fro=5s", "open-fro");
    }

    private void refuses(String override, String expectedInMessage) {
        runner.withPropertyValues(VALID).withPropertyValues(override)
                .run(context -> assertThat(messageChain(context.getStartupFailure())).contains(expectedInMessage));
    }

    private static String messageChain(Throwable failure) {
        assertThat(failure).as("startup failure").isNotNull();
        StringBuilder chain = new StringBuilder();
        for (Throwable t = failure; t != null; t = t.getCause()) {
            if (t.getMessage() != null) {
                chain.append(t.getMessage()).append(' ');
            }
        }
        return chain.toString();
    }

    @Configuration
    @EnableConfigurationProperties(ResilienceProperties.class)
    static class TestConfig {
    }
}
