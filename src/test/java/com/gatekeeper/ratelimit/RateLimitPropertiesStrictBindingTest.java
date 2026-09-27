package com.gatekeeper.ratelimit;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@code gatekeeper.api-key} is an existing, unrelated prefix, so typing
 * {@code assignments.api-key} (singular) instead of {@code assignments.api-keys} under
 * {@code gatekeeper.rate-limit} is an easy slip. Relaxed binding accepts it silently and binds
 * nothing, quietly putting that caller on the default plan — the same silent failure the
 * constructor checks exist to prevent, one level down. {@code ignoreUnknownFields = false} turns
 * that slip into a boot failure instead.
 */
class RateLimitPropertiesStrictBindingTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(TestConfig.class);

    @Test
    void bindsAValidConfiguration() {
        runner.withPropertyValues(
                "gatekeeper.rate-limit.redis-timeout=200ms",
                "gatekeeper.rate-limit.default-plan=free",
                "gatekeeper.rate-limit.plans.free.requests-per-second=5",
                "gatekeeper.rate-limit.plans.free.burst=10",
                "gatekeeper.rate-limit.plans.free.daily-quota=1000",
                "gatekeeper.rate-limit.assignments.api-keys.demo-job=free")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(RateLimitProperties.class).assignments().apiKeys())
                            .containsEntry("demo-job", "free");
                });
    }

    @Test
    void refusesATypoedAssignmentKind() {
        runner.withPropertyValues(
                "gatekeeper.rate-limit.redis-timeout=200ms",
                "gatekeeper.rate-limit.default-plan=free",
                "gatekeeper.rate-limit.plans.free.requests-per-second=5",
                "gatekeeper.rate-limit.plans.free.burst=10",
                "gatekeeper.rate-limit.plans.free.daily-quota=1000",
                "gatekeeper.rate-limit.assignments.api-keys.demo-job=free",
                "gatekeeper.rate-limit.assignments.api-key.demo-job=free")
                .run(context -> {
                    assertThat(context).hasFailed();
                    String messageChain = messageChain(context.getStartupFailure());
                    assertThat(messageChain).contains("assignments.api-key.demo-job").contains("left unbound");
                });
    }

    private static String messageChain(Throwable failure) {
        StringBuilder chain = new StringBuilder();
        for (Throwable t = failure; t != null; t = t.getCause()) {
            if (t.getMessage() != null) {
                chain.append(t.getMessage()).append(' ');
            }
        }
        return chain.toString();
    }

    @Configuration
    @EnableConfigurationProperties(RateLimitProperties.class)
    static class TestConfig {
    }
}
