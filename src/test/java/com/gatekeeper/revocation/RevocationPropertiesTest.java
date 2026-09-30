package com.gatekeeper.revocation;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/** Bound strictly and validated at startup, as the limiter's are. The M6 design, section 10. */
class RevocationPropertiesTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(TestConfig.class);

    @Test
    void bindsTheTimeout() {
        runner.withPropertyValues("gatekeeper.revocation.redis-timeout=200ms")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(RevocationProperties.class).redisTimeout())
                            .isEqualTo(Duration.ofMillis(200));
                });
    }

    @Test
    void refusesAMissingTimeout() {
        runner.run(context -> assertThat(messageChain(context.getStartupFailure()))
                .contains("gatekeeper.revocation.redis-timeout must be a positive duration"));
    }

    @Test
    void refusesAZeroTimeout() {
        runner.withPropertyValues("gatekeeper.revocation.redis-timeout=0ms")
                .run(context -> assertThat(messageChain(context.getStartupFailure()))
                        .contains("gatekeeper.revocation.redis-timeout must be a positive duration"));
    }

    @Test
    void refusesANegativeTimeout() {
        runner.withPropertyValues("gatekeeper.revocation.redis-timeout=-1s")
                .run(context -> assertThat(messageChain(context.getStartupFailure()))
                        .contains("gatekeeper.revocation.redis-timeout must be a positive duration"));
    }

    /** A typo must fail the boot, not silently leave the real key unset. */
    @Test
    void refusesAnUnknownKey() {
        runner.withPropertyValues(
                        "gatekeeper.revocation.redis-timeout=200ms",
                        "gatekeeper.revocation.redis-timout=5s")
                .run(context -> assertThat(messageChain(context.getStartupFailure()))
                        .contains("redis-timout"));
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
    @EnableConfigurationProperties(RevocationProperties.class)
    static class TestConfig {
    }
}
