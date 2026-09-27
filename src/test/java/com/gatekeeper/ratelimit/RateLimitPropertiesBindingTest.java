package com.gatekeeper.ratelimit;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Relaxed binding accepts a mistyped key silently, so a context that starts proves nothing about
 * the values. This reads them back: the structure from {@code application.yml}, and the
 * unlimited allowances from the test override in {@code config/application.yml} — which is also
 * the proof that the override is loaded at all.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class RateLimitPropertiesBindingTest {

    @Autowired
    RateLimitProperties properties;

    @Test
    void bindsTheStructureFromApplicationYml() {
        assertThat(properties.redisTimeout()).isEqualTo(Duration.ofMillis(200));
        assertThat(properties.defaultPlan()).isEqualTo("free");
        assertThat(properties.plans()).containsOnlyKeys("free", "pro");
        assertThat(properties.assignments().tenants()).containsEntry("acme", "pro");
        assertThat(properties.assignments().clients()).containsEntry("authcore-machine", "pro");
        assertThat(properties.assignments().apiKeys()).containsEntry("demo-reporting-job", "free");
    }

    @Test
    void appliesTheTestOverrideSoExistingSuitesAreNeverLimited() {
        assertThat(properties.plans().get("free").requestsPerSecond()).isEqualTo(1_000_000);
        assertThat(properties.plans().get("pro").dailyQuota()).isEqualTo(1_000_000_000L);

        assertThat(properties.plans().values()).allSatisfy(limits -> {
            assertThat(limits.requestsPerSecond()).isGreaterThanOrEqualTo(1_000_000);
            assertThat(limits.dailyQuota()).isGreaterThanOrEqualTo(1_000_000_000L);
        });
    }
}
