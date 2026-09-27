package com.gatekeeper.ratelimit;

import com.gatekeeper.ratelimit.RateLimitIdentity.Kind;
import com.gatekeeper.ratelimit.RateLimitProperties.Assignments;
import com.gatekeeper.ratelimit.RateLimitProperties.PlanLimits;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

class ConfiguredPlanResolverTest {

    private final ConfiguredPlanResolver resolver = new ConfiguredPlanResolver(new RateLimitProperties(
            Duration.ofMillis(200),
            "free",
            Map.of("free", new PlanLimits(5, 10, 1000), "pro", new PlanLimits(50, 100, 100_000)),
            new Assignments(
                    Map.of("acme", "pro", "shared-name", "pro"),
                    Map.of("authcore-machine", "pro"),
                    Map.of("demo-reporting-job", "pro"))));

    @Test
    void resolvesAnAssignedTenant() {
        assertThat(resolver.resolve(new RateLimitIdentity(Kind.TENANT, "acme")))
                .isEqualTo(new Plan("pro", 50, 100, 100_000));
    }

    @Test
    void resolvesAnAssignedClient() {
        assertThat(resolver.resolve(new RateLimitIdentity(Kind.CLIENT, "authcore-machine")).name())
                .isEqualTo("pro");
    }

    @Test
    void resolvesAnAssignedApiKey() {
        assertThat(resolver.resolve(new RateLimitIdentity(Kind.API_KEY, "demo-reporting-job")).name())
                .isEqualTo("pro");
    }

    @Test
    void givesAnyoneUnlistedTheDefaultPlan() {
        assertThat(resolver.resolve(new RateLimitIdentity(Kind.TENANT, "default")))
                .isEqualTo(new Plan("free", 5, 10, 1000));
    }

    /** Assignments are per kind: a client that happens to share a tenant's name is not that tenant. */
    @Test
    void keepsATenantAndAClientOfTheSameNameApart() {
        assertThat(resolver.resolve(new RateLimitIdentity(Kind.TENANT, "shared-name")).name()).isEqualTo("pro");
        assertThat(resolver.resolve(new RateLimitIdentity(Kind.CLIENT, "shared-name")).name()).isEqualTo("free");
    }

    @Test
    void rejectsAnIdentityWithoutAName() {
        assertThatNullPointerException().isThrownBy(() -> new RateLimitIdentity(Kind.TENANT, null));
    }
}
