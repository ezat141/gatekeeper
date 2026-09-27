package com.gatekeeper.ratelimit;

import com.gatekeeper.ratelimit.RateLimitProperties.Assignments;
import com.gatekeeper.ratelimit.RateLimitProperties.PlanLimits;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatIllegalArgumentException;

/**
 * Every rule here stops the gateway from starting when broken. A limiter configured wrongly
 * must fail the boot rather than limit nothing — see the M5 design, section 10.
 */
class RateLimitPropertiesTest {

    static final Duration TIMEOUT = Duration.ofMillis(200);
    static final PlanLimits FREE = new PlanLimits(5, 10, 1000);

    @Test
    void acceptsAValidConfiguration() {
        RateLimitProperties properties = new RateLimitProperties(TIMEOUT, "free", Map.of("free", FREE),
                new Assignments(Map.of("acme", "free"), null, null));

        assertThat(properties.assignments().tenants()).containsEntry("acme", "free");
        assertThat(properties.assignments().clients()).isEmpty();
        assertThat(properties.assignments().apiKeys()).isEmpty();
    }

    @Test
    void treatsAMissingAssignmentsSectionAsNoAssignments() {
        RateLimitProperties properties = new RateLimitProperties(TIMEOUT, "free", Map.of("free", FREE), null);

        assertThat(properties.assignments().tenants()).isEmpty();
    }

    /** What a mistyped prefix produces: nothing bound. The boot must stop, not limit nothing. */
    @Test
    void refusesNoPlansAtAll() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new RateLimitProperties(TIMEOUT, "free", null, null))
                .withMessageContaining("at least one plan");
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new RateLimitProperties(TIMEOUT, "free", Map.of(), null))
                .withMessageContaining("at least one plan");
    }

    @Test
    void refusesADefaultPlanThatDoesNotExist() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new RateLimitProperties(TIMEOUT, "gold", Map.of("free", FREE), null))
                .withMessageContaining("gold");
    }

    @Test
    void refusesAnAssignmentToAPlanThatDoesNotExist() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new RateLimitProperties(TIMEOUT, "free", Map.of("free", FREE),
                        new Assignments(null, Map.of("authcore-machine", "gold"), null)))
                .withMessageContaining("authcore-machine")
                .withMessageContaining("gold");
    }

    @Test
    void refusesALimitBelowOne() {
        assertThatIllegalArgumentException().isThrownBy(() -> new PlanLimits(0, 10, 1000));
        assertThatIllegalArgumentException().isThrownBy(() -> new PlanLimits(5, 0, 1000));
        assertThatIllegalArgumentException().isThrownBy(() -> new PlanLimits(5, 10, 0));
    }

    @Test
    void refusesAMissingOrNonPositiveTimeout() {
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new RateLimitProperties(null, "free", Map.of("free", FREE), null));
        assertThatIllegalArgumentException()
                .isThrownBy(() -> new RateLimitProperties(Duration.ZERO, "free", Map.of("free", FREE), null));
    }
}
