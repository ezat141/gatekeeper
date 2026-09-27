package com.gatekeeper.ratelimit;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.Map;
import java.util.Set;

/**
 * {@code gatekeeper.rate-limit.*}: the plans, who is on which, and how long the gateway waits
 * for Redis before letting a request through unlimited. The M5 design, sections 3, 7 and 10.
 *
 * <p><strong>Every rule is checked here, in the constructor, so a violation stops the boot.</strong>
 * The first rule matters most: a mistyped prefix binds no plans at all, and relaxed binding
 * would otherwise start a gateway that limits nothing — the one silent failure the handoff
 * warns about.
 */
@ConfigurationProperties(prefix = "gatekeeper.rate-limit")
public record RateLimitProperties(
        Duration redisTimeout,
        String defaultPlan,
        Map<String, PlanLimits> plans,
        Assignments assignments) {

    public RateLimitProperties {
        if (plans == null || plans.isEmpty()) {
            throw new IllegalArgumentException(
                    "gatekeeper.rate-limit.plans must define at least one plan");
        }
        if (redisTimeout == null || redisTimeout.isZero() || redisTimeout.isNegative()) {
            throw new IllegalArgumentException(
                    "gatekeeper.rate-limit.redis-timeout must be a positive duration");
        }
        if (defaultPlan == null || !plans.containsKey(defaultPlan)) {
            throw new IllegalArgumentException(
                    "gatekeeper.rate-limit.default-plan names no configured plan: " + defaultPlan);
        }
        plans = Map.copyOf(plans);
        assignments = assignments == null ? new Assignments(null, null, null) : assignments;
        assignments.requireKnownPlans(plans.keySet());
    }

    /** One plan's allowance. Every number at least 1. */
    public record PlanLimits(int requestsPerSecond, long burst, long dailyQuota) {

        public PlanLimits {
            if (requestsPerSecond < 1 || burst < 1 || dailyQuota < 1) {
                throw new IllegalArgumentException(
                        "every rate-limit plan value must be at least 1, got requests-per-second="
                                + requestsPerSecond + ", burst=" + burst + ", daily-quota=" + dailyQuota);
            }
        }
    }

    /** Who is on which plan, by kind. Anyone unlisted is on the default plan. */
    public record Assignments(
            Map<String, String> tenants,
            Map<String, String> clients,
            Map<String, String> apiKeys) {

        public Assignments {
            tenants = tenants == null ? Map.of() : Map.copyOf(tenants);
            clients = clients == null ? Map.of() : Map.copyOf(clients);
            apiKeys = apiKeys == null ? Map.of() : Map.copyOf(apiKeys);
        }

        void requireKnownPlans(Set<String> planNames) {
            requireKnown("tenants", tenants, planNames);
            requireKnown("clients", clients, planNames);
            requireKnown("api-keys", apiKeys, planNames);
        }

        private static void requireKnown(String kind, Map<String, String> assigned, Set<String> planNames) {
            assigned.forEach((who, plan) -> {
                if (!planNames.contains(plan)) {
                    throw new IllegalArgumentException("gatekeeper.rate-limit.assignments." + kind
                            + " assigns " + who + " to unknown plan " + plan);
                }
            });
        }
    }
}
