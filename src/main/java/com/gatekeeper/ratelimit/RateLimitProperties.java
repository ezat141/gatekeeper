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
 * warns about. Unknown keys under the prefix are refused too, so a misspelt kind inside
 * {@code assignments} (for example {@code api-key} for {@code api-keys}) fails the boot rather
 * than silently putting its callers on the default plan.
 */
@ConfigurationProperties(prefix = "gatekeeper.rate-limit", ignoreUnknownFields = false)
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

    /** One plan's allowance. Every number at least 1, and burst and daily quota at most {@link #MAX_VALUE}. */
    public record PlanLimits(int requestsPerSecond, long burst, long dailyQuota) {

        /**
         * 1e12: exact in a Lua double, so the script's arithmetic never overflows it, and
         * {@code burst / rate * 2} stays far inside Redis's {@code EXPIRE} limit.
         */
        static final long MAX_VALUE = 1_000_000_000_000L;

        public PlanLimits {
            if (requestsPerSecond < 1 || burst < 1 || dailyQuota < 1) {
                throw new IllegalArgumentException(
                        "every rate-limit plan value must be present and at least 1, got requests-per-second="
                                + requestsPerSecond + ", burst=" + burst + ", daily-quota=" + dailyQuota);
            }
            if (burst > MAX_VALUE || dailyQuota > MAX_VALUE) {
                throw new IllegalArgumentException(
                        "burst and daily-quota must be at most " + MAX_VALUE
                                + "; larger values overflow the Redis script, got burst=" + burst
                                + ", daily-quota=" + dailyQuota);
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
                            + " assigns " + who + " to unknown plan '" + plan + "'");
                }
            });
        }
    }
}
