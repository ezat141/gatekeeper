package com.gatekeeper.ratelimit;

import java.util.Map;
import java.util.stream.Collectors;

/**
 * Plans and assignments from {@code gatekeeper.rate-limit.*}. Assignments are looked up by kind,
 * so a tenant and a client that share a name never share a plan by accident. The cost, stated
 * in the M5 design, section 3: who is on which plan lives in gateway configuration, and changes
 * with a redeploy.
 */
public class ConfiguredPlanResolver implements PlanResolver {

    private final Map<String, Plan> plans;
    private final Plan defaultPlan;
    private final RateLimitProperties.Assignments assignments;

    public ConfiguredPlanResolver(RateLimitProperties properties) {
        this.plans = properties.plans().entrySet().stream()
                .collect(Collectors.toUnmodifiableMap(Map.Entry::getKey, entry -> new Plan(
                        entry.getKey(),
                        entry.getValue().requestsPerSecond(),
                        entry.getValue().burst(),
                        entry.getValue().dailyQuota())));
        this.defaultPlan = plans.get(properties.defaultPlan());
        this.assignments = properties.assignments();
    }

    @Override
    public Plan resolve(RateLimitIdentity identity) {
        Map<String, String> assigned = switch (identity.kind()) {
            case TENANT -> assignments.tenants();
            case CLIENT -> assignments.clients();
            case API_KEY -> assignments.apiKeys();
        };
        String planName = assigned.get(identity.name());
        return planName == null ? defaultPlan : plans.get(planName);
    }
}
