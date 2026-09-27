# GateKeeper M5 — Distributed Rate Limiting and Daily Quotas Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Limit every authorized caller to its plan's per-second rate and daily quota, enforced in Redis so that every gateway instance sharing that Redis enforces one limit, and refuse with `429` in the platform shape with a computed `Retry-After`.

**Architecture:** A `GlobalFilter` running after authorization derives the caller's identity (`tenant:`, `client:` or `apikey:`), resolves its plan from configuration, and runs one atomic Lua script against two Redis hashes per identity — a token bucket and a daily counter — on Redis's clock. A Redis error or timeout lets the request through unlimited. Refusals are rendered by a small writer in the `error` package through the same `ErrorBody` as every other refusal.

**Tech Stack:** Spring Boot 4.0.7, Spring Cloud Gateway 5.0.2 (webflux), Spring Security 7.0.6, Spring Framework 7.0.8, spring-data-redis 4.0.6 (reactive, Lettuce), Redis 7, WireMock 3.13.2, JUnit 6.0.3.

Design: [`docs/superpowers/specs/2026-09-27-gatekeeper-m5-design.md`](../specs/2026-09-27-gatekeeper-m5-design.md). Where this plan and the spec disagree, the spec wins — say so rather than silently following one.

---

## Environment rules — read before the first command

- **`.\mvnw.cmd -o`, never `mvn`.** M5 adds no dependency; every build runs offline.
- **Redis must be running for the suite**, from the authcore directory: `docker compose up -d redis`. Without it, Redis-backed tests fail with `RedisConnectionFailureException` — not a regression.
- **`curl.exe`, never `curl`** in PowerShell. **`&&` does not work** in Windows PowerShell 5.1; use `;` or the Bash tool.
- **Commit with `git commit -F <file>`**, the message written with a file-writing tool. Never `Set-Content -Encoding utf8` (it writes a BOM).
- **No Claude attribution anywhere** — no `Co-Authored-By`, no "Generated with Claude Code", in commits, merges or PR text.
- **Verify every framework name you add** that this plan does not give, with `javap -cp <jar> <FQCN>` against `~/.m2/repository`.
- **Jackson 3** (`tools.jackson.databind`) if you ever need a mapper. This plan does not.
- **Branches:** `feature/m5-task-N` off `master`, merged with `git merge --no-ff`. The `feature/task-N` and `feature/m4-task-N` names are taken.
- **Suite count on `master` before M5: 151.**

**Single-repo milestone.** Only `D:\courses\My CV\My cv\ProjectsCVs\gatekeeper` changes. AuthCore and ledger-service are started for Task 8 and never modified.

---

## Facts this plan relies on, all verified against the jars

- Spring Cloud Gateway's `RedisRateLimiter` sets rates per route id, not per caller, so the gateway carries its own limiter (spec §2).
- `ReactiveRedisTemplate.execute(RedisScript<T>, List<K> keys, List<?> args)` returns `Flux<T>`; `RedisScript.of(Resource, Class<T>)` builds a script; the executor tries `EVALSHA` and falls back to `EVAL`.
- A Lua number returned to Redis is truncated to an integer, so the script returns only integer-valued numbers and Java reads them as `Long`.
- Access tokens carry `aud = [client id]`; client-credentials tokens carry `sub = client id`; user access tokens carry `tenant`.
- `EXPIREAT` with a time in the past deletes the key immediately. **Script tests must use a fixed `now` in the future**, never a date in the past.
- Spring Boot loads both `classpath:/application.yml` and `classpath:/config/application.yml`, the second overriding the first property by property. The test override in Task 1 relies on this; Task 1's binding test proves it.

---

## File structure

| File | Responsibility |
|---|---|
| `src/main/java/com/gatekeeper/ratelimit/RateLimitProperties.java` | Create — binds and validates `gatekeeper.rate-limit.*` |
| `src/main/java/com/gatekeeper/ratelimit/Plan.java` | Create — a plan's name and limits |
| `src/main/java/com/gatekeeper/ratelimit/PlanResolver.java` | Create — interface |
| `src/main/java/com/gatekeeper/ratelimit/ConfiguredPlanResolver.java` | Create — assignments from configuration |
| `src/main/java/com/gatekeeper/ratelimit/RateLimitIdentity.java` | Create — `tenant:` / `client:` / `apikey:`, encoded |
| `src/main/java/com/gatekeeper/ratelimit/RateLimitReason.java` | Create — the two refusal reasons and their `detail` |
| `src/main/java/com/gatekeeper/ratelimit/Decision.java` | Create — one check's outcome |
| `src/main/java/com/gatekeeper/ratelimit/RateLimitStore.java` | Create — interface |
| `src/main/java/com/gatekeeper/ratelimit/RedisRateLimitStore.java` | Create — runs the script |
| `src/main/resources/ratelimit/check.lua` | Create — bucket and quota, atomically |
| `src/main/java/com/gatekeeper/ratelimit/RateLimitConfig.java` | Create — the resolver and store beans |
| `src/main/java/com/gatekeeper/ratelimit/RateLimitFilter.java` | Create — the `GlobalFilter` |
| `src/main/java/com/gatekeeper/error/TooManyRequestsWriter.java` | Create — the `429` body |
| `src/main/java/com/gatekeeper/error/ErrorBody.java` | Modify — Javadoc names the new caller |
| `src/main/resources/application.yml` | Modify — plans and assignments |
| `src/test/resources/config/application.yml` | Create — keeps existing suites out of the limiter's way |
| `src/test/java/com/gatekeeper/ratelimit/*Test.java` | Create — unit, script, integration, two-gateway, fail-open |
| `src/test/java/com/gatekeeper/error/TooManyRequestsWriterTest.java` | Create |

**Why `ratelimit` is its own package:** it mirrors `apikey`, `authz` and `identity`, and it is the package the implementation plan's structure names. The writer lives in `error` because `ErrorBody` is package-private there, as M4's 403 handler does.

---

## Task 1: Plans — configuration, validation and resolution

**Files:**
- Create: `src/main/java/com/gatekeeper/ratelimit/Plan.java`
- Create: `src/main/java/com/gatekeeper/ratelimit/RateLimitProperties.java`
- Create: `src/main/java/com/gatekeeper/ratelimit/PlanResolver.java`
- Create: `src/main/java/com/gatekeeper/ratelimit/ConfiguredPlanResolver.java`
- Create: `src/main/java/com/gatekeeper/ratelimit/RateLimitIdentity.java` (the record only — its derivation from an `Authentication` is Task 2)
- Modify: `src/main/resources/application.yml`
- Create: `src/test/resources/config/application.yml`
- Test: `src/test/java/com/gatekeeper/ratelimit/RateLimitPropertiesTest.java`
- Test: `src/test/java/com/gatekeeper/ratelimit/RateLimitPropertiesBindingTest.java`
- Test: `src/test/java/com/gatekeeper/ratelimit/ConfiguredPlanResolverTest.java`

- [ ] **Step 1: Branch, start Redis, confirm the baseline**

```bash
git checkout master
git checkout -b feature/m5-task-1
```

From the authcore directory: `docker compose up -d redis`. Then `.\mvnw.cmd -o test` — expected PASS, 151. If not, stop and report.

- [ ] **Step 2: Write the failing validation test**

`src/test/java/com/gatekeeper/ratelimit/RateLimitPropertiesTest.java`:

```java
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
```

- [ ] **Step 3: Run it to make sure it fails**

`.\mvnw.cmd -o test -Dtest=RateLimitPropertiesTest` — expected: compilation failure, `RateLimitProperties` does not exist.

- [ ] **Step 4: Write `Plan` and `RateLimitProperties`**

`src/main/java/com/gatekeeper/ratelimit/Plan.java`:

```java
package com.gatekeeper.ratelimit;

/** A plan's name and the allowance it grants every caller assigned to it. */
public record Plan(String name, int requestsPerSecond, long burst, long dailyQuota) {
}
```

`src/main/java/com/gatekeeper/ratelimit/RateLimitProperties.java`:

```java
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
```

- [ ] **Step 5: Run it to make sure it passes**

`.\mvnw.cmd -o test -Dtest=RateLimitPropertiesTest` — expected PASS, 7.

- [ ] **Step 6: Configuration, and the test override**

Append to `src/main/resources/application.yml`, under the existing top-level `gatekeeper:` key (after `api-key:`, same indentation as `api-key:`):

```yaml
  rate-limit:
    # How long a request waits for Redis before going through unlimited. Rate limiting is a
    # capacity control, not a security control, so a Redis failure must not become a gateway
    # outage — and it must fail fast, not hang (the JWKS fetch's missing timeout is an open M7
    # item; this call does not repeat it). See the M5 design, section 7.
    redis-timeout: 200ms
    default-plan: free
    plans:
      free:
        requests-per-second: 5
        burst: 10
        daily-quota: 1000
      pro:
        requests-per-second: 50
        burst: 100
        daily-quota: 100000
    # Anyone unlisted is on default-plan. Tenants are user tokens' tenant claim; clients are a
    # tenant-less token's aud (its client id); api-keys are the key's name from introspection.
    assignments:
      tenants:
        acme: pro
      clients:
        authcore-machine: pro
      api-keys:
        demo-reporting-job: free
```

Create `src/test/resources/config/application.yml`:

```yaml
# Loaded after classpath:/application.yml and overriding it property by property.
#
# Every existing integration test calls as tenant acme or a handful of clients, and quota state
# lives for a day in the Redis the tests share. Left at the real limits, repeated runs would
# accumulate counts and start failing at random. So every plan the main configuration defines
# is made effectively unlimited here. Rate-limit tests define their own small plans and use
# fresh identities, and never rely on these two.
gatekeeper:
  rate-limit:
    plans:
      free:
        requests-per-second: 1000000
        burst: 1000000
        daily-quota: 1000000000
      pro:
        requests-per-second: 1000000
        burst: 1000000
        daily-quota: 1000000000
```

- [ ] **Step 7: The binding test — proves both files bind as intended**

`src/test/java/com/gatekeeper/ratelimit/RateLimitPropertiesBindingTest.java`:

```java
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
    }
}
```

Run `.\mvnw.cmd -o test -Dtest=RateLimitPropertiesBindingTest` — expected PASS, 2. **If the override test fails because `free` still reads 5, stop and report**: the override file is not being loaded, and every later task depends on it.

- [ ] **Step 8: Write the failing resolver test**

`src/test/java/com/gatekeeper/ratelimit/ConfiguredPlanResolverTest.java`:

```java
package com.gatekeeper.ratelimit;

import com.gatekeeper.ratelimit.RateLimitIdentity.Kind;
import com.gatekeeper.ratelimit.RateLimitProperties.Assignments;
import com.gatekeeper.ratelimit.RateLimitProperties.PlanLimits;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

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
}
```

Run `.\mvnw.cmd -o test -Dtest=ConfiguredPlanResolverTest` — expected: compilation failure.

- [ ] **Step 9: Write `RateLimitIdentity` (record only), `PlanResolver`, `ConfiguredPlanResolver`**

`src/main/java/com/gatekeeper/ratelimit/RateLimitIdentity.java` — the record and its key; Task 2 adds the derivation:

```java
package com.gatekeeper.ratelimit;

import java.nio.charset.StandardCharsets;

/**
 * Whose bucket a request counts against: a tenant, or else a client, or else an API key. The
 * M5 design, section 4.
 *
 * <p>{@link #key()} is the Redis-safe form, {@code <kind>:<name>}. The name is percent-encoded
 * outside {@code [A-Za-z0-9._-]}. No caller can choose an identity — every part comes from a
 * signed token or from introspection — but an odd name must still never break the key's
 * structure or the {@code {…}} hash tag it is wrapped in.
 */
public record RateLimitIdentity(Kind kind, String name) {

    public enum Kind {
        TENANT("tenant"),
        CLIENT("client"),
        API_KEY("apikey");

        private final String prefix;

        Kind(String prefix) {
            this.prefix = prefix;
        }
    }

    public String key() {
        return kind.prefix + ":" + encode(name);
    }

    static String encode(String raw) {
        StringBuilder encoded = new StringBuilder();
        for (byte b : raw.getBytes(StandardCharsets.UTF_8)) {
            int c = b & 0xFF;
            boolean plain = (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                    || c == '.' || c == '_' || c == '-';
            if (plain) {
                encoded.append((char) c);
            } else {
                encoded.append('%').append(String.format("%02X", c));
            }
        }
        return encoded.toString();
    }
}
```

`src/main/java/com/gatekeeper/ratelimit/PlanResolver.java`:

```java
package com.gatekeeper.ratelimit;

/**
 * Which plan a caller is on. An interface so that a later milestone can move assignments out of
 * configuration — into Redis behind a management API — without touching the limiter.
 */
public interface PlanResolver {

    Plan resolve(RateLimitIdentity identity);
}
```

`src/main/java/com/gatekeeper/ratelimit/ConfiguredPlanResolver.java`:

```java
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
```

- [ ] **Step 10: Run the three classes, then the whole suite**

`.\mvnw.cmd -o test -Dtest="RateLimitPropertiesTest,RateLimitPropertiesBindingTest,ConfiguredPlanResolverTest"` — expected PASS, 14.

`.\mvnw.cmd -o test` — expected PASS, 165 (151 + 14). Nothing is wired into the request path yet.

- [ ] **Step 11: Make it fail on purpose**

1. In `RateLimitProperties`, delete the `plans == null || plans.isEmpty()` check. Expected: `refusesNoPlansAtAll` fails. Revert.
2. In `ConfiguredPlanResolver.resolve`, look every kind up in `assignments.tenants()`. Expected: `keepsATenantAndAClientOfTheSameNameApart`, `resolvesAnAssignedClient` and `resolvesAnAssignedApiKey` fail. Revert.

- [ ] **Step 12: Commit**

Message:

```
feat(M5): plans, their validation, and who is on which

Plans and assignments come from gatekeeper.rate-limit in configuration,
behind a PlanResolver that a later milestone can move into Redis. Every
rule is checked when the properties bind, so a mistyped prefix or an
assignment to a plan that does not exist stops the boot instead of
starting a gateway that limits nothing.

Tests run with every configured plan made effectively unlimited, so the
existing suites never meet the limiter.
```

```bash
git add src/main/java/com/gatekeeper/ratelimit src/main/resources/application.yml src/test/resources/config src/test/java/com/gatekeeper/ratelimit
git commit -F <message-file>
```

- [ ] **Step 13: Review, then merge** — spec-compliance review, then code-quality review, each told not to trust the report; fix and re-review until clean; `git checkout master; git merge --no-ff feature/m5-task-1` with message `Merge branch 'feature/m5-task-1'`.

---

## Task 2: Identity from the authenticated caller

**Files:**
- Modify: `src/main/java/com/gatekeeper/ratelimit/RateLimitIdentity.java`
- Test: `src/test/java/com/gatekeeper/ratelimit/RateLimitIdentityTest.java`

- [ ] **Step 1: Branch** — `git checkout master; git checkout -b feature/m5-task-2`

- [ ] **Step 2: Write the failing test**

`src/test/java/com/gatekeeper/ratelimit/RateLimitIdentityTest.java`:

```java
package com.gatekeeper.ratelimit;

import com.gatekeeper.apikey.ApiKeyAuthenticationToken;
import com.gatekeeper.ratelimit.RateLimitIdentity.Kind;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.List;
import java.util.function.UnaryOperator;

import static org.assertj.core.api.Assertions.assertThat;

/** The M5 design, section 4: tenant where there is one, otherwise the client, or the key. */
class RateLimitIdentityTest {

    @Test
    void aUserTokenCountsAgainstItsTenant() {
        assertThat(RateLimitIdentity.of(jwt(builder -> builder
                .subject("ezzat").audience(List.of("authcore-spa")).claim("tenant", "acme"))))
                .contains(new RateLimitIdentity(Kind.TENANT, "acme"));
    }

    /** Client credentials: no tenant, and aud names the client. */
    @Test
    void aTenantlessTokenCountsAgainstItsClient() {
        assertThat(RateLimitIdentity.of(jwt(builder -> builder
                .subject("authcore-machine").audience(List.of("authcore-machine")))))
                .contains(new RateLimitIdentity(Kind.CLIENT, "authcore-machine"));
    }

    /** aud is the identity when present, even where sub differs. */
    @Test
    void preferTheAudienceOverTheSubject() {
        assertThat(RateLimitIdentity.of(jwt(builder -> builder
                .subject("someone").audience(List.of("the-client")))))
                .contains(new RateLimitIdentity(Kind.CLIENT, "the-client"));
    }

    /** Without aud, sub — which on a client-credentials token is the same client id. */
    @Test
    void fallsBackToTheSubjectWithoutAnAudience() {
        assertThat(RateLimitIdentity.of(jwt(builder -> builder.subject("authcore-machine"))))
                .contains(new RateLimitIdentity(Kind.CLIENT, "authcore-machine"));
    }

    /** A blank tenant is no tenant: every such token would otherwise share one bucket. */
    @Test
    void treatsABlankTenantAsAbsent() {
        assertThat(RateLimitIdentity.of(jwt(builder -> builder
                .subject("c").audience(List.of("c")).claim("tenant", " "))))
                .contains(new RateLimitIdentity(Kind.CLIENT, "c"));
    }

    @Test
    void anApiKeyCountsAgainstItsName() {
        Authentication key = new ApiKeyAuthenticationToken("demo-reporting-job",
                AuthorityUtils.createAuthorityList("SCOPE_payments:read"));

        assertThat(RateLimitIdentity.of(key)).contains(new RateLimitIdentity(Kind.API_KEY, "demo-reporting-job"));
    }

    @Test
    void anythingElseHasNoIdentity() {
        Authentication anonymous = new AnonymousAuthenticationToken(
                "key", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

        assertThat(RateLimitIdentity.of(anonymous)).isEmpty();
        assertThat(RateLimitIdentity.of(null)).isEmpty();
    }

    @Test
    void keysCarryTheKindAndTheName() {
        assertThat(new RateLimitIdentity(Kind.TENANT, "acme").key()).isEqualTo("tenant:acme");
        assertThat(new RateLimitIdentity(Kind.CLIENT, "authcore-machine").key()).isEqualTo("client:authcore-machine");
        assertThat(new RateLimitIdentity(Kind.API_KEY, "demo_job.v2").key()).isEqualTo("apikey:demo_job.v2");
    }

    /** Braces would move the Redis Cluster hash tag; colons and spaces would blur the structure. */
    @Test
    void percentEncodesAnythingOutsideTheSafeSet() {
        assertThat(new RateLimitIdentity(Kind.TENANT, "we{ird}:name one").key())
                .isEqualTo("tenant:we%7Bird%7D%3Aname%20one");
        assertThat(new RateLimitIdentity(Kind.TENANT, "café").key()).isEqualTo("tenant:caf%C3%A9");
    }

    private static Authentication jwt(UnaryOperator<Jwt.Builder> claims) {
        Jwt token = claims.apply(Jwt.withTokenValue("t").header("alg", "RS256")).build();
        return new JwtAuthenticationToken(token, AuthorityUtils.NO_AUTHORITIES);
    }
}
```

Run `.\mvnw.cmd -o test -Dtest=RateLimitIdentityTest` — expected: compilation failure, `RateLimitIdentity.of` does not exist.

- [ ] **Step 3: Add the derivation**

In `RateLimitIdentity.java`, add these imports:

```java
import com.gatekeeper.apikey.ApiKeyAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.List;
import java.util.Optional;
```

and this method, after `key()`:

```java
    /**
     * Derives the identity of an authenticated caller.
     *
     * <ul>
     *   <li>A JWT carrying a non-blank {@code tenant} — every user token — is its tenant. Every
     *       user of a tenant shares the tenant's plan, which is what a plan means for a tenant.</li>
     *   <li>A tenant-less JWT — client credentials — is its client: the first {@code aud}, which
     *       Spring Authorization Server sets to the client id, else {@code sub}, which on a
     *       client-credentials token is that same client id. {@code aud} is <em>read</em> as
     *       identity here, not validated: AuthCore's {@code aud} names the client, not a resource
     *       server, so there is nothing to validate it against. It is signed, so a caller cannot
     *       choose whose bucket they drain. See the M5 design, section 4.</li>
     *   <li>An API key is its name, from introspection.</li>
     * </ul>
     *
     * Anything else has no identity. Every routed request is authenticated, so that is not
     * expected to happen.
     */
    public static Optional<RateLimitIdentity> of(Authentication authentication) {
        if (authentication instanceof JwtAuthenticationToken jwtAuthentication) {
            Jwt token = jwtAuthentication.getToken();
            String tenant = token.getClaimAsString("tenant");
            if (tenant != null && !tenant.isBlank()) {
                return Optional.of(new RateLimitIdentity(Kind.TENANT, tenant));
            }
            List<String> audience = token.getAudience();
            String client = audience != null && !audience.isEmpty() ? audience.get(0) : token.getSubject();
            return Optional.ofNullable(client).map(name -> new RateLimitIdentity(Kind.CLIENT, name));
        }
        if (authentication instanceof ApiKeyAuthenticationToken apiKey && apiKey.isAuthenticated()) {
            return Optional.ofNullable(apiKey.getName()).map(name -> new RateLimitIdentity(Kind.API_KEY, name));
        }
        return Optional.empty();
    }
```

- [ ] **Step 4: Run it** — `.\mvnw.cmd -o test -Dtest=RateLimitIdentityTest` — expected PASS, 9. Then `.\mvnw.cmd -o test` — expected 174.

- [ ] **Step 5: Make it fail on purpose**

1. Drop the tenant branch (always use the client). Expected: `aUserTokenCountsAgainstItsTenant` fails. Revert.
2. Use `token.getSubject()` before `aud`. Expected: `preferTheAudienceOverTheSubject` fails. Revert.
3. Add `'{'` and `'}'` to the plain set in `encode`. Expected: `percentEncodesAnythingOutsideTheSafeSet` fails. Revert.

- [ ] **Step 6: Commit**

```
feat(M5): whose bucket a request counts against

A user token counts against its tenant, a tenant-less token against its
client (the aud Spring Authorization Server sets to the client id, else
sub), and an API key against its name. aud is read as identity and not
validated: AuthCore's aud names the client, not a resource server, and
it is signed, so no caller can pick whose bucket it drains.
```

```bash
git add src/main/java/com/gatekeeper/ratelimit/RateLimitIdentity.java src/test/java/com/gatekeeper/ratelimit/RateLimitIdentityTest.java
git commit -F <message-file>
```

- [ ] **Step 7: Review, then merge** — as Task 1 Step 13, branch `feature/m5-task-2`.

---

## Task 3: The script and the Redis store

**Files:**
- Create: `src/main/resources/ratelimit/check.lua`
- Create: `src/main/java/com/gatekeeper/ratelimit/RateLimitReason.java`
- Create: `src/main/java/com/gatekeeper/ratelimit/Decision.java`
- Create: `src/main/java/com/gatekeeper/ratelimit/RateLimitStore.java`
- Create: `src/main/java/com/gatekeeper/ratelimit/RedisRateLimitStore.java`
- Test: `src/test/java/com/gatekeeper/ratelimit/RedisRateLimitStoreTest.java`

- [ ] **Step 1: Branch** — `git checkout master; git checkout -b feature/m5-task-3`

- [ ] **Step 2: Write the failing test**

`src/test/java/com/gatekeeper/ratelimit/RedisRateLimitStoreTest.java`:

```java
package com.gatekeeper.ratelimit;

import com.gatekeeper.ratelimit.RateLimitIdentity.Kind;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The script against the real Redis, with a fixed {@code now}, so that refill, Retry-After and
 * the midnight rollover are exact assertions rather than sleeps. The M5 design, section 6.
 *
 * <p><strong>{@code now} is always in the future.</strong> The quota key expires with
 * {@code EXPIREAT} at the next UTC midnight plus an hour, computed from {@code now}; a {@code now}
 * in the past would make Redis delete the key the moment it was written.
 *
 * <p>Every test uses a fresh tenant and deletes its keys afterwards: this Redis is shared with
 * AuthCore and with every other test.
 */
@SpringBootTest
class RedisRateLimitStoreTest {

    static final double DAY = 86_400;

    /** Noon, UTC, two days from now. */
    static final double NOON = (Math.floor(System.currentTimeMillis() / 1000.0 / DAY) + 2) * DAY + DAY / 2;

    @Autowired
    ReactiveStringRedisTemplate redis;

    private final List<RateLimitIdentity> used = new ArrayList<>();

    @AfterEach
    void deleteKeys() {
        for (RateLimitIdentity identity : used) {
            redis.delete(RedisRateLimitStore.bucketKey(identity), RedisRateLimitStore.quotaKey(identity)).block();
        }
    }

    @Test
    void allowsTheBurstAndRefusesTheNextRequest() {
        RateLimitIdentity caller = fresh();
        Plan plan = new Plan("t", 1, 3, 100);

        for (long remaining = 2; remaining >= 0; remaining--) {
            Decision allowed = check(caller, plan, NOON);
            assertThat(allowed.allowed()).isTrue();
            assertThat(allowed.tokensRemaining()).isEqualTo(remaining);
        }
        Decision refused = check(caller, plan, NOON);

        assertThat(refused.allowed()).isFalse();
        assertThat(refused.reason()).isEqualTo(RateLimitReason.RATE_LIMITED);
        assertThat(refused.tokensRemaining()).isZero();
        assertThat(refused.retryAfterSeconds()).isEqualTo(1);
    }

    @Test
    void refillsAtThePlansRate() {
        RateLimitIdentity caller = fresh();
        Plan plan = new Plan("t", 2, 4, 100);
        for (int i = 0; i < 4; i++) {
            check(caller, plan, NOON);
        }

        // 1.5 s at 2 tokens/s refills 3; the request takes one.
        Decision decision = check(caller, plan, NOON + 1.5);

        assertThat(decision.allowed()).isTrue();
        assertThat(decision.tokensRemaining()).isEqualTo(2);
    }

    @Test
    void neverRefillsBeyondTheBurst() {
        RateLimitIdentity caller = fresh();
        Plan plan = new Plan("t", 10, 3, 100);
        check(caller, plan, NOON);

        Decision decision = check(caller, plan, NOON + 3600);

        assertThat(decision.tokensRemaining()).isEqualTo(2);
    }

    @Test
    void refusesOnceTheDailyQuotaIsUsedUpUntilUtcMidnight() {
        RateLimitIdentity caller = fresh();
        Plan plan = new Plan("t", 1000, 1000, 2);
        assertThat(check(caller, plan, NOON).quotaRemaining()).isEqualTo(1);
        assertThat(check(caller, plan, NOON).quotaRemaining()).isZero();

        Decision refused = check(caller, plan, NOON);

        assertThat(refused.allowed()).isFalse();
        assertThat(refused.reason()).isEqualTo(RateLimitReason.QUOTA_EXCEEDED);
        assertThat(refused.retryAfterSeconds()).isEqualTo(43_200);
        assertThat(refused.quotaResetSeconds()).isEqualTo(43_200);
    }

    /** The bucket is checked first, so a request refused for speed spends none of the day. */
    @Test
    void aRateRefusalSpendsNoQuota() {
        RateLimitIdentity caller = fresh();
        Plan plan = new Plan("t", 1, 1, 5);
        check(caller, plan, NOON);
        assertThat(check(caller, plan, NOON).reason()).isEqualTo(RateLimitReason.RATE_LIMITED);

        Decision next = check(caller, plan, NOON + 1);

        assertThat(next.allowed()).isTrue();
        assertThat(next.quotaRemaining()).isEqualTo(3);
    }

    /** A request refused for the quota takes no token. */
    @Test
    void aQuotaRefusalTakesNoToken() {
        RateLimitIdentity caller = fresh();
        Plan plan = new Plan("t", 1, 5, 1);
        check(caller, plan, NOON);

        Decision refused = check(caller, plan, NOON);

        assertThat(refused.reason()).isEqualTo(RateLimitReason.QUOTA_EXCEEDED);
        assertThat(refused.tokensRemaining()).isEqualTo(4);
        assertThat(redis.opsForHash().get(RedisRateLimitStore.bucketKey(caller), "tokens").block())
                .asString().startsWith("4");
    }

    @Test
    void resetsTheQuotaAtUtcMidnight() {
        RateLimitIdentity caller = fresh();
        Plan plan = new Plan("t", 1000, 1000, 1);
        double midnight = NOON + DAY / 2;

        assertThat(check(caller, plan, midnight - 0.5).allowed()).isTrue();
        Decision refused = check(caller, plan, midnight - 0.4);
        assertThat(refused.reason()).isEqualTo(RateLimitReason.QUOTA_EXCEEDED);
        assertThat(refused.retryAfterSeconds()).isEqualTo(1);

        assertThat(check(caller, plan, midnight + 0.1).allowed()).isTrue();
    }

    @Test
    void namesAndExpiresItsKeysAsSpecified() {
        RateLimitIdentity caller = fresh();
        check(caller, new Plan("t", 5, 10, 100), NOON);

        assertThat(RedisRateLimitStore.bucketKey(caller)).isEqualTo("gatekeeper:rl:{" + caller.key() + "}");
        assertThat(RedisRateLimitStore.quotaKey(caller)).isEqualTo("gatekeeper:quota:{" + caller.key() + "}");

        // ceil(burst / rate * 2) = ceil(10 / 5 * 2) = 4 s.
        Duration bucketTtl = redis.getExpire(RedisRateLimitStore.bucketKey(caller)).block();
        assertThat(bucketTtl).isBetween(Duration.ofSeconds(1), Duration.ofSeconds(4));

        // Next UTC midnight after NOON, plus an hour, measured from the real clock.
        double expireAt = NOON + DAY / 2 + 3600;
        double expected = expireAt - System.currentTimeMillis() / 1000.0;
        Duration quotaTtl = redis.getExpire(RedisRateLimitStore.quotaKey(caller)).block();
        assertThat((double) quotaTtl.toSeconds()).isBetween(expected - 5, expected + 5);
    }

    /** Production passes no time: Redis's own clock is used, so the call works end to end. */
    @Test
    void usesRedisTimeWhenNoTimeIsGiven() {
        RateLimitIdentity caller = fresh();

        Decision decision = new RedisRateLimitStore(redis).check(caller, new Plan("t", 5, 10, 100)).block();

        assertThat(decision.allowed()).isTrue();
        assertThat(decision.tokensRemaining()).isEqualTo(9);
        assertThat(decision.quotaResetSeconds()).isBetween(1L, 86_400L);
    }

    private Decision check(RateLimitIdentity caller, Plan plan, double now) {
        return new RedisRateLimitStore(redis).check(caller, plan, now).block();
    }

    private RateLimitIdentity fresh() {
        RateLimitIdentity identity = new RateLimitIdentity(Kind.TENANT, "t-" + UUID.randomUUID());
        used.add(identity);
        return identity;
    }
}
```

Run `.\mvnw.cmd -o test -Dtest=RedisRateLimitStoreTest` — expected: compilation failure.

- [ ] **Step 3: The script**

`src/main/resources/ratelimit/check.lua`:

```lua
-- GateKeeper rate limit: a token bucket and a daily quota for one identity, checked and spent
-- atomically. The M5 design, section 6.
--
-- KEYS[1]  bucket hash: tokens, ts
-- KEYS[2]  quota hash:  day, count
-- ARGV[1]  requests per second (refill rate)
-- ARGV[2]  burst (bucket capacity)
-- ARGV[3]  daily quota
-- ARGV[4]  now, in seconds since the epoch; empty in production, so Redis's clock is used and
--          every gateway instance shares one clock
--
-- Returns six integers: allowed (1/0), reason (0 none, 1 rate, 2 quota), tokens remaining,
-- quota remaining, retry-after seconds, seconds until the quota resets.

local rate = tonumber(ARGV[1])
local burst = tonumber(ARGV[2])
local quota = tonumber(ARGV[3])
local now = tonumber(ARGV[4])
if not now then
  local time = redis.call('TIME')
  now = tonumber(time[1]) + tonumber(time[2]) / 1000000
end

local day = math.floor(now / 86400)
local until_midnight = math.ceil((day + 1) * 86400 - now)

local tokens = burst
local stored_tokens = tonumber(redis.call('HGET', KEYS[1], 'tokens'))
local stored_ts = tonumber(redis.call('HGET', KEYS[1], 'ts'))
if stored_tokens and stored_ts then
  tokens = math.min(burst, stored_tokens + math.max(0, now - stored_ts) * rate)
end

local count = 0
if tonumber(redis.call('HGET', KEYS[2], 'day')) == day then
  count = tonumber(redis.call('HGET', KEYS[2], 'count')) or 0
end

-- Bucket first: a request refused for speed spends none of the day, and nothing is written.
if tokens < 1 then
  return {0, 1, 0, quota - count, math.max(1, math.ceil((1 - tokens) / rate)), until_midnight}
end

-- Then the quota: a request refused for the day takes no token, and nothing is written.
if count + 1 > quota then
  return {0, 2, math.floor(tokens), 0, math.max(1, until_midnight), until_midnight}
end

tokens = tokens - 1
count = count + 1
redis.call('HSET', KEYS[1], 'tokens', string.format('%.6f', tokens), 'ts', string.format('%.6f', now))
redis.call('EXPIRE', KEYS[1], math.max(1, math.ceil(burst / rate * 2)))
redis.call('HSET', KEYS[2], 'day', string.format('%d', day), 'count', string.format('%d', count))
redis.call('EXPIREAT', KEYS[2], string.format('%d', (day + 1) * 86400 + 3600))
return {1, 0, math.floor(tokens), quota - count, 0, until_midnight}
```

- [ ] **Step 4: The reason, the decision, the store**

`src/main/java/com/gatekeeper/ratelimit/RateLimitReason.java`:

```java
package com.gatekeeper.ratelimit;

/**
 * Why a request was refused 429, with the one {@code detail} string a caller sees for it. Neither
 * names the plan or the identity. The M5 design, section 8.
 */
public enum RateLimitReason {

    RATE_LIMITED("the request rate exceeds the caller's plan"),
    QUOTA_EXCEEDED("the caller's daily quota is used up");

    private final String detail;

    RateLimitReason(String detail) {
        this.detail = detail;
    }

    public String detail() {
        return detail;
    }
}
```

`src/main/java/com/gatekeeper/ratelimit/Decision.java`:

```java
package com.gatekeeper.ratelimit;

/**
 * One check's outcome. {@code reason} is null when the request is allowed; {@code
 * retryAfterSeconds} is zero then.
 */
public record Decision(
        boolean allowed,
        RateLimitReason reason,
        long tokensRemaining,
        long quotaRemaining,
        long retryAfterSeconds,
        long quotaResetSeconds) {
}
```

`src/main/java/com/gatekeeper/ratelimit/RateLimitStore.java`:

```java
package com.gatekeeper.ratelimit;

import reactor.core.publisher.Mono;

/** Checks, and on success spends, one request of a caller's allowance. */
@FunctionalInterface
public interface RateLimitStore {

    Mono<Decision> check(RateLimitIdentity identity, Plan plan);
}
```

`src/main/java/com/gatekeeper/ratelimit/RedisRateLimitStore.java`:

```java
package com.gatekeeper.ratelimit;

import org.springframework.core.io.ClassPathResource;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * One atomic script per request against two hashes per identity: the bucket and the daily
 * quota. The M5 design, section 6.
 *
 * <p>Both keys carry the identity as a {@code {…}} hash tag, so they share a Redis Cluster slot,
 * which a multi-key script requires. The day is a field of the quota hash, not part of its name:
 * a script must declare its keys before it runs, and the day is known only from Redis's clock,
 * read inside the script.
 */
public class RedisRateLimitStore implements RateLimitStore {

    @SuppressWarnings("rawtypes")
    private static final RedisScript<List> SCRIPT =
            RedisScript.of(new ClassPathResource("ratelimit/check.lua"), List.class);

    private final ReactiveStringRedisTemplate redis;

    public RedisRateLimitStore(ReactiveStringRedisTemplate redis) {
        this.redis = redis;
    }

    static String bucketKey(RateLimitIdentity identity) {
        return "gatekeeper:rl:{" + identity.key() + "}";
    }

    static String quotaKey(RateLimitIdentity identity) {
        return "gatekeeper:quota:{" + identity.key() + "}";
    }

    @Override
    public Mono<Decision> check(RateLimitIdentity identity, Plan plan) {
        return run(identity, plan, "");
    }

    /** For tests only: a fixed {@code now}, so time-dependent behaviour is exact. */
    Mono<Decision> check(RateLimitIdentity identity, Plan plan, double now) {
        return run(identity, plan, Double.toString(now));
    }

    private Mono<Decision> run(RateLimitIdentity identity, Plan plan, String now) {
        return redis.execute(SCRIPT,
                        List.of(bucketKey(identity), quotaKey(identity)),
                        List.of(Integer.toString(plan.requestsPerSecond()),
                                Long.toString(plan.burst()),
                                Long.toString(plan.dailyQuota()),
                                now))
                .next()
                .map(RedisRateLimitStore::toDecision);
    }

    private static Decision toDecision(List<?> result) {
        long reason = number(result, 1);
        return new Decision(
                number(result, 0) == 1,
                reason == 1 ? RateLimitReason.RATE_LIMITED : reason == 2 ? RateLimitReason.QUOTA_EXCEEDED : null,
                number(result, 2),
                number(result, 3),
                number(result, 4),
                number(result, 5));
    }

    private static long number(List<?> result, int index) {
        return ((Number) result.get(index)).longValue();
    }
}
```

- [ ] **Step 5: Run it** — `.\mvnw.cmd -o test -Dtest=RedisRateLimitStoreTest` — expected PASS, 9.

If a test fails on a value the script returns (for example the quota TTL, or the rounding of `tokens`), **investigate the script before touching the test**, and report the actual value. If `execute` returns elements that are not `Number`, report the actual type rather than coercing.

Then `.\mvnw.cmd -o test` — expected 183.

- [ ] **Step 6: Make it fail on purpose**

1. In the script, move the quota block above the bucket block. Expected: `checksTheBucketBeforeTheQuota` fails (added in Task 3: the plan's original expectation named `aRateRefusalSpendsNoQuota`, which cannot see the order — only a request over both limits can). Revert.
2. Replace `math.max(1, until_midnight)` in the quota refusal with `1`. Expected: `refusesOnceTheDailyQuotaIsUsedUpUntilUtcMidnight` fails. Revert.
3. Replace the `if tonumber(redis.call('HGET', KEYS[2], 'day')) == day then` condition with `if true then`. Expected: `resetsTheQuotaAtUtcMidnight` fails. Revert.

- [ ] **Step 7: Commit**

```
feat(M5): one script for the bucket and the daily quota

A token bucket and a daily counter per identity, checked and spent
atomically on Redis's clock, so every gateway instance shares one clock
and one count. The bucket is checked first, so a request refused for
speed spends none of the day, and a request refused for the day takes
no token. The day is a field rather than part of the key's name,
because a script must declare its keys before it can read the time.
```

```bash
git add src/main/resources/ratelimit src/main/java/com/gatekeeper/ratelimit src/test/java/com/gatekeeper/ratelimit/RedisRateLimitStoreTest.java
git commit -F <message-file>
```

- [ ] **Step 8: Review, then merge** — as Task 1 Step 13, branch `feature/m5-task-3`.

---

## Task 4: The 429 writer

**Files:**
- Create: `src/main/java/com/gatekeeper/error/TooManyRequestsWriter.java`
- Modify: `src/main/java/com/gatekeeper/error/ErrorBody.java` (Javadoc only)
- Test: `src/test/java/com/gatekeeper/error/TooManyRequestsWriterTest.java`

- [ ] **Step 1: Branch** — `git checkout master; git checkout -b feature/m5-task-4`

- [ ] **Step 2: Write the failing test**

`src/test/java/com/gatekeeper/error/TooManyRequestsWriterTest.java`:

```java
package com.gatekeeper.error;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpResponse;
import org.springframework.mock.web.server.MockServerWebExchange;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class TooManyRequestsWriterTest {

    private final TooManyRequestsWriter writer = new TooManyRequestsWriter(ServerCodecConfigurer.create());

    @Test
    void writesThePlatformShapeWithTheGivenDetailAndHeaders() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/ledger/entries"));
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put(HttpHeaders.RETRY_AFTER, "7");
        headers.put("X-RateLimit-Remaining", "0");

        writer.write(exchange, "the request rate exceeds the caller's plan", headers).block();

        MockServerHttpResponse response = exchange.getResponse();
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(response.getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_JSON);
        assertThat(response.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("7");
        assertThat(response.getHeaders().getFirst("X-RateLimit-Remaining")).isEqualTo("0");
        assertThat(response.getBodyAsString().block()).isEqualTo(
                "{\"error\":\"too_many_requests\",\"status\":429,\"path\":\"/api/ledger/entries\","
                        + "\"detail\":\"the request rate exceeds the caller's plan\"}");
    }

    /** The caller is authenticated; the answer is to wait, not to re-authenticate. */
    @Test
    void setsNoChallenge() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/x"));

        writer.write(exchange, "the caller's daily quota is used up", Map.of()).block();

        assertThat(exchange.getResponse().getHeaders().get(HttpHeaders.WWW_AUTHENTICATE)).isNull();
    }
}
```

Run `.\mvnw.cmd -o test -Dtest=TooManyRequestsWriterTest` — expected: compilation failure.

- [ ] **Step 3: Write the writer**

`src/main/java/com/gatekeeper/error/TooManyRequestsWriter.java`:

```java
package com.gatekeeper.error;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Writes the 429 the rate limiter refuses with, in the platform's {@link ErrorBody} shape, through
 * the same writers as the 401 entry point and the 403 handler. The limiter completes the response
 * itself with this rather than throwing, so the 429 shape is written in exactly one place. The
 * M5 design, section 8.
 *
 * <p>The caller supplies the {@code detail} and every header, {@code Retry-After} included: this
 * class knows the shape of a refusal, not the rules of rate limiting. No {@code WWW-Authenticate}
 * — the caller is authenticated.
 */
@Component
public class TooManyRequestsWriter {

    private final ServerCodecConfigurer codecConfigurer;

    public TooManyRequestsWriter(ServerCodecConfigurer codecConfigurer) {
        this.codecConfigurer = codecConfigurer;
    }

    public Mono<Void> write(ServerWebExchange exchange, String detail, Map<String, String> headers) {
        String path = exchange.getRequest().getPath().value();
        return ServerResponse.status(HttpStatus.TOO_MANY_REQUESTS)
                .contentType(MediaType.APPLICATION_JSON)
                .headers(outgoing -> headers.forEach(outgoing::set))
                .bodyValue(ErrorBody.of(HttpStatus.TOO_MANY_REQUESTS, path, detail))
                .flatMap(response -> response.writeTo(exchange, new CodecWriterContext(codecConfigurer)));
    }
}
```

In `ErrorBody.java`'s class Javadoc, change the first paragraph's list of callers to name this one too: after `{@link JsonServerAccessDeniedHandler} (the 403 it commits the same way)` add `, and {@link TooManyRequestsWriter} (the rate limiter's 429)`, and change "Three call sites" to "Four call sites".

- [ ] **Step 4: Run it** — `.\mvnw.cmd -o test -Dtest=TooManyRequestsWriterTest` — expected PASS, 2. Full suite — expected 185.

- [ ] **Step 5: Make it fail on purpose** — remove `.headers(...)`. Expected: `writesThePlatformShapeWithTheGivenDetailAndHeaders` fails on `Retry-After`. Revert.

- [ ] **Step 6: Commit**

```
feat(M5): a 429 in the platform's JSON shape

Written through the same ErrorBody and writers as the 401 and the 403,
with the detail and every header, Retry-After included, supplied by the
caller. The writer knows the shape of a refusal; the limiter knows why.
```

```bash
git add src/main/java/com/gatekeeper/error src/test/java/com/gatekeeper/error/TooManyRequestsWriterTest.java
git commit -F <message-file>
```

- [ ] **Step 7: Review, then merge** — as Task 1 Step 13, branch `feature/m5-task-4`.

---

## Task 5: The filter, wired in, end to end

**Files:**
- Create: `src/main/java/com/gatekeeper/ratelimit/RateLimitConfig.java`
- Create: `src/main/java/com/gatekeeper/ratelimit/RateLimitFilter.java`
- Test: `src/test/java/com/gatekeeper/ratelimit/RateLimitFilterTest.java`
- Test: `src/test/java/com/gatekeeper/ratelimit/RateLimitTest.java`
- Test: `src/test/java/com/gatekeeper/ratelimit/DeadRedisFailOpenTest.java`
- Test: `src/test/java/com/gatekeeper/ratelimit/SilentRedisFailOpenTest.java`

- [ ] **Step 1: Branch** — `git checkout master; git checkout -b feature/m5-task-5`

- [ ] **Step 2: Write the failing unit test of the filter**

The trap this test exists for: a `Mono<Void>` from the downstream chain completes *empty*, so writing the filter as `.flatMap(limit).switchIfEmpty(chain.filter(exchange))` forwards every allowed request **twice**. Every case below counts chain calls.

`src/test/java/com/gatekeeper/ratelimit/RateLimitFilterTest.java`:

```java
package com.gatekeeper.ratelimit;

import com.gatekeeper.error.TooManyRequestsWriter;
import com.gatekeeper.ratelimit.RateLimitProperties.PlanLimits;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class RateLimitFilterTest {

    static final Authentication ACME = new JwtAuthenticationToken(
            Jwt.withTokenValue("t").header("alg", "RS256").subject("ezzat").claim("tenant", "acme").build(),
            AuthorityUtils.NO_AUTHORITIES);

    static final RateLimitProperties PROPERTIES = new RateLimitProperties(
            Duration.ofMillis(100), "free", Map.of("free", new PlanLimits(5, 10, 1000)), null);

    final AtomicInteger chainCalls = new AtomicInteger();
    final AtomicInteger storeCalls = new AtomicInteger();
    final GatewayFilterChain chain = exchange -> {
        chainCalls.incrementAndGet();
        return Mono.empty();
    };

    @Test
    void forwardsAnAllowedRequestOnceWithTheHeaders() {
        MockServerWebExchange exchange = exchange();

        run(exchange, store(Mono.just(new Decision(true, null, 9, 999, 0, 3600))), ACME);

        assertThat(chainCalls).hasValue(1);
        HttpHeaders headers = exchange.getResponse().getHeaders();
        assertThat(headers.getFirst("X-RateLimit-Remaining")).isEqualTo("9");
        assertThat(headers.getFirst("X-RateLimit-Replenish-Rate")).isEqualTo("5");
        assertThat(headers.getFirst("X-RateLimit-Burst-Capacity")).isEqualTo("10");
        assertThat(headers.getFirst("X-Quota-Limit")).isEqualTo("1000");
        assertThat(headers.getFirst("X-Quota-Remaining")).isEqualTo("999");
        assertThat(headers.getFirst("X-Quota-Reset")).isEqualTo("3600");
        assertThat(headers.getFirst(HttpHeaders.RETRY_AFTER)).isNull();
    }

    @Test
    void refusesWithoutForwarding() {
        MockServerWebExchange exchange = exchange();

        run(exchange, store(Mono.just(new Decision(false, RateLimitReason.QUOTA_EXCEEDED, 4, 0, 120, 120))), ACME);

        assertThat(chainCalls).hasValue(0);
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(exchange.getResponse().getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("120");
        assertThat(exchange.getResponse().getHeaders().getFirst("X-Quota-Remaining")).isEqualTo("0");
        assertThat(exchange.getResponse().getBodyAsString().block())
                .contains("\"detail\":\"the caller's daily quota is used up\"");
    }

    @Test
    void letsARequestThroughUnlimitedWhenTheStoreFails() {
        MockServerWebExchange exchange = exchange();

        run(exchange, store(Mono.error(new IllegalStateException("redis down"))), ACME);

        assertThat(chainCalls).hasValue(1);
        assertThat(exchange.getResponse().getHeaders().getFirst("X-RateLimit-Remaining")).isNull();
    }

    @Test
    void letsARequestThroughUnlimitedWhenTheStoreNeverAnswers() {
        MockServerWebExchange exchange = exchange();
        long started = System.nanoTime();

        run(exchange, store(Mono.never()), ACME);

        assertThat(chainCalls).hasValue(1);
        assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(2));
        assertThat(exchange.getResponse().getHeaders().getFirst("X-RateLimit-Remaining")).isNull();
    }

    @Test
    void letsARequestThroughUnlimitedWhenTheStoreCompletesEmpty() {
        MockServerWebExchange exchange = exchange();

        run(exchange, store(Mono.empty()), ACME);

        assertThat(chainCalls).hasValue(1);
        assertThat(exchange.getResponse().getHeaders().getFirst("X-RateLimit-Remaining")).isNull();
    }

    @Test
    void forwardsACallerWithNoIdentityOnceWithoutConsultingTheStore() {
        MockServerWebExchange exchange = exchange();

        filter(store(Mono.just(new Decision(true, null, 9, 999, 0, 3600)))).filter(exchange, chain).block();

        assertThat(chainCalls).hasValue(1);
        assertThat(storeCalls).hasValue(0);
    }

    private static MockServerWebExchange exchange() {
        return MockServerWebExchange.from(MockServerHttpRequest.get("/api/ledger/entries"));
    }

    private RateLimitStore store(Mono<Decision> answer) {
        return (identity, plan) -> {
            storeCalls.incrementAndGet();
            return answer;
        };
    }

    private RateLimitFilter filter(RateLimitStore store) {
        return new RateLimitFilter(new ConfiguredPlanResolver(PROPERTIES), store,
                new TooManyRequestsWriter(ServerCodecConfigurer.create()), PROPERTIES);
    }

    private void run(MockServerWebExchange exchange, RateLimitStore store, Authentication caller) {
        filter(store).filter(exchange, chain)
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(caller))
                .block(Duration.ofSeconds(5));
    }
}
```

Run `.\mvnw.cmd -o test -Dtest=RateLimitFilterTest` — expected: compilation failure.

- [ ] **Step 3: Write the filter and the configuration**

`src/main/java/com/gatekeeper/ratelimit/RateLimitConfig.java`:

```java
package com.gatekeeper.ratelimit;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;

@Configuration
public class RateLimitConfig {

    @Bean
    public PlanResolver planResolver(RateLimitProperties properties) {
        return new ConfiguredPlanResolver(properties);
    }

    @Bean
    public RateLimitStore rateLimitStore(ReactiveStringRedisTemplate redis) {
        return new RedisRateLimitStore(redis);
    }
}
```

`src/main/java/com/gatekeeper/ratelimit/RateLimitFilter.java`:

```java
package com.gatekeeper.ratelimit;

import com.gatekeeper.error.TooManyRequestsWriter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Limits every routed request to its caller's plan. The M5 design, sections 4 to 8.
 *
 * <p>A gateway filter, so it runs after Spring Security's whole chain: only a request that
 * passed authentication and the rule table is counted, and a 401 or 403 never touches Redis.
 * Ordered just after {@code IdentityStampFilter} and ahead of every routing filter, so a refusal
 * never reaches a downstream. It applies to every route without route configuration.
 *
 * <p><strong>Fails open, fast.</strong> A Redis error, a timeout, or an empty answer lets the
 * request through unlimited, with a warning and no rate-limit headers. Rate limiting is a
 * capacity control; a Redis outage must not become a gateway outage. M6's revocation check will
 * fail closed on the same Redis, deliberately — see the M5 design, section 7.
 *
 * <p>The fail-open branch covers only the store call, never the downstream chain: an error from
 * the downstream must not be mistaken for Redis failing and forward the request a second time.
 */
@Component
public class RateLimitFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(RateLimitFilter.class);

    private final PlanResolver plans;
    private final RateLimitStore store;
    private final TooManyRequestsWriter writer;
    private final Duration timeout;

    public RateLimitFilter(PlanResolver plans, RateLimitStore store, TooManyRequestsWriter writer,
                           RateLimitProperties properties) {
        this.plans = plans;
        this.store = store;
        this.writer = writer;
        this.timeout = properties.redisTimeout();
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .mapNotNull(SecurityContext::getAuthentication)
                .map(RateLimitIdentity::of)
                .defaultIfEmpty(Optional.empty())
                .flatMap(identity -> identity
                        .map(caller -> limit(exchange, chain, caller))
                        .orElseGet(() -> {
                            log.warn("Routed request with no rate-limit identity; forwarding unlimited: {}",
                                    exchange.getRequest().getPath());
                            return chain.filter(exchange);
                        }));
    }

    private Mono<Void> limit(ServerWebExchange exchange, GatewayFilterChain chain, RateLimitIdentity caller) {
        Plan plan = plans.resolve(caller);
        return store.check(caller, plan)
                .timeout(timeout)
                .map(Optional::of)
                .onErrorResume(error -> {
                    log.warn("Rate limiter unavailable; forwarding {} unlimited", caller.key(), error);
                    return Mono.just(Optional.<Decision>empty());
                })
                .defaultIfEmpty(Optional.empty())
                .flatMap(decision -> decision
                        .map(outcome -> apply(exchange, chain, plan, outcome))
                        .orElseGet(() -> chain.filter(exchange)));
    }

    private Mono<Void> apply(ServerWebExchange exchange, GatewayFilterChain chain, Plan plan, Decision decision) {
        Map<String, String> headers = headers(plan, decision);
        if (decision.allowed()) {
            headers.forEach(exchange.getResponse().getHeaders()::set);
            return chain.filter(exchange);
        }
        headers.put(HttpHeaders.RETRY_AFTER, Long.toString(decision.retryAfterSeconds()));
        return writer.write(exchange, decision.reason().detail(), headers);
    }

    private static Map<String, String> headers(Plan plan, Decision decision) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("X-RateLimit-Remaining", Long.toString(decision.tokensRemaining()));
        headers.put("X-RateLimit-Replenish-Rate", Integer.toString(plan.requestsPerSecond()));
        headers.put("X-RateLimit-Burst-Capacity", Long.toString(plan.burst()));
        headers.put("X-Quota-Limit", Long.toString(plan.dailyQuota()));
        headers.put("X-Quota-Remaining", Long.toString(decision.quotaRemaining()));
        headers.put("X-Quota-Reset", Long.toString(decision.quotaResetSeconds()));
        return headers;
    }

    /** Just after {@code IdentityStampFilter}, which is {@code HIGHEST_PRECEDENCE}. */
    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 1;
    }
}
```

- [ ] **Step 4: Run the unit test** — `.\mvnw.cmd -o test -Dtest=RateLimitFilterTest` — expected PASS, 6.

- [ ] **Step 5: Write the end-to-end test**

`src/test/java/com/gatekeeper/ratelimit/RateLimitTest.java`:

```java
package com.gatekeeper.ratelimit;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.gatekeeper.support.TestKey;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.anyRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * The limiter through the real chain, one gateway. The M5 design, sections 4, 5 and 8.
 *
 * <p>The default plan here is {@code burst3} (1/s, burst 3). Rate tests send the burst and one
 * more back to back; the fourth request lands well inside the second it would take one token to
 * refill. Quota tests use {@code quota3} (effectively unlimited rate, quota 3), which needs no
 * timing at all. Every test uses fresh tenants and clients, so neither the shared Redis nor
 * another test can have spent their allowance.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class RateLimitTest {

    static final String ISSUER = "http://localhost:8080";
    static final String QUOTA_TENANT = "q-" + UUID.randomUUID();
    static final String ROOMY_TENANT = "r-" + UUID.randomUUID();

    static WireMockServer downstream;
    static TestKey signingKey;

    @Autowired
    WebTestClient client;

    @Autowired
    ReactiveStringRedisTemplate redis;

    @BeforeAll
    static void start() {
        signingKey = TestKey.generate("k1");
        downstream = new WireMockServer(options().dynamicPort());
        downstream.start();
        downstream.stubFor(get(urlEqualTo("/oauth2/jwks")).willReturn(okJson(TestKey.jwksDocument(signingKey))));
        downstream.stubFor(any(anyUrl()).atPriority(20).willReturn(okJson("{}")));
    }

    @AfterAll
    static void stop() {
        downstream.stop();
    }

    @BeforeEach
    void clearRequestLog() {
        downstream.resetRequests();
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("gatekeeper.auth.jwk-set-uri", () -> downstream.baseUrl() + "/oauth2/jwks");
        registry.add("gatekeeper.auth.issuer", () -> ISSUER);
        registry.add("gatekeeper.downstream.ledger", () -> downstream.baseUrl());
        registry.add("gatekeeper.downstream.authcore", () -> downstream.baseUrl());
        registry.add("gatekeeper.rate-limit.default-plan", () -> "burst3");
        registry.add("gatekeeper.rate-limit.plans.burst3.requests-per-second", () -> "1");
        registry.add("gatekeeper.rate-limit.plans.burst3.burst", () -> "3");
        registry.add("gatekeeper.rate-limit.plans.burst3.daily-quota", () -> "1000");
        registry.add("gatekeeper.rate-limit.plans.quota3.requests-per-second", () -> "1000");
        registry.add("gatekeeper.rate-limit.plans.quota3.burst", () -> "1000");
        registry.add("gatekeeper.rate-limit.plans.quota3.daily-quota", () -> "3");
        registry.add("gatekeeper.rate-limit.plans.roomy.requests-per-second", () -> "1");
        registry.add("gatekeeper.rate-limit.plans.roomy.burst", () -> "6");
        registry.add("gatekeeper.rate-limit.plans.roomy.daily-quota", () -> "1000");
        registry.add("gatekeeper.rate-limit.assignments.tenants." + QUOTA_TENANT, () -> "quota3");
        registry.add("gatekeeper.rate-limit.assignments.tenants." + ROOMY_TENANT, () -> "roomy");
    }

    @Test
    void refusesTheRequestAfterTheBurstWith429() {
        String token = userToken(freshTenant(), "ezzat");
        for (int i = 0; i < 3; i++) {
            ledger(token).expectStatus().isOk();
        }

        ledger(token)
                .expectStatus().isEqualTo(429)
                .expectHeader().valueEquals(HttpHeaders.RETRY_AFTER, "1")
                .expectHeader().valueEquals("X-RateLimit-Remaining", "0")
                .expectHeader().doesNotExist(HttpHeaders.WWW_AUTHENTICATE)
                .expectBody()
                .jsonPath("$.error").isEqualTo("too_many_requests")
                .jsonPath("$.status").isEqualTo(429)
                .jsonPath("$.path").isEqualTo("/api/ledger/entries")
                .jsonPath("$.detail").isEqualTo(RateLimitReason.RATE_LIMITED.detail());

        assertThat(downstream.findAll(anyRequestedFor(urlPathEqualTo("/ledger/entries")))).hasSize(3);
    }

    @Test
    void refusesOnceTheDailyQuotaIsUsedUp() {
        String token = userToken(QUOTA_TENANT, "ezzat");
        for (int i = 0; i < 3; i++) {
            ledger(token).expectStatus().isOk();
        }

        long retryAfter = Long.parseLong(ledger(token)
                .expectStatus().isEqualTo(429)
                .expectBody().jsonPath("$.detail").isEqualTo(RateLimitReason.QUOTA_EXCEEDED.detail())
                .returnResult().getResponseHeaders().getFirst(HttpHeaders.RETRY_AFTER));

        long untilMidnight = 86_400 - Instant.now().getEpochSecond() % 86_400;
        assertThat(retryAfter).isBetween(untilMidnight - 5, untilMidnight + 5);
        assertThat(downstream.findAll(anyRequestedFor(urlPathEqualTo("/ledger/entries")))).hasSize(3);
    }

    @Test
    void allowedResponsesCarryTheHeaders() {
        ledger(userToken(freshTenant(), "ezzat"))
                .expectStatus().isOk()
                .expectHeader().valueEquals("X-RateLimit-Remaining", "2")
                .expectHeader().valueEquals("X-RateLimit-Replenish-Rate", "1")
                .expectHeader().valueEquals("X-RateLimit-Burst-Capacity", "3")
                .expectHeader().valueEquals("X-Quota-Limit", "1000")
                .expectHeader().valueEquals("X-Quota-Remaining", "999")
                .expectHeader().exists("X-Quota-Reset")
                .expectHeader().doesNotExist(HttpHeaders.RETRY_AFTER);
    }

    @Test
    void differentPlansGetDifferentAllowances() {
        ledger(userToken(ROOMY_TENANT, "ezzat")).expectHeader().valueEquals("X-RateLimit-Burst-Capacity", "6");
        ledger(userToken(freshTenant(), "ezzat")).expectHeader().valueEquals("X-RateLimit-Burst-Capacity", "3");
    }

    @Test
    void usersOfOneTenantShareABucket() {
        String tenant = freshTenant();
        ledger(userToken(tenant, "alice")).expectStatus().isOk();
        ledger(userToken(tenant, "alice")).expectStatus().isOk();
        ledger(userToken(tenant, "bob")).expectStatus().isOk();

        ledger(userToken(tenant, "bob")).expectStatus().isEqualTo(429);
    }

    @Test
    void twoClientsDoNotShareABucket() {
        String first = clientToken("c-" + UUID.randomUUID());
        String second = clientToken("c-" + UUID.randomUUID());
        for (int i = 0; i < 3; i++) {
            ledger(first).expectStatus().isOk();
        }

        ledger(second).expectStatus().isOk().expectHeader().valueEquals("X-RateLimit-Remaining", "2");
    }

    /** Authentication and the rule table run first: their refusals are never counted. */
    @Test
    void refusalsBeforeTheLimiterCarryNoHeadersAndTouchNoRedis() {
        String tenant = freshTenant();

        client.get().uri("/api/ledger/entries").exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().doesNotExist("X-RateLimit-Remaining");
        client.get().uri("/api/unknown")
                .header(HttpHeaders.AUTHORIZATION, userToken(tenant, "ezzat"))
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().doesNotExist("X-RateLimit-Remaining");

        RateLimitIdentity identity = new RateLimitIdentity(RateLimitIdentity.Kind.TENANT, tenant);
        assertThat(redis.hasKey(RedisRateLimitStore.bucketKey(identity)).block()).isFalse();
        assertThat(redis.hasKey(RedisRateLimitStore.quotaKey(identity)).block()).isFalse();
    }

    private WebTestClient.ResponseSpec ledger(String bearer) {
        return client.get().uri("/api/ledger/entries").header(HttpHeaders.AUTHORIZATION, bearer).exchange();
    }

    private static String freshTenant() {
        return "t-" + UUID.randomUUID();
    }

    private static String userToken(String tenant, String subject) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("scope", List.of("payments:read"));
        claims.put("tenant", tenant);
        claims.put("aud", List.of("authcore-spa"));
        return "Bearer " + signingKey.mint(ISSUER, subject, Instant.now().plus(5, ChronoUnit.MINUTES), claims);
    }

    private static String clientToken(String clientId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("scope", List.of("payments:read"));
        claims.put("aud", List.of(clientId));
        return "Bearer " + signingKey.mint(ISSUER, clientId, Instant.now().plus(5, ChronoUnit.MINUTES), claims);
    }
}
```

`TestKey.mint` writes the `claims` map with `JWTClaimsSet.Builder.claim`; if `aud` supplied that way does not reach the decoded token as an audience list (check `Jwt.getAudience()` in a failing assertion before adjusting anything), report it rather than changing the identity code.

Run `.\mvnw.cmd -o test -Dtest=RateLimitTest` — expected PASS, 7. If `refusesTheRequestAfterTheBurstWith429` or `usersOfOneTenantShareABucket` is flaky because the four requests took longer than a second, report the observed timing — do not loosen the assertion.

- [ ] **Step 6: The two fail-open tests against a real, broken Redis**

`src/test/java/com/gatekeeper/ratelimit/DeadRedisFailOpenTest.java`:

```java
package com.gatekeeper.ratelimit;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.gatekeeper.support.TestKey;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.io.IOException;
import java.net.ServerSocket;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;

/**
 * Nothing listens on the Redis port. A JWT caller — whose authentication needs no Redis — is
 * still served, unlimited and without rate-limit headers. The M5 design, section 7.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class DeadRedisFailOpenTest {

    static final String ISSUER = "http://localhost:8080";
    static WireMockServer downstream;
    static TestKey signingKey;
    static int deadPort;

    @Autowired
    WebTestClient client;

    @BeforeAll
    static void start() throws IOException {
        signingKey = TestKey.generate("k1");
        downstream = new WireMockServer(options().dynamicPort());
        downstream.start();
        downstream.stubFor(get(urlEqualTo("/oauth2/jwks")).willReturn(okJson(TestKey.jwksDocument(signingKey))));
        downstream.stubFor(any(anyUrl()).atPriority(20).willReturn(okJson("{}")));
        try (ServerSocket probe = new ServerSocket(0)) {
            deadPort = probe.getLocalPort();
        }
    }

    @AfterAll
    static void stop() {
        downstream.stop();
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("gatekeeper.auth.jwk-set-uri", () -> downstream.baseUrl() + "/oauth2/jwks");
        registry.add("gatekeeper.auth.issuer", () -> ISSUER);
        registry.add("gatekeeper.downstream.ledger", () -> downstream.baseUrl());
        registry.add("gatekeeper.downstream.authcore", () -> downstream.baseUrl());
        registry.add("spring.data.redis.port", () -> deadPort);
    }

    @Test
    void servesTheRequestUnlimited() {
        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + signingKey.mint(ISSUER, "ezzat",
                        Instant.now().plus(5, ChronoUnit.MINUTES),
                        Map.of("tenant", "acme", "scope", List.of("payments:read"))))
                .exchange()
                .expectStatus().isOk()
                .expectHeader().doesNotExist("X-RateLimit-Remaining")
                .expectHeader().doesNotExist("X-Quota-Remaining");
    }
}
```

`src/test/java/com/gatekeeper/ratelimit/SilentRedisFailOpenTest.java` — identical imports and structure to `DeadRedisFailOpenTest`, with these differences:

- a static `ServerSocket silent` opened in `start()` with `new ServerSocket(0)`, and a daemon thread that accepts connections forever and holds them open without ever writing:

```java
        silent = new ServerSocket(0);
        Thread acceptor = new Thread(() -> {
            List<java.net.Socket> held = new java.util.ArrayList<>();
            while (!silent.isClosed()) {
                try {
                    held.add(silent.accept());
                } catch (IOException closed) {
                    return;
                }
            }
        });
        acceptor.setDaemon(true);
        acceptor.start();
```

- `stop()` also calls `silent.close()`;
- `spring.data.redis.port` is `silent.getLocalPort()`;
- the class Javadoc reads: "A Redis that accepts the connection and never answers — the failure a missing timeout turns into a hang. The request must be served within about the configured timeout, not wait on Lettuce's own. The M5 design, section 7.";
- the test is:

```java
    @Test
    void servesTheRequestUnlimitedWithinTheTimeout() {
        long started = System.nanoTime();

        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + signingKey.mint(ISSUER, "ezzat",
                        Instant.now().plus(5, ChronoUnit.MINUTES),
                        Map.of("tenant", "acme", "scope", List.of("payments:read"))))
                .exchange()
                .expectStatus().isOk()
                .expectHeader().doesNotExist("X-RateLimit-Remaining");

        org.assertj.core.api.Assertions.assertThat(java.time.Duration.ofNanos(System.nanoTime() - started))
                .isLessThan(java.time.Duration.ofSeconds(3));
    }
```

Write the file out in full — do not leave it as a diff against the other class.

- [ ] **Step 7: Run everything**

`.\mvnw.cmd -o test -Dtest="RateLimitFilterTest,RateLimitTest,DeadRedisFailOpenTest,SilentRedisFailOpenTest"` — expected PASS, 15 (6 + 7 + 1 + 1).

`.\mvnw.cmd -o test` — expected PASS, 200 (185 + 15). Every existing suite must still pass unchanged: they run with the unlimited test plans. **Any existing test that fails is a finding** — do not edit it.

- [ ] **Step 8: Make it fail on purpose**

1. In `RateLimitFilter.filter`, replace the `map(RateLimitIdentity::of)…flatMap(...)` pipeline with `.flatMap(a -> Mono.justOrEmpty(RateLimitIdentity.of(a))).flatMap(caller -> limit(exchange, chain, caller)).switchIfEmpty(Mono.defer(() -> chain.filter(exchange)))`. Expected: `forwardsAnAllowedRequestOnceWithTheHeaders` fails with 2 chain calls. Revert.
2. Remove `.onErrorResume(...)`. Expected: `letsARequestThroughUnlimitedWhenTheStoreFails` and `DeadRedisFailOpenTest` fail. Revert.
3. Remove `.timeout(timeout)`. Expected: `letsARequestThroughUnlimitedWhenTheStoreNeverAnswers` fails (blocks for the 5 s cap) and `SilentRedisFailOpenTest` fails or exceeds 3 s. Revert.

- [ ] **Step 9: Commit**

```
feat(M5): limit every routed request to its caller's plan

A global filter after authorization resolves the caller and its plan,
runs the script, and either forwards with the rate-limit and quota
headers or answers 429 with Retry-After without reaching a downstream.
A Redis error, timeout or empty answer forwards the request unlimited
and without headers: a capacity control must not turn a Redis outage
into a gateway outage, and must not hang on a silent Redis either.
```

```bash
git add src/main/java/com/gatekeeper/ratelimit src/test/java/com/gatekeeper/ratelimit
git commit -F <message-file>
```

- [ ] **Step 10: Review, then merge** — as Task 1 Step 13, branch `feature/m5-task-5`.

---

## Task 6: Two gateways, one Redis

**Files:**
- Test: `src/test/java/com/gatekeeper/ratelimit/TwoGatewaysShareOneLimitTest.java`

- [ ] **Step 1: Branch** — `git checkout master; git checkout -b feature/m5-task-6`

- [ ] **Step 2: Write the test**

`src/test/java/com/gatekeeper/ratelimit/TwoGatewaysShareOneLimitTest.java`:

```java
package com.gatekeeper.ratelimit;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.gatekeeper.GateKeeperApplication;
import com.gatekeeper.support.TestKey;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * The proof that the limit is distributed: two gateway instances, as separate application
 * contexts on their own ports, sharing one Redis and one downstream. Requests alternate between
 * them and the combined count trips the limit on whichever instance receives the next one. The
 * M5 design, section 11.
 *
 * <p>The quota test needs no timing and is the unconditional proof. The burst test relies on
 * four requests landing within the second one token takes to refill.
 */
class TwoGatewaysShareOneLimitTest {

    static final String ISSUER = "http://localhost:8080";
    static final String QUOTA_TENANT = "q-" + UUID.randomUUID();

    static WireMockServer downstream;
    static TestKey signingKey;
    static ConfigurableApplicationContext first;
    static ConfigurableApplicationContext second;
    static WebTestClient toFirst;
    static WebTestClient toSecond;

    @BeforeAll
    static void start() {
        signingKey = TestKey.generate("k1");
        downstream = new WireMockServer(options().dynamicPort());
        downstream.start();
        downstream.stubFor(get(urlEqualTo("/oauth2/jwks")).willReturn(okJson(TestKey.jwksDocument(signingKey))));
        downstream.stubFor(any(anyUrl()).atPriority(20).willReturn(okJson("{}")));

        first = gateway();
        second = gateway();
        toFirst = clientFor(first);
        toSecond = clientFor(second);
    }

    @AfterAll
    static void stop() {
        if (first != null) {
            first.close();
        }
        if (second != null) {
            second.close();
        }
        downstream.stop();
    }

    @Test
    void theTwoInstancesAreDistinct() {
        assertThat(port(first)).isNotEqualTo(port(second));
    }

    @Test
    void shareOneDailyQuota() {
        String token = userToken(QUOTA_TENANT);
        toFirst.get().uri("/api/ledger/entries").header(HttpHeaders.AUTHORIZATION, token).exchange().expectStatus().isOk();
        toSecond.get().uri("/api/ledger/entries").header(HttpHeaders.AUTHORIZATION, token).exchange().expectStatus().isOk();
        toFirst.get().uri("/api/ledger/entries").header(HttpHeaders.AUTHORIZATION, token).exchange().expectStatus().isOk();

        toSecond.get().uri("/api/ledger/entries").header(HttpHeaders.AUTHORIZATION, token).exchange()
                .expectStatus().isEqualTo(429)
                .expectBody().jsonPath("$.detail").isEqualTo(RateLimitReason.QUOTA_EXCEEDED.detail());
    }

    @Test
    void shareOneBurst() {
        String token = userToken("t-" + UUID.randomUUID());
        toFirst.get().uri("/api/ledger/entries").header(HttpHeaders.AUTHORIZATION, token).exchange().expectStatus().isOk();
        toSecond.get().uri("/api/ledger/entries").header(HttpHeaders.AUTHORIZATION, token).exchange().expectStatus().isOk();
        toFirst.get().uri("/api/ledger/entries").header(HttpHeaders.AUTHORIZATION, token).exchange().expectStatus().isOk();

        toSecond.get().uri("/api/ledger/entries").header(HttpHeaders.AUTHORIZATION, token).exchange()
                .expectStatus().isEqualTo(429)
                .expectBody().jsonPath("$.detail").isEqualTo(RateLimitReason.RATE_LIMITED.detail());
    }

    /**
     * Command-line arguments, not {@code SpringApplicationBuilder.properties(...)}: those set
     * default properties, the lowest-priority source, so {@code application.yml} would win —
     * {@code server.port: 8081} would put both instances on one port, and {@code default-plan:
     * free} would give every fresh tenant the test override's unlimited plan. Arguments outrank
     * every configuration file.
     */
    private static ConfigurableApplicationContext gateway() {
        return new SpringApplicationBuilder(GateKeeperApplication.class).run(
                "--server.port=0",
                "--gatekeeper.auth.jwk-set-uri=" + downstream.baseUrl() + "/oauth2/jwks",
                "--gatekeeper.auth.issuer=" + ISSUER,
                "--gatekeeper.downstream.ledger=" + downstream.baseUrl(),
                "--gatekeeper.downstream.authcore=" + downstream.baseUrl(),
                "--gatekeeper.rate-limit.default-plan=burst3",
                "--gatekeeper.rate-limit.plans.burst3.requests-per-second=1",
                "--gatekeeper.rate-limit.plans.burst3.burst=3",
                "--gatekeeper.rate-limit.plans.burst3.daily-quota=1000",
                "--gatekeeper.rate-limit.plans.quota3.requests-per-second=1000",
                "--gatekeeper.rate-limit.plans.quota3.burst=1000",
                "--gatekeeper.rate-limit.plans.quota3.daily-quota=3",
                "--gatekeeper.rate-limit.assignments.tenants." + QUOTA_TENANT + "=quota3");
    }

    private static int port(ConfigurableApplicationContext context) {
        return context.getEnvironment().getRequiredProperty("local.server.port", Integer.class);
    }

    private static WebTestClient clientFor(ConfigurableApplicationContext context) {
        return WebTestClient.bindToServer().baseUrl("http://localhost:" + port(context)).build();
    }

    private static String userToken(String tenant) {
        return "Bearer " + signingKey.mint(ISSUER, "ezzat", Instant.now().plus(5, ChronoUnit.MINUTES),
                Map.of("tenant", tenant, "scope", List.of("payments:read")));
    }
}
```

An earlier draft passed these through `SpringApplicationBuilder.properties(Map)`. Task 1's code review showed, with Boot's own binder, that those are default properties and lose to `application.yml`: the second instance would try port 8081, and `default-plan` would stay `free`. Command-line arguments outrank every file. If `shareOneBurst` never refuses, print the second response's `X-RateLimit-Burst-Capacity`: it must read `3`.

- [ ] **Step 3: Run it to make sure it fails first**

Before any fix, prove the test can fail: temporarily change `RateLimitConfig.rateLimitStore` to return a store backed by a per-instance `ConcurrentHashMap` counting requests per identity key — for example:

```java
        java.util.Map<String, java.util.concurrent.atomic.AtomicLong> counts = new java.util.concurrent.ConcurrentHashMap<>();
        return (identity, plan) -> {
            long used = counts.computeIfAbsent(identity.key(), k -> new java.util.concurrent.atomic.AtomicLong()).incrementAndGet();
            boolean allowed = used <= Math.min(plan.burst(), plan.dailyQuota());
            return reactor.core.publisher.Mono.just(new Decision(allowed,
                    allowed ? null : RateLimitReason.RATE_LIMITED, 0, 0, allowed ? 0 : 1, 1));
        };
```

Run `.\mvnw.cmd -o test -Dtest=TwoGatewaysShareOneLimitTest`. Expected: `shareOneDailyQuota` and `shareOneBurst` **fail** — each instance counts only its own half. Revert with `git checkout -- src/main/java/com/gatekeeper/ratelimit/RateLimitConfig.java`.

- [ ] **Step 4: Run it against the real store** — `.\mvnw.cmd -o test -Dtest=TwoGatewaysShareOneLimitTest` — expected PASS, 3. Full suite — expected 203.

- [ ] **Step 5: Commit**

```
test(M5): prove two gateways share one limit

Two application contexts on their own ports share one Redis and one
downstream. Alternating requests trip the combined burst and the
combined quota on whichever instance receives the next one. A store
counting per instance fails both tests, which is the point of them.
```

```bash
git add src/test/java/com/gatekeeper/ratelimit/TwoGatewaysShareOneLimitTest.java
git commit -F <message-file>
```

- [ ] **Step 6: Review, then merge** — as Task 1 Step 13, branch `feature/m5-task-6`.

---

## Task 7: Prove the tests actually test something

Each mutation is a temporary edit on `master` after Task 6's merge, never committed, reverted with `git checkout -- <file>` before the next. Report, for each, the failing test names.

| # | Edit | Run | Must fail |
|---|---|---|---|
| 1 | In `check.lua`, delete the quota block (the `if count + 1 > quota then … end` and keep the writes) | `RedisRateLimitStoreTest,RateLimitTest` | the quota tests in both |
| 2 | In `check.lua`, move the quota block above the bucket block | `RedisRateLimitStoreTest` | `checksTheBucketBeforeTheQuota` |
| 3 | In `RateLimitConfig`, the per-instance store from Task 6 Step 3 | `TwoGatewaysShareOneLimitTest` | `shareOneDailyQuota`, `shareOneBurst` |
| 4 | In `RateLimitFilter.limit`, remove `.onErrorResume(...)` | `RateLimitFilterTest,DeadRedisFailOpenTest` | the store-fails test and the dead-Redis test |
| 5 | In `RateLimitFilter.apply`, set `Retry-After` to `"5"` | `RateLimitTest,RateLimitFilterTest` | `refusesOnceTheDailyQuotaIsUsedUp`, `refusesTheRequestAfterTheBurstWith429`, `refusesWithoutForwarding` |
| 6 | In `RateLimitIdentity.of`, skip the tenant branch | `RateLimitIdentityTest,RateLimitTest` | `aUserTokenCountsAgainstItsTenant`, `usersOfOneTenantShareABucket` |

Finish with `git status --short` (must be empty) and the full suite (203).

---

## Task 8: Run it against the real thing

- [ ] **Step 1: Start everything.** From the authcore directory, `docker compose up -d postgres redis`. Start AuthCore and ledger-service with `.\mvnw.cmd -o spring-boot:run`. Start **two** GateKeepers with a tiny plan for the demo key (the machine client stays on `pro`, from `application.yml`):

```bash
.\mvnw.cmd -o spring-boot:run "-Dspring-boot.run.arguments=--server.port=8081 --gatekeeper.rate-limit.plans.tiny.requests-per-second=1 --gatekeeper.rate-limit.plans.tiny.burst=3 --gatekeeper.rate-limit.plans.tiny.daily-quota=6 --gatekeeper.rate-limit.assignments.api-keys.demo-reporting-job=tiny"
```

and the same with `--server.port=8083`.

- [ ] **Step 2: One burst across two instances.** Send the demo key (`X-API-Key: ak_demo_reporting_job_local_only_0000000000`) to `GET /api/machine/payments`, alternating `:8081` and `:8083`, four times back to back. Expected: three `200`s, then `429` with `Retry-After: 1`, the `RATE_LIMITED` detail, `X-RateLimit-Remaining: 0`.

- [ ] **Step 3: One quota across two instances.** Wait two seconds between requests so the bucket never empties, and keep alternating until the quota of 6 is spent. Expected: six `200`s in total across both instances — counting the three from Step 2 — then `429` with the `QUOTA_EXCEEDED` detail and `Retry-After` equal to the seconds until UTC midnight.

- [ ] **Step 4: Plans differ.** A machine token (client credentials, `payments:read`, from `curl.exe -s -u authcore-machine:machine-secret -d "grant_type=client_credentials&scope=payments:read" http://localhost:8080/oauth2/token`) on `GET /api/machine/payments` shows `X-RateLimit-Burst-Capacity: 100` (pro); the demo key shows `3` (tiny). No browser login is needed for M5's run.

- [ ] **Step 5: Fail open.** `docker compose stop redis`. A machine token on `:8081` still gets `200`, promptly, with no `X-RateLimit-*` headers; the gateway log shows the WARN. (The API key now fails, because its introspection cache needs Redis — M3's path, unchanged by M5; record what status it gives.) `docker compose start redis`; within a few seconds limits apply again.

- [ ] **Step 6: Record** anything that differed from this plan or the design, in the design doc or the handoff.

Stop the services afterwards.

---

## Task 9: Documentation

- [ ] **Step 1: Branch** — `git checkout master; git checkout -b feature/m5-task-9`

- [ ] **Step 2: README.** Add a **Rate limiting** section: the plans and where they are configured; the identity table and the `aud` rationale (read, not validated, and why); that the limiter runs after authorization; the two-hash Redis design on Redis's clock; the `429` example with every header and the two details; allowed responses' headers; failing open and why, and that M6 will fail closed; the two-gateway test and the live run's result. Update the audience paragraph and the Known limitations entry on audience: `aud` is now read as the client's identity for rate limiting; still not validated; add per-IP flood protection to Known limitations. Roadmap: M5 done. Testing section: the new classes and the new total.

- [ ] **Step 3: Handoff** (`docs/superpowers/HANDOFF-M3-M6.md`): §1 — M0–M5 complete, the new head and test count, "GateKeeper today" gains rate limiting, "Next: M6" — including that M6's revocation check must fail **closed** on the same Redis M5 fails open on, and why. §4 — M5 marked built. §5 — anything Tasks 7–8 found and left open.

- [ ] **Step 4: Commit** with a message summarising what the documents now say, then review and merge as Task 1 Step 13, branch `feature/m5-task-9`.

- [ ] **Step 5: Push only when the user says so.** Before pushing: `git log --format=%B origin/master..master | grep -ci "co-authored\|claude"` must print `0`.

---

## Definition of done

The M5 design, section 14:

- [ ] A caller over its plan's rate is refused `429` with a computed `Retry-After`, in the platform shape, and the downstream never sees the request — `RateLimitTest`, Task 8 Step 2.
- [ ] A caller over its daily quota is refused `429` until UTC midnight — `RedisRateLimitStoreTest`, `RateLimitTest`, Task 8 Step 3.
- [ ] `free` and `pro` differ; a tenant's users share one allowance — `RateLimitTest`, Task 8 Step 4.
- [ ] Two instances sharing one Redis enforce one limit — `TwoGatewaysShareOneLimitTest`, Task 8 Steps 2–3.
- [ ] With Redis dead or silent, requests succeed without headers, within the timeout — fail-open tests, Task 8 Step 5.
- [ ] Allowed responses carry the headers; `401`, `403` and health do not — `RateLimitTest`.
- [ ] Every mutation in Task 7 fails its test; Task 8 behaved as described.
- [ ] Green; each task on its own `feature/m5-task-N` branch, reviewed and merged.
