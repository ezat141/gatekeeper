# GateKeeper M3 — API-Key Authentication Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make GateKeeper accept an `X-API-Key` alongside a bearer JWT, so either mechanism authenticates a caller at the edge.

**Architecture:** AuthCore gains one authenticated introspection endpoint on the `/api/**` chain that already validates API keys. GateKeeper presents its own scoped API key to that endpoint, caches the answer in Redis under the SHA-256 of the caller's key, and turns scopes into `SCOPE_*` authorities so M4's rules never branch on mechanism. The caller's key is forwarded unchanged.

**Tech Stack:** Spring Boot 4.0.7, Spring Cloud 2025.1.2, Spring Security 7.0.6, WebFlux, reactive Redis (`spring-data-redis` 4.1.0), WireMock 3.13.2, JUnit 5.

Design: [`docs/superpowers/specs/2026-08-24-gatekeeper-m3-design.md`](../specs/2026-08-24-gatekeeper-m3-design.md). Where this plan and the spec disagree, the spec wins — say so rather than silently following one.

---

## Environment rules — read before the first command

These cost real time in M0–M2. They are not optional.

- **`.\mvnw.cmd`, never `mvn`.** System Maven is 3.2.5. Prefer `-o` (offline) — **except** the first build after Task 6, which adds a starter absent from `~/.m2` and therefore needs network.
- **`curl.exe`, never `curl`** in PowerShell; `curl` is an alias for `Invoke-WebRequest`.
- **`&&` does not work in Windows PowerShell 5.1.** Use `;` or `if ($?) { ... }`.
- **`git commit -m` breaks on quotes.** Write a message file, use `git commit -F`.
- **Never write a commit message with `Set-Content -Encoding utf8`** — it emits a BOM that lands in the commit subject. Use `[System.IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding($false)))`, or write the file with a file-writing tool.
- **Never add a `Co-Authored-By` line.**
- **Docker Desktop must be running** for AuthCore: `docker compose up -d postgres redis` from the authcore directory. GateKeeper now needs that Redis too.
- **Verify names against the jar before writing them.** `jar tf <jar> | grep ClassName`, `javap -cp <jar> <FQCN>`. Nearly every M0–M2 defect was a confidently-remembered name that had changed.
- **Jackson 3, not Jackson 2 — this catches everyone.** Boot 4 ships the Jackson 3 rebrand. Verified against GateKeeper's actual resolved classpath (`mvnw.cmd dependency:list`):

  | Artifact | Package | Note |
  |---|---|---|
  | `tools.jackson.core:jackson-databind:3.1.4` | `tools.jackson.databind` | **not** `com.fasterxml.jackson.databind` |
  | `com.fasterxml.jackson.core:jackson-annotations:2.21` | `com.fasterxml.jackson.annotation` | annotations kept the old coordinates *and* package |
  | — | — | **no `jackson-datatype-jsr310`.** `java.time` support is folded into databind at `tools/jackson/databind/ext/javatime/`. `JavaTimeModule` does not exist; do not import or register it. |

  So `ObjectMapper` is `tools.jackson.databind.ObjectMapper`, while `@JsonInclude`, `@JsonCreator` and `@JsonProperty` stay on `com.fasterxml.jackson.annotation`. Mixing the two packages in one file is correct here and is not a mistake to "fix". Jackson 3 also made `writeValueAsString` / `readValue` throw the unchecked `JacksonException` rather than a checked `JsonProcessingException`; `Mono.fromCallable` handles either, so the code below is unaffected.

  **AuthCore is on Boot 4.1.0 and GateKeeper on 4.0.7** — different parent versions, same Jackson 3 story.
- Every task gets a `feature/task-N` branch off `master`, merged back with `git merge --no-ff`.

**This plan spans two repositories.** Tasks 1–5 are in `authcore`. Tasks 6–15 are in `gatekeeper`. They are separate branches, separate reviews, separate merges. Finish and merge the AuthCore side first — the GateKeeper integration tests stub it with WireMock, but the manual verification in Task 15 needs it live.

---

## File structure

### AuthCore (`D:\courses\My CV\My cv\ProjectsCVs\authcore`)

| File | Responsibility |
|---|---|
| `src/main/java/com/authcore/apikey/ApiKeyIntrospectionRequest.java` | Create — request body record |
| `src/main/java/com/authcore/apikey/ApiKeyIntrospectionResponse.java` | Create — response body record, nulls omitted |
| `src/main/java/com/authcore/apikey/ApiKeyIntrospectionController.java` | Create — the endpoint |
| `src/main/java/com/authcore/config/AuthorizationServerConfig.java` | Modify — one authorization rule |
| `src/main/java/com/authcore/config/DataSeeder.java` | Modify — seed the gateway's key |
| `src/main/resources/db/migration/V7__create_api_keys.sql` | Modify — comment only, `last_used_at` meaning |
| `src/test/java/com/authcore/ApiKeyIntrospectionControllerTest.java` | Create — endpoint behaviour |
| `src/test/java/com/authcore/ApiKeyIntrospectionAccessTest.java` | Create — the endpoint is not open |

### GateKeeper (`D:\courses\My CV\My cv\ProjectsCVs\gatekeeper`)

| File | Responsibility |
|---|---|
| `pom.xml` | Modify — reactive Redis starters |
| `src/main/resources/application.yml` | Modify — introspection URI, gateway key, TTLs, timeout |
| `src/main/java/com/gatekeeper/apikey/ApiKeyAuthenticationToken.java` | Create — the `Authentication` for a key caller |
| `src/main/java/com/gatekeeper/apikey/ApiKeyAuthenticationConverter.java` | Create — reads `X-API-Key` |
| `src/main/java/com/gatekeeper/apikey/ApiKeyIntrospection.java` | Create — the cached answer |
| `src/main/java/com/gatekeeper/apikey/ApiKeyCache.java` | Create — cache interface |
| `src/main/java/com/gatekeeper/apikey/RedisApiKeyCache.java` | Create — Redis implementation |
| `src/main/java/com/gatekeeper/apikey/IntrospectionClient.java` | Create — outbound call, with timeout |
| `src/main/java/com/gatekeeper/apikey/ApiKeyReactiveAuthenticationManager.java` | Create — cache, introspect, guard, fail closed |
| `src/main/java/com/gatekeeper/apikey/ApiKeyProperties.java` | Create — bound configuration |
| `src/main/java/com/gatekeeper/config/GatewaySecurityConfig.java` | Modify — add the API-key filter |
| `src/main/java/com/gatekeeper/error/GlobalErrorWebExceptionHandler.java` | Modify — `Retry-After` on 503 |
| `src/main/java/com/gatekeeper/identity/IdentityStampFilter.java` | Modify — stamp key callers |
| `src/test/java/com/gatekeeper/apikey/*Test.java` | Create — unit and integration |

**Why `com.gatekeeper.apikey` is its own package:** it mirrors `com.gatekeeper.identity` and AuthCore's own `com.authcore.apikey`, and keeps `config` from accumulating a second responsibility.

---

# Part A — AuthCore

## Task 1: Introspection request and response records

**Files:**
- Create: `src/main/java/com/authcore/apikey/ApiKeyIntrospectionRequest.java`
- Create: `src/main/java/com/authcore/apikey/ApiKeyIntrospectionResponse.java`

- [ ] **Step 1: Create the request record**

```java
package com.authcore.apikey;

/**
 * The key travels in a POST body, never in a path or query string. A credential in a URL
 * lands in access logs, proxy logs and Referer headers.
 */
public record ApiKeyIntrospectionRequest(String key) {
}
```

- [ ] **Step 2: Create the response record**

```java
package com.authcore.apikey;

import com.fasterxml.jackson.annotation.JsonInclude;

import java.time.Instant;
import java.util.Set;

/**
 * Answers "is this key valid, and what does it grant". Never carries the key or its hash —
 * it answers a question, it does not echo the credential.
 *
 * <p>Unknown, disabled and expired keys all produce the same {@code active: false} with no
 * further detail. Distinguishing them would make this endpoint an enumeration oracle: a
 * caller able to tell "no such key" from "that key exists but is disabled" could confirm
 * which keys are real. AuthCore still logs the distinction — see
 * {@link ApiKeyAuthenticationProvider}, which keeps its DisabledException /
 * CredentialsExpiredException split — so operators keep the diagnosis the caller is denied.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ApiKeyIntrospectionResponse(
        boolean active,
        String name,
        Set<String> scopes,
        Instant expiresAt) {

    public static ApiKeyIntrospectionResponse inactive() {
        return new ApiKeyIntrospectionResponse(false, null, null, null);
    }

    public static ApiKeyIntrospectionResponse of(ApiKey apiKey) {
        return new ApiKeyIntrospectionResponse(
                true, apiKey.name(), apiKey.scopes(), apiKey.expiresAt());
    }
}
```

- [ ] **Step 3: Compile**

Run: `.\mvnw.cmd -o -q compile`
Expected: BUILD SUCCESS, no output.

- [ ] **Step 4: Commit**

```bash
git add src/main/java/com/authcore/apikey/ApiKeyIntrospectionRequest.java src/main/java/com/authcore/apikey/ApiKeyIntrospectionResponse.java
git commit -F <message-file>
```

Message subject: `feat(M3): introspection request and response records`

---

## Task 2: The introspection endpoint

**Files:**
- Create: `src/main/java/com/authcore/apikey/ApiKeyIntrospectionController.java`
- Test: `src/test/java/com/authcore/ApiKeyIntrospectionControllerTest.java`

- [ ] **Step 1: Write the failing test**

Read `src/test/java/com/authcore/ApiKeyAuthenticationProviderTest.java` first and copy its fixture style rather than inventing one.

```java
package com.authcore;

import com.authcore.apikey.ApiKeyIntrospectionController;
import com.authcore.apikey.ApiKeyIntrospectionRequest;
import com.authcore.apikey.ApiKeyIntrospectionResponse;
import com.authcore.apikey.ApiKeyStore;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.time.Duration;
import java.time.Instant;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

class ApiKeyIntrospectionControllerTest {

    ApiKeyStore store;
    ApiKeyIntrospectionController controller;

    @BeforeEach
    void setUp() {
        store = mock(ApiKeyStore.class);
        controller = new ApiKeyIntrospectionController(store);
    }

    @Test
    void reportsAUsableKeyAsActiveWithItsScopes() {
        Instant expiry = Instant.now().plus(Duration.ofDays(30));
        when(store.findByRawKey("ak_good")).thenReturn(java.util.Optional.of(
                new com.authcore.apikey.ApiKey("id-1", "reporting", "ak_good", Set.of("payments:read"), true, expiry)));

        ApiKeyIntrospectionResponse response =
                controller.introspect(new ApiKeyIntrospectionRequest("ak_good"));

        assertThat(response.active()).isTrue();
        assertThat(response.name()).isEqualTo("reporting");
        assertThat(response.scopes()).containsExactly("payments:read");
        assertThat(response.expiresAt()).isEqualTo(expiry);
    }

    @Test
    void reportsAnUnknownKeyAsInactiveAndSaysNothingElse() {
        when(store.findByRawKey(anyString())).thenReturn(java.util.Optional.empty());

        ApiKeyIntrospectionResponse response =
                controller.introspect(new ApiKeyIntrospectionRequest("ak_nope"));

        assertThat(response.active()).isFalse();
        assertThat(response.name()).isNull();
        assertThat(response.scopes()).isNull();
    }

    /**
     * A disabled key and an unknown key must be indistinguishable to the caller, or this
     * endpoint becomes a way to confirm which keys exist.
     */
    @Test
    void reportsADisabledKeyIdenticallyToAnUnknownOne() {
        when(store.findByRawKey("ak_disabled")).thenReturn(java.util.Optional.of(
                new com.authcore.apikey.ApiKey("id-2", "old", "ak_disabled", Set.of("payments:read"), false, null)));

        assertThat(controller.introspect(new ApiKeyIntrospectionRequest("ak_disabled")))
                .isEqualTo(ApiKeyIntrospectionResponse.inactive());
    }

    @Test
    void reportsAnExpiredKeyIdenticallyToAnUnknownOne() {
        when(store.findByRawKey("ak_expired")).thenReturn(java.util.Optional.of(
                new com.authcore.apikey.ApiKey("id-3", "lapsed", "ak_expired", Set.of("payments:read"),
                        true, Instant.now().minus(Duration.ofDays(1)))));

        assertThat(controller.introspect(new ApiKeyIntrospectionRequest("ak_expired")))
                .isEqualTo(ApiKeyIntrospectionResponse.inactive());
    }

    @Test
    void doesNotTouchLastUsedForAKeyItRefuses() {
        when(store.findByRawKey(anyString())).thenReturn(java.util.Optional.empty());

        controller.introspect(new ApiKeyIntrospectionRequest("ak_nope"));

        verify(store, never()).touchLastUsed(anyString());
    }

    @Test
    void treatsABlankKeyAsInactiveWithoutQueryingTheStore() {
        assertThat(controller.introspect(new ApiKeyIntrospectionRequest("  ")))
                .isEqualTo(ApiKeyIntrospectionResponse.inactive());
        verify(store, never()).findByRawKey(anyString());
    }
}
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `.\mvnw.cmd -o test -Dtest=ApiKeyIntrospectionControllerTest`
Expected: FAIL — compilation error, `ApiKeyIntrospectionController` does not exist.

- [ ] **Step 3: Write the controller**

```java
package com.authcore.apikey;

import org.springframework.util.StringUtils;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

/**
 * Lets a trusted caller ask whether an API key is valid and what it grants.
 *
 * <p>Exists because the platform's other services cannot answer that question. The
 * {@code api_keys} table is AuthCore's, and a second service reaching into it directly
 * would put two services on one schema — the property this platform exists not to have.
 * AuthCore owns identity, and "is this credential valid" is an identity question.
 *
 * <p>Guarded by {@code SCOPE_apikeys:introspect} in {@code AuthorizationServerConfig}. Left
 * open it would be an oracle for testing stolen keys at line rate.
 */
@RestController
@RequestMapping("/api/internal/api-keys")
public class ApiKeyIntrospectionController {

    private final ApiKeyStore apiKeyStore;

    public ApiKeyIntrospectionController(ApiKeyStore apiKeyStore) {
        this.apiKeyStore = apiKeyStore;
    }

    @PostMapping("/introspect")
    public ApiKeyIntrospectionResponse introspect(@RequestBody ApiKeyIntrospectionRequest request) {
        if (request == null || !StringUtils.hasText(request.key())) {
            return ApiKeyIntrospectionResponse.inactive();
        }

        return apiKeyStore.findByRawKey(request.key())
                .filter(ApiKey::isUsable)
                .map(apiKey -> {
                    // Keeps last_used_at tracking real validation. Note that GateKeeper
                    // caches this answer, so the column means "last validated at the
                    // source, accurate to within the gateway's cache TTL" rather than
                    // "last used" — recorded in V7's comment and in the M3 design.
                    apiKeyStore.touchLastUsed(apiKey.id());
                    return ApiKeyIntrospectionResponse.of(apiKey);
                })
                .orElseGet(ApiKeyIntrospectionResponse::inactive);
    }
}
```

- [ ] **Step 4: Run the test and confirm it passes**

Run: `.\mvnw.cmd -o test -Dtest=ApiKeyIntrospectionControllerTest`
Expected: PASS, 6 tests.

- [ ] **Step 5: Commit**

Message subject: `feat(M3): an endpoint to ask whether an API key is valid`

---

## Task 3: Guard the endpoint with a scope

**Files:**
- Modify: `src/main/java/com/authcore/config/AuthorizationServerConfig.java` (the `authorizeHttpRequests` block in `resourceApiSecurityFilterChain`)
- Test: `src/test/java/com/authcore/ApiKeyIntrospectionAccessTest.java`

> **Depends on Task 4.** The third test below needs the gateway's key seeded. Do Task 4 first, then return here — the two are separated only because they are different concerns, not because this order works.

- [ ] **Step 1: Write the failing test**

Read `src/test/java/com/authcore/MachineAccessIntegrationTest.java` and follow its bootstrapping exactly — it already solves standing up the app with a database.

```java
@Test
void refusesAnUnauthenticatedCaller() throws Exception {
    mockMvc.perform(post("/api/internal/api-keys/introspect")
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("{\"key\":\"ak_anything\"}"))
            .andExpect(status().isUnauthorized());
}

/**
 * The assertion that matters. Without it the rule could be plain authenticated() and this
 * class would still pass — the demo key would sail through and nothing would notice that
 * any API key at all can introspect every other one.
 */
@Test
void refusesAnAuthenticatedCallerLackingTheScope() throws Exception {
    mockMvc.perform(post("/api/internal/api-keys/introspect")
                    .header("X-API-Key", DataSeeder.DEMO_API_KEY)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("{\"key\":\"ak_anything\"}"))
            .andExpect(status().isForbidden());
}

@Test
void allowsTheGatewaysKey() throws Exception {
    mockMvc.perform(post("/api/internal/api-keys/introspect")
                    .header("X-API-Key", DataSeeder.GATEWAY_API_KEY)
                    .contentType(MediaType.APPLICATION_JSON)
                    .content("{\"key\":\"" + DataSeeder.DEMO_API_KEY + "\"}"))
            .andExpect(status().isOk())
            .andExpect(jsonPath("$.active").value(true))
            .andExpect(jsonPath("$.scopes[0]").value("payments:read"));
}
```

`DEMO_API_KEY` and `GATEWAY_API_KEY` are package-private on `DataSeeder`, and this test is in package `com.authcore` — same package, so they are reachable. `AutoConfigureMockMvc` lives in `org.springframework.boot.webmvc.test.autoconfigure` in Boot 4, not the Boot 3 location.

The third test depends on Task 4 having seeded the gateway key, so write Task 4 first if you are working out of order.

- [ ] **Step 2: Run it and confirm it fails**

Run: `.\mvnw.cmd -o test -Dtest=ApiKeyIntrospectionAccessTest`
Expected: FAIL on assertion 2 — the endpoint currently falls into `anyRequest().access(tenantScoped(authenticated()))`, so the demo key gets `200` where `403` is required.

- [ ] **Step 3: Add the rule**

In `resourceApiSecurityFilterChain`, add as the **first** `requestMatchers` entry, above the `/api/machine/**` rules:

```java
.requestMatchers("/api/internal/**")
    .access(tenantScoped(AuthorityAuthorizationManager.hasAuthority("SCOPE_apikeys:introspect")))
```

Leave the existing `/api/machine/**` rules and the `anyRequest()` fallback untouched.

Two things already verified, recorded here so they are not re-derived:

- The chain is `securityMatcher("/api/**")`, so `/api/internal/**` is already inside it. No new chain, no new filter.
- `tenantScoped(...)` is safe for a tenant-less caller: `TenantAuthorizationManager.tenantClaimOf()` returns `null` for anything that is not a `JwtAuthenticationToken`, and the manager then returns the delegate's result unchanged. An API-key caller is not refused there.

- [ ] **Step 4: Run the test and confirm it passes**

Run: `.\mvnw.cmd -o test -Dtest=ApiKeyIntrospectionAccessTest`
Expected: PASS.

- [ ] **Step 4b: Update the controller's javadoc, which now says the opposite of the truth**

Task 2 shipped `ApiKeyIntrospectionController` with a javadoc paragraph stating that **no** scope rule guards it yet and that any authenticated caller can use it as an oracle — accurate when written, false the moment Step 3 lands. Replace that paragraph with:

```java
 * <p>Guarded by {@code SCOPE_apikeys:introspect} in {@code AuthorizationServerConfig}. Left
 * open it would be an oracle for testing stolen keys at line rate — and merely requiring
 * authentication is not enough, since any low-privilege key would then qualify.
```

Do not skip this. A comment that overstates safety is worse than one that overstates risk, and this milestone has already corrected two javadoc claims that drifted from the code.

- [ ] **Step 5: Run the whole AuthCore suite**

Run: `.\mvnw.cmd -o test`
Expected: PASS. Baseline is 65 tests; expect 65 + the new ones. **If any previously-passing test now fails, stop** — the new matcher has captured a path it should not.

- [ ] **Step 6: Commit**

Message subject: `feat(M3): require a scope to introspect an API key`

---

## Task 4: Seed the gateway's own key

**Files:**
- Modify: `src/main/java/com/authcore/config/DataSeeder.java`

- [ ] **Step 1: Add the constants**

Beside the existing `DEMO_API_KEY_NAME` / `DEMO_API_KEY` at the top of the class:

```java
static final String GATEWAY_API_KEY_NAME = "gatekeeper-introspection";
static final String GATEWAY_API_KEY = "ak_gatekeeper_introspection_local_only_00000";
```

- [ ] **Step 2: Add the seeding method**

```java
/**
 * The credential GateKeeper presents when asking about somebody else's key.
 *
 * <p>Scoped to apikeys:introspect and nothing else — never payments:*. A leak of this key
 * yields an introspection oracle rather than data access, which is the difference between
 * an incident and a breach.
 *
 * <p>No expiry, deliberately: an infrastructure credential that silently lapses takes the
 * gateway's API-key authentication down with it. That makes it a long-lived secret with no
 * online rotation path, which is accepted debt recorded in the M3 design — the
 * overlap-window pattern in ClientSecretRotationStore is the thing to copy when M9 brings
 * key management under an API.
 */
private void seedGatewayApiKey() {
    if (apiKeyStore.existsByName(GATEWAY_API_KEY_NAME)) return;

    apiKeyStore.save(GATEWAY_API_KEY_NAME, GATEWAY_API_KEY, Set.of("apikeys:introspect"), null);

    log.warn("Seeded gateway introspection key '{}'. Local development only.", GATEWAY_API_KEY_NAME);
}
```

- [ ] **Step 3: Call it from `run`**

In `run(ApplicationArguments args)`, immediately after the existing `seedApiKey();`:

```java
seedApiKey();
seedGatewayApiKey();
```

- [ ] **Step 4: Document the `last_used_at` consequence — in a NEW migration**

The design (§10) requires this be recorded in AuthCore's schema documentation, not only in the design doc.

**Do not edit `V7__create_api_keys.sql`.** An earlier draft of this plan said to add a comment there and claimed comments were safe because no DDL changed. That is wrong, and it was verified wrong against the live database: Flyway checksums the whole file, and `validate-on-migrate` defaults to `true` with nothing in this project overriding it, so the edit produced

```
FlywayValidateException: Migration checksum mismatch for migration version 7
-> Applied to database : -338152876
-> Resolved locally    : -394142168
```

and the app refused to boot. That would break every environment where V7 has already run, which is the normal case.

Add a forward migration instead. `V12` is the next free version (V1–V11 are taken and applied). Create `src/main/resources/db/migration/V12__comment_api_key_last_used_at.sql`:

```sql
-- Records what last_used_at now means, since M3 changed it.
--
-- It is updated on every validation at the source, including introspection calls from
-- GateKeeper. Because the gateway caches an introspection answer for its configured TTL,
-- a continuously-used key is introspected only once per TTL. Read this as "last validated
-- at the source, accurate to within that TTL", not "last used".
--
-- A separate migration rather than an edit to V7: Flyway checksums the whole file,
-- comments included, so editing an applied migration breaks validation on boot.
COMMENT ON COLUMN api_keys.last_used_at IS
    'Last validated at the source. Gateway caching means this is accurate only to within the gateway''s introspection cache TTL, not per-request.';
```

Verify it applies: boot the app and confirm it starts, then check the comment landed:

```bash
docker exec authcore-postgres-1 psql -U authcore -d authcore -c "SELECT col_description('api_keys'::regclass, (SELECT attnum FROM pg_attribute WHERE attrelid='api_keys'::regclass AND attname='last_used_at'));"
```

- [ ] **Step 5: Verify the seeding runs**

Run: `docker compose up -d postgres redis` then `.\mvnw.cmd -o spring-boot:run`
Expected: the log line `Seeded gateway introspection key 'gatekeeper-introspection'. Local development only.` on first boot, and **not** on the second (the `existsByName` guard).

- [ ] **Step 6: Commit**

Message subject: `feat(M3): seed the gateway's introspection key`

---

## Task 5: Merge the AuthCore side

- [ ] **Step 1: Full suite**

Run: `.\mvnw.cmd -o test`
Expected: all green.

- [ ] **Step 2: Merge each task branch**

```bash
git checkout master
git merge --no-ff feature/task-1
```

Repeat for each branch, then push.

- [ ] **Step 3: Record the new commit hash.** Tasks 12–15 need a running AuthCore built from it.

---

# Part B — GateKeeper

## Task 6: Dependencies and configuration

**Files:**
- Modify: `pom.xml`
- Modify: `src/main/resources/application.yml`
- Create: `src/main/java/com/gatekeeper/apikey/ApiKeyProperties.java`

- [ ] **Step 1: Add the starters**

In `pom.xml`, after the existing `spring-boot-starter-actuator` dependency:

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-redis-reactive</artifactId>
</dependency>
```

And in the test block:

```xml
<dependency>
    <groupId>org.springframework.boot</groupId>
    <artifactId>spring-boot-starter-data-redis-reactive-test</artifactId>
    <scope>test</scope>
</dependency>
```

Both artifact ids are confirmed present in the Boot 4.0.7 BOM. Neither is in the local `~/.m2` at 4.0.7, so **this build needs network — drop `-o` for it only.**

- [ ] **Step 2: Verify the dependency resolved and the class name is right**

Run: `.\mvnw.cmd dependency:resolve`
Then: `jar tf ~/.m2/repository/org/springframework/data/spring-data-redis/<version>/spring-data-redis-<version>.jar | grep ReactiveStringRedisTemplate`
Expected: `org/springframework/data/redis/core/ReactiveStringRedisTemplate.class`

- [ ] **Step 3: Add configuration**

In `application.yml`, under the existing `gatekeeper:` block:

```yaml
gatekeeper:
  api-key:
    # AuthCore's introspection endpoint, and the credential the gateway presents to it.
    # The key is scoped to apikeys:introspect only — see the M3 design, section 5.
    introspection-uri: ${gatekeeper.downstream.authcore}/api/internal/api-keys/introspect
    gateway-key: ak_gatekeeper_introspection_local_only_00000
    # The positive TTL IS the API-key revocation latency. A disabled key keeps working
    # for at most this long.
    cache-ttl: 60s
    # Shorter: caching a rejection absorbs a retry storm from a misconfigured client,
    # while a short window limits how much an enumeration attempt is amplified.
    negative-cache-ttl: 10s
    # The JWKS fetch has no timeout and that is filed as an M7 defect. Do not repeat it:
    # a host that accepts the connection and never answers must fail, not hang.
    timeout: 2s

spring:
  data:
    redis:
      host: localhost
      port: 6379
```

- [ ] **Step 4: Create the properties class**

```java
package com.gatekeeper.apikey;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "gatekeeper.api-key")
public record ApiKeyProperties(
        String introspectionUri,
        String gatewayKey,
        Duration cacheTtl,
        Duration negativeCacheTtl,
        Duration timeout) {
}
```

Register it by adding `@ConfigurationPropertiesScan` to `GateKeeperApplication`, or `@EnableConfigurationProperties(ApiKeyProperties.class)` on the config class that consumes it. Check which the codebase already uses before picking.

- [ ] **Step 5: Confirm the app still boots**

Run: `.\mvnw.cmd -o test -Dtest=GateKeeperApplicationTests`
Expected: PASS. **If it fails on a missing Redis connection, that is the finding** — Boot's reactive Redis autoconfiguration is lazy about connecting, so a context-load failure here means something else is wrong. Read the actual error, do not add Redis to the test context reflexively.

- [ ] **Step 6: Commit**

Message subject: `build(M3): reactive Redis, and the introspection settings`

---

## Task 7: The authentication token and the converter

**Files:**
- Create: `src/main/java/com/gatekeeper/apikey/ApiKeyAuthenticationToken.java`
- Create: `src/main/java/com/gatekeeper/apikey/ApiKeyAuthenticationConverter.java`
- Test: `src/test/java/com/gatekeeper/apikey/ApiKeyAuthenticationConverterTest.java`

- [ ] **Step 1: Write the failing test**

```java
package com.gatekeeper.apikey;

import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import reactor.test.StepVerifier;

class ApiKeyAuthenticationConverterTest {

    final ApiKeyAuthenticationConverter converter = new ApiKeyAuthenticationConverter();

    @Test
    void producesAnUnauthenticatedTokenWhenTheHeaderIsPresent() {
        StepVerifier.create(convert("ak_something"))
                .assertNext(authentication -> {
                    org.assertj.core.api.Assertions.assertThat(authentication.getCredentials())
                            .isEqualTo("ak_something");
                    org.assertj.core.api.Assertions.assertThat(authentication.isAuthenticated())
                            .isFalse();
                })
                .verifyComplete();
    }

    /**
     * Empty, not an error. A request with no key must fall through to the JWT path
     * untouched — this converter is additive, not a replacement.
     */
    @Test
    void producesNothingWhenTheHeaderIsAbsent() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/ledger/entries").build();
        StepVerifier.create(converter.convert(MockServerWebExchange.from(request)))
                .verifyComplete();
    }

    @Test
    void producesNothingWhenTheHeaderIsBlank() {
        StepVerifier.create(convert("   ")).verifyComplete();
    }

    private reactor.core.publisher.Mono<Authentication> convert(String headerValue) {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/ledger/entries")
                .header(ApiKeyAuthenticationConverter.HEADER_NAME, headerValue)
                .build();
        return converter.convert(MockServerWebExchange.from(request));
    }
}
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `.\mvnw.cmd -o test -Dtest=ApiKeyAuthenticationConverterTest`
Expected: FAIL — compilation error, class does not exist.

- [ ] **Step 3: Write the token**

```java
package com.gatekeeper.apikey;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * Two states, as Spring Security expects: unauthenticated (the raw key, straight from the
 * header) and authenticated (the key's name and its scopes as authorities).
 */
public class ApiKeyAuthenticationToken extends AbstractAuthenticationToken {

    private final String rawKey;
    private final String name;

    /** Unauthenticated — what the converter produces. */
    public ApiKeyAuthenticationToken(String rawKey) {
        super(null);
        this.rawKey = rawKey;
        this.name = null;
        setAuthenticated(false);
    }

    /** Authenticated — what the manager produces once introspection says the key is good. */
    public ApiKeyAuthenticationToken(String name, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.rawKey = null;
        this.name = name;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return rawKey;
    }

    @Override
    public Object getPrincipal() {
        return name;
    }

    @Override
    public String getName() {
        return name;
    }
}
```

- [ ] **Step 4: Write the converter**

```java
package com.gatekeeper.apikey;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Turns an {@code X-API-Key} header into an unauthenticated token for the manager to
 * verify. Returns empty when the header is absent or blank, so a bearer-token request
 * passes through to the JWT path exactly as it did before M3.
 */
public class ApiKeyAuthenticationConverter implements ServerAuthenticationConverter {

    public static final String HEADER_NAME = "X-API-Key";

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        String rawKey = exchange.getRequest().getHeaders().getFirst(HEADER_NAME);
        if (!StringUtils.hasText(rawKey)) {
            return Mono.empty();
        }
        return Mono.just(new ApiKeyAuthenticationToken(rawKey));
    }
}
```

- [ ] **Step 5: Run the test and confirm it passes**

Run: `.\mvnw.cmd -o test -Dtest=ApiKeyAuthenticationConverterTest`
Expected: PASS, 3 tests.

- [ ] **Step 6: Commit**

Message subject: `feat(M3): read X-API-Key into an unauthenticated token`

---

## Task 8: The cached answer and the cache interface

**Files:**
- Create: `src/main/java/com/gatekeeper/apikey/ApiKeyIntrospection.java`
- Create: `src/main/java/com/gatekeeper/apikey/ApiKeyCache.java`
- Create: `src/main/java/com/gatekeeper/apikey/RedisApiKeyCache.java`
- Test: `src/test/java/com/gatekeeper/apikey/RedisApiKeyCacheTest.java`

- [ ] **Step 1: Write the record and the interface**

```java
package com.gatekeeper.apikey;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Set;

/** What introspection answered, as cached. Mirrors AuthCore's response body. */
public record ApiKeyIntrospection(
        boolean active, String name, Set<String> scopes, Instant expiresAt) {

    @JsonCreator
    public ApiKeyIntrospection(
            @JsonProperty("active") boolean active,
            @JsonProperty("name") String name,
            @JsonProperty("scopes") Set<String> scopes,
            @JsonProperty("expiresAt") Instant expiresAt) {
        this.active = active;
        this.name = name;
        this.scopes = scopes == null ? Set.of() : Set.copyOf(scopes);
        this.expiresAt = expiresAt;
    }

    public static ApiKeyIntrospection inactive() {
        return new ApiKeyIntrospection(false, null, Set.of(), null);
    }
}
```

```java
package com.gatekeeper.apikey;

import reactor.core.publisher.Mono;

import java.time.Duration;

/**
 * Narrow on purpose: the authentication manager is unit-tested against a fake
 * implementation, and one integration test proves the Redis one is wired correctly.
 */
public interface ApiKeyCache {

    /** Empty when nothing is cached for this hash. */
    Mono<ApiKeyIntrospection> get(String keyHash);

    Mono<Void> put(String keyHash, ApiKeyIntrospection introspection, Duration ttl);
}
```

- [ ] **Step 2: Write the failing Redis test**

The test needs a Redis. Use the one Docker Compose already runs for AuthCore — the same instance, a different key prefix. Guard the test so it is skipped when Redis is absent rather than failing the suite for someone without Docker:

```java
package com.gatekeeper.apikey;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import tools.jackson.databind.ObjectMapper;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.time.Instant;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class RedisApiKeyCacheTest {

    @Autowired
    ReactiveStringRedisTemplate redis;

    @Test
    void storesAndReadsBackAnIntrospection() {
        RedisApiKeyCache cache = new RedisApiKeyCache(redis, objectMapper());
        ApiKeyIntrospection stored = new ApiKeyIntrospection(
                true, "reporting", Set.of("payments:read"), Instant.now().plusSeconds(3600));

        StepVerifier.create(cache.put("hash-1", stored, Duration.ofSeconds(60)).then(cache.get("hash-1")))
                .assertNext(read -> {
                    assertThat(read.active()).isTrue();
                    assertThat(read.name()).isEqualTo("reporting");
                    assertThat(read.scopes()).containsExactly("payments:read");
                })
                .verifyComplete();
    }

    @Test
    void returnsEmptyForAHashItHasNeverSeen() {
        RedisApiKeyCache cache = new RedisApiKeyCache(redis, objectMapper());
        StepVerifier.create(cache.get("hash-never-written")).verifyComplete();
    }

    /**
     * The stored key must be the hash, never the credential. A Redis dump or a KEYS scan
     * must not yield anything usable.
     */
    @Test
    void namesTheRedisKeyByHashAndNotByCredential() {
        RedisApiKeyCache cache = new RedisApiKeyCache(redis, objectMapper());
        cache.put("hash-2", ApiKeyIntrospection.inactive(), Duration.ofSeconds(30)).block();

        StepVerifier.create(redis.hasKey("gatekeeper:apikey:hash-2"))
                .expectNext(true)
                .verifyComplete();
    }

    /** No JavaTimeModule — Jackson 3 folds java.time into databind. See the environment rules. */
    private static ObjectMapper objectMapper() {
        return new ObjectMapper();
    }
}
```

- [ ] **Step 3: Run it and confirm it fails**

Run: `.\mvnw.cmd -o test -Dtest=RedisApiKeyCacheTest`
Expected: FAIL — `RedisApiKeyCache` does not exist.

- [ ] **Step 4: Write the implementation**

```java
package com.gatekeeper.apikey;

import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import reactor.core.publisher.Mono;
import tools.jackson.databind.ObjectMapper;

import java.time.Duration;

/**
 * Caches introspection answers under the SHA-256 of the key, never the key itself. The
 * database stores a hash for the same reason: a dump of this store must not hand anybody a
 * working credential.
 */
public class RedisApiKeyCache implements ApiKeyCache {

    private static final String KEY_PREFIX = "gatekeeper:apikey:";

    private final ReactiveStringRedisTemplate redis;
    private final ObjectMapper objectMapper;

    public RedisApiKeyCache(ReactiveStringRedisTemplate redis, ObjectMapper objectMapper) {
        this.redis = redis;
        this.objectMapper = objectMapper;
    }

    @Override
    public Mono<ApiKeyIntrospection> get(String keyHash) {
        return redis.opsForValue().get(KEY_PREFIX + keyHash)
                .flatMap(this::deserialize);
    }

    @Override
    public Mono<Void> put(String keyHash, ApiKeyIntrospection introspection, Duration ttl) {
        return Mono.fromCallable(() -> objectMapper.writeValueAsString(introspection))
                .flatMap(json -> redis.opsForValue().set(KEY_PREFIX + keyHash, json, ttl))
                .then();
    }

    /**
     * A cached entry this process cannot read is treated as a miss, not as a failure. The
     * shape could change across a rolling deploy, and a stale entry must not turn into a
     * 503 for a caller holding a perfectly good key.
     */
    private Mono<ApiKeyIntrospection> deserialize(String json) {
        return Mono.fromCallable(() -> objectMapper.readValue(json, ApiKeyIntrospection.class))
                .onErrorResume(error -> Mono.empty());
    }
}
```

- [ ] **Step 5: Run and confirm it passes**

Run: `.\mvnw.cmd -o test -Dtest=RedisApiKeyCacheTest`
Expected: PASS, 3 tests. Requires Redis: `docker compose up -d redis` from the authcore directory.

- [ ] **Step 6: Commit**

Message subject: `feat(M3): cache introspection answers under the key's hash`

---

## Task 9: The introspection client

**Files:**
- Create: `src/main/java/com/gatekeeper/apikey/IntrospectionClient.java`
- Test: `src/test/java/com/gatekeeper/apikey/IntrospectionClientTest.java`

- [ ] **Step 1: Write the failing test**

Cover four cases with WireMock: an active answer, an inactive answer, a 500 from AuthCore, and a response slower than the timeout. The last two must both surface as the same failure type — the caller cannot distinguish them and should not.

```java
package com.gatekeeper.apikey;

import com.github.tomakehurst.wiremock.WireMockServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.test.StepVerifier;

import java.time.Duration;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

class IntrospectionClientTest {

    static final String PATH = "/api/internal/api-keys/introspect";
    static WireMockServer authCore;

    @BeforeAll
    static void start() {
        authCore = new WireMockServer(options().dynamicPort());
        authCore.start();
    }

    @AfterAll
    static void stop() {
        authCore.stop();
    }

    @Test
    void returnsTheActiveAnswer() {
        authCore.resetAll();
        authCore.stubFor(post(urlEqualTo(PATH)).willReturn(okJson("""
                {"active":true,"name":"reporting","scopes":["payments:read"]}""")));

        StepVerifier.create(client(Duration.ofSeconds(2)).introspect("ak_good"))
                .assertNext(result -> {
                    assertThat(result.active()).isTrue();
                    assertThat(result.scopes()).containsExactly("payments:read");
                })
                .verifyComplete();
    }

    /** The gateway must identify itself, or AuthCore will refuse the call. */
    @Test
    void presentsTheGatewaysOwnKey() {
        authCore.resetAll();
        authCore.stubFor(post(urlEqualTo(PATH)).willReturn(okJson("""
                {"active":false}""")));

        client(Duration.ofSeconds(2)).introspect("ak_whatever").block();

        authCore.verify(postRequestedFor(urlEqualTo(PATH))
                .withHeader("X-API-Key", equalTo("ak_gateway_test_key")));
    }

    /**
     * A redirect is not an error to retrieve(), and carries no body. Without explicit
     * status handling this completes EMPTY instead of failing, which downstream becomes a
     * silent fallthrough to the JWT path rather than a refusal. Measured against the real
     * AuthCore before it grew a 400 handler: a malformed body produced a 302 to /login for
     * a client accepting text/html, and a 401 for a JSON client.
     */
    @Test
    void failsOnARedirectRatherThanCompletingEmpty() {
        authCore.resetAll();
        authCore.stubFor(post(urlEqualTo(PATH)).willReturn(
                aResponse().withStatus(302).withHeader("Location", "/login")));

        StepVerifier.create(client(Duration.ofSeconds(2)).introspect("ak_good"))
                .expectError(IntrospectionUnavailableException.class)
                .verify();
    }

    /** A 200 with no body must fail, not complete empty, for the same reason. */
    @Test
    void failsOnAnEmptyBodyRatherThanCompletingEmpty() {
        authCore.resetAll();
        authCore.stubFor(post(urlEqualTo(PATH)).willReturn(aResponse().withStatus(200)));

        StepVerifier.create(client(Duration.ofSeconds(2)).introspect("ak_good"))
                .expectError(IntrospectionUnavailableException.class)
                .verify();
    }

    @Test
    void failsWhenAuthCoreErrors() {
        authCore.resetAll();
        authCore.stubFor(post(urlEqualTo(PATH)).willReturn(aResponse().withStatus(500)));

        StepVerifier.create(client(Duration.ofSeconds(2)).introspect("ak_good"))
                .expectError(IntrospectionUnavailableException.class)
                .verify();
    }

    /**
     * The failure this test exists for. A host that accepts the connection and never
     * answers must fail, not hang — the JWKS fetch has exactly this gap and it is filed
     * as an M7 defect.
     */
    @Test
    void failsWhenAuthCoreIsTooSlowRatherThanHanging() {
        authCore.resetAll();
        authCore.stubFor(post(urlEqualTo(PATH))
                .willReturn(okJson("{\"active\":true}").withFixedDelay(1500)));

        StepVerifier.create(client(Duration.ofMillis(200)).introspect("ak_good"))
                .expectError(IntrospectionUnavailableException.class)
                .verify(Duration.ofSeconds(5));
    }

    private static IntrospectionClient client(Duration timeout) {
        ApiKeyProperties properties = new ApiKeyProperties(
                authCore.baseUrl() + PATH, "ak_gateway_test_key",
                Duration.ofSeconds(60), Duration.ofSeconds(10), timeout);
        return new IntrospectionClient(WebClient.builder().build(), properties);
    }
}
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `.\mvnw.cmd -o test -Dtest=IntrospectionClientTest`
Expected: FAIL — `IntrospectionClient` and `IntrospectionUnavailableException` do not exist.

- [ ] **Step 3: Write the exception**

```java
package com.gatekeeper.apikey;

/**
 * Introspection could not be completed — AuthCore unreachable, erroring, too slow, or
 * answering with something unusable.
 *
 * <p>Deliberately not an {@code AuthenticationException}. That distinction is what produces
 * a 503 instead of a 401: {@code AuthenticationWebFilter} catches only
 * {@code AuthenticationException} and converts it into the entry point's 401, so anything
 * else propagates to {@code GlobalErrorWebExceptionHandler} instead. The caller's key may
 * be perfectly valid; answering 401 would send them to rotate a working credential.
 */
public class IntrospectionUnavailableException extends RuntimeException {

    public IntrospectionUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
```

- [ ] **Step 4: Write the client**

```java
package com.gatekeeper.apikey;

import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Asks AuthCore about a key, presenting the gateway's own key as identification.
 *
 * <p>Carries an explicit response timeout. Spring Security's ReactiveRemoteJWKSource does
 * not, which is why an unreachable-but-listening JWKS host hangs the request instead of
 * failing closed; that is recorded as an M7 defect. Building a second outbound call with
 * the same gap would be repeating a known bug deliberately.
 */
public class IntrospectionClient {

    private final WebClient webClient;
    private final ApiKeyProperties properties;

    public IntrospectionClient(WebClient webClient, ApiKeyProperties properties) {
        this.webClient = webClient;
        this.properties = properties;
    }

    public Mono<ApiKeyIntrospection> introspect(String rawKey) {
        return webClient.post()
                .uri(properties.introspectionUri())
                .header(ApiKeyAuthenticationConverter.HEADER_NAME, properties.gatewayKey())
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("key", rawKey))
                .retrieve()
                // retrieve() errors on 4xx and 5xx but NOT on 3xx, and a redirect carries no
                // body — so without this, bodyToMono would complete EMPTY rather than fail.
                // Not hypothetical: before AuthCore grew its own 400 handler, a malformed
                // body there fell through to a second security chain and the response
                // depended on content negotiation — 401 for a JSON client, 302 to /login for
                // one accepting text/html. Measured, not assumed. An empty completion here
                // propagates through the manager and reaches AuthenticationWebFilter as "no
                // authentication", which CONTINUES the filter chain — turning a failed
                // introspection into the exact JWT fallthrough the precedence table forbids.
                // The guard matters for any non-2xx, so which one AuthCore picks is moot.
                .onStatus(status -> !status.is2xxSuccessful(),
                        response -> Mono.error(new IntrospectionUnavailableException(
                                "Introspection answered " + response.statusCode(), null)))
                .bodyToMono(ApiKeyIntrospection.class)
                // A 200 with an empty or unparseable body would complete empty too.
                .switchIfEmpty(Mono.error(new IntrospectionUnavailableException(
                        "Introspection returned no body", null)))
                .timeout(properties.timeout())
                .onErrorMap(error -> !(error instanceof IntrospectionUnavailableException),
                        error -> new IntrospectionUnavailableException(
                                "API key introspection failed", error));
    }
}
```

The `WebClient` comes from a bean; wire it in Task 11. This class needs no `ObjectMapper` — `bodyToMono(ApiKeyIntrospection.class)` uses WebClient's own configured codecs, and `Instant` decodes without extra registration because Jackson 3 folds `java.time` into databind.

- [ ] **Step 5: Run and confirm it passes**

Run: `.\mvnw.cmd -o test -Dtest=IntrospectionClientTest`
Expected: PASS, 4 tests.

- [ ] **Step 6: Commit**

Message subject: `feat(M3): ask AuthCore about a key, with a timeout`

---

## Task 10: The authentication manager

**Files:**
- Create: `src/main/java/com/gatekeeper/apikey/ApiKeyReactiveAuthenticationManager.java`
- Test: `src/test/java/com/gatekeeper/apikey/ApiKeyReactiveAuthenticationManagerTest.java`

This is where the three security properties live: fail closed, clamp the TTL, and refuse the gateway's own key.

- [ ] **Step 1: Write the failing test**

Write a fake cache (a `ConcurrentHashMap`, recording the TTL it was asked for) rather than mocking — the TTL assertions read far better against a fake.

Cases that must be covered:

| Test | Assertion |
|---|---|
| active key | authenticated, authority `SCOPE_payments:read`, name set |
| inactive key | errors with `BadCredentialsException` |
| introspection unavailable | errors with `IntrospectionUnavailableException`, **not** an `AuthenticationException` |
| cache hit | introspection client is never called |
| cache miss | client called once, answer written to cache |
| TTL clamp | a key expiring in 5s is cached with a TTL of 5s, not the configured 60s |
| negative TTL | an inactive answer is cached with the negative TTL |
| **gateway key replay** | a key whose scopes contain `apikeys:introspect` is refused with `BadCredentialsException` |

The last row is the privilege-separation guard from the design. Write it so it fails against a manager without the check.

```java
@Test
void refusesACallerPresentingTheGatewaysOwnIntrospectionKey() {
    client.answer = new ApiKeyIntrospection(
            true, "gatekeeper-introspection", Set.of("apikeys:introspect"), null);

    StepVerifier.create(manager.authenticate(new ApiKeyAuthenticationToken("ak_gateway")))
            .expectError(BadCredentialsException.class)
            .verify();
}
```

```java
@Test
void neverCachesPastTheKeysOwnExpiry() {
    Instant soon = Instant.now().plusSeconds(5);
    client.answer = new ApiKeyIntrospection(true, "briefly", Set.of("payments:read"), soon);

    manager.authenticate(new ApiKeyAuthenticationToken("ak_brief")).block();

    assertThat(cache.lastTtl).isLessThanOrEqualTo(Duration.ofSeconds(5));
}
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `.\mvnw.cmd -o test -Dtest=ApiKeyReactiveAuthenticationManagerTest`
Expected: FAIL — the manager does not exist.

- [ ] **Step 3: Write the manager**

```java
package com.gatekeeper.apikey;

import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.authentication.ReactiveAuthenticationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import reactor.core.publisher.Mono;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Set;
import java.util.stream.Collectors;

/**
 * Validates an API key against a short-TTL cache in front of AuthCore's introspection
 * endpoint, and turns its scopes into authorities.
 *
 * <p>Scopes become {@code SCOPE_*}, the shape Spring derives from a JWT's {@code scope}
 * claim. That is the whole composability property: M4 writes one
 * {@code hasAuthority("SCOPE_payments:read")} rule that accepts either credential without
 * branching on how the caller authenticated. AuthCore made the same choice internally.
 */
public class ApiKeyReactiveAuthenticationManager implements ReactiveAuthenticationManager {

    /** A caller holding this scope would be the gateway itself. See refuseSelfIntrospection. */
    static final String INTROSPECTION_SCOPE = "apikeys:introspect";

    private final ApiKeyCache cache;
    private final IntrospectionClient client;
    private final ApiKeyProperties properties;

    public ApiKeyReactiveAuthenticationManager(
            ApiKeyCache cache, IntrospectionClient client, ApiKeyProperties properties) {
        this.cache = cache;
        this.client = client;
        this.properties = properties;
    }

    @Override
    public Mono<Authentication> authenticate(Authentication authentication) {
        String rawKey = (String) authentication.getCredentials();
        String keyHash = sha256(rawKey);

        return cache.get(keyHash)
                .switchIfEmpty(introspectAndCache(rawKey, keyHash))
                .flatMap(ApiKeyReactiveAuthenticationManager::toAuthentication)
                // Defence in depth. AuthenticationWebFilter reads an empty Mono from a
                // manager as "no authentication attempted" and CONTINUES the chain, so an
                // empty completion anywhere above would silently become the JWT fallthrough
                // that the precedence table forbids. IntrospectionClient already refuses to
                // complete empty; this guarantees it regardless of what it does later.
                .switchIfEmpty(Mono.error(new IntrospectionUnavailableException(
                        "Introspection produced no answer", null)));
    }

    private Mono<ApiKeyIntrospection> introspectAndCache(String rawKey, String keyHash) {
        return client.introspect(rawKey)
                .flatMap(result -> cache.put(keyHash, result, ttlFor(result)).thenReturn(result));
    }

    /**
     * Never cache past the key's own expiry. Without the clamp a key expiring in two
     * seconds, cached for sixty, would keep authenticating for fifty-eight seconds after
     * it died.
     */
    private Duration ttlFor(ApiKeyIntrospection result) {
        if (!result.active()) {
            return properties.negativeCacheTtl();
        }
        Duration configured = properties.cacheTtl();
        if (result.expiresAt() == null) {
            return configured;
        }
        Duration untilExpiry = Duration.between(Instant.now(), result.expiresAt());
        if (untilExpiry.isNegative() || untilExpiry.isZero()) {
            return Duration.ZERO;
        }
        return untilExpiry.compareTo(configured) < 0 ? untilExpiry : configured;
    }

    private static Mono<Authentication> toAuthentication(ApiKeyIntrospection result) {
        if (!result.active()) {
            return Mono.error(new BadCredentialsException("API key is not valid"));
        }
        if (result.scopes().contains(INTROSPECTION_SCOPE)) {
            return refuseSelfIntrospection();
        }

        Set<SimpleGrantedAuthority> authorities = result.scopes().stream()
                .map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope))
                .collect(Collectors.toSet());

        return Mono.just(new ApiKeyAuthenticationToken(result.name(), authorities));
    }

    /**
     * The gateway's own introspection key is a valid key, so introspection reports it
     * active. Accepting it here would let anyone who obtained it authenticate <em>as the
     * gateway</em> by replaying the credential the gateway itself puts on the wire.
     * Refused with the same message as any other bad key — a caller learns nothing about
     * why.
     */
    private static Mono<Authentication> refuseSelfIntrospection() {
        return Mono.error(new BadCredentialsException("API key is not valid"));
    }

    static String sha256(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256")
                    .digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException ex) {
            throw new IllegalStateException("SHA-256 is required but unavailable", ex);
        }
    }
}
```

- [ ] **Step 4: Run and confirm it passes**

Run: `.\mvnw.cmd -o test -Dtest=ApiKeyReactiveAuthenticationManagerTest`
Expected: PASS, 8 tests.

- [ ] **Step 5: Commit**

Message subject: `feat(M3): validate a key, clamp its cache TTL, and refuse the gateway's own`

---

## Task 11: Wire it into the security chain

**Files:**
- Modify: `src/main/java/com/gatekeeper/config/GatewaySecurityConfig.java`
- Test: `src/test/java/com/gatekeeper/apikey/ApiKeyAuthenticationTest.java`

- [ ] **Step 1: Write the failing integration test**

Model it on `src/test/java/com/gatekeeper/auth/JwtAuthenticationTest.java` — same WireMock-as-AuthCore setup, same `@DynamicPropertySource`. Add a stub for the introspection path and point `gatekeeper.api-key.introspection-uri` at it.

Every row of the precedence table in the design must have a test:

| `X-API-Key` | `Authorization` | Expected |
|---|---|---|
| absent | absent | 401 |
| absent | valid JWT | 200, proxied |
| valid key | absent | 200, proxied |
| valid key | valid JWT | 200, authenticated as the key |
| invalid key | valid JWT | **401 — no fallthrough** |
| invalid key | absent | 401 |

The fifth row is the one that matters. Without it, a caller could smuggle a bad key past the gateway by attaching a good token.

Also assert the error shape on each 401: `{"error": "unauthorized", "status": 401, "path": "..."}`.

Plus the cache assertion the design calls for by name — the only one that proves caching rather than assuming it:

```java
/**
 * Counting requests to AuthCore is the assertion. A test that merely calls twice and
 * expects 200 twice passes just as well with no cache at all.
 */
@Test
void introspectsOnceForTwoRequestsInsideTheTtl() {
    authCore.resetRequests();

    for (int i = 0; i < 2; i++) {
        client.get().uri("/api/machine/payments")
                .header("X-API-Key", VALID_KEY)
                .exchange()
                .expectStatus().isOk();
    }

    assertThat(authCore.findAll(postRequestedFor(urlEqualTo(INTROSPECT_PATH)))).hasSize(1);
}
```

Redis persists between test methods, so call `authCore.resetRequests()` and flush the cache key in a `@BeforeEach`, or this test passes for the wrong reason when another test warmed the same key.

- [ ] **Step 2: Run it and confirm it fails**

Run: `.\mvnw.cmd -o test -Dtest=ApiKeyAuthenticationTest`
Expected: FAIL — a valid key gets 401, because nothing reads the header yet.

- [ ] **Step 3: Add the beans and the filter**

In `GatewaySecurityConfig`:

```java
@Bean
public WebClient introspectionWebClient() {
    return WebClient.builder().build();
}

@Bean
public ApiKeyCache apiKeyCache(ReactiveStringRedisTemplate redis, ObjectMapper objectMapper) {
    return new RedisApiKeyCache(redis, objectMapper);
}

@Bean
public IntrospectionClient introspectionClient(
        WebClient introspectionWebClient, ApiKeyProperties properties) {
    return new IntrospectionClient(introspectionWebClient, properties);
}

@Bean
public ApiKeyReactiveAuthenticationManager apiKeyAuthenticationManager(
        ApiKeyCache cache, IntrospectionClient client, ApiKeyProperties properties) {
    return new ApiKeyReactiveAuthenticationManager(cache, client, properties);
}

/**
 * Runs at the authentication position, ahead of the resource server's own filter, so
 * X-API-Key decides the outcome whenever it is present.
 *
 * <p>A present-but-invalid key fails here rather than falling through to the JWT path.
 * A typo'd key should read as "bad credentials", not as a confusing "no credentials", and
 * a caller must not be able to smuggle a bad key past the gateway by attaching a good
 * token. This matches ApiKeyAuthenticationFilter's behaviour in AuthCore.
 */
private AuthenticationWebFilter apiKeyAuthenticationWebFilter(
        ApiKeyReactiveAuthenticationManager manager,
        ServerAuthenticationEntryPoint entryPoint) {

    AuthenticationWebFilter filter = new AuthenticationWebFilter(manager);
    filter.setServerAuthenticationConverter(new ApiKeyAuthenticationConverter());
    filter.setAuthenticationFailureHandler(
            new ServerAuthenticationEntryPointFailureHandler(entryPoint));
    return filter;
}
```

Then in `securityWebFilterChain`, add to the builder chain — take the two new beans as method parameters:

```java
.addFilterAt(apiKeyAuthenticationWebFilter(apiKeyAuthenticationManager, authenticationEntryPoint),
        SecurityWebFiltersOrder.AUTHENTICATION)
```

**Verify these two names against the jars before writing them** (§3 discipline):

```bash
jar tf ~/.m2/repository/org/springframework/security/spring-security-config/7.0.6/spring-security-config-7.0.6.jar | grep SecurityWebFiltersOrder
jar tf ~/.m2/repository/org/springframework/security/spring-security-web/7.0.6/spring-security-web-7.0.6.jar | grep -E "AuthenticationWebFilter|ServerAuthenticationEntryPointFailureHandler"
```

Expected: `org/springframework/security/config/web/server/SecurityWebFiltersOrder.class` and the two `org/springframework/security/web/server/authentication/...` classes. The first is already confirmed; confirm the other two yourself rather than trusting this line.

- [ ] **Step 4: Run and confirm it passes**

Run: `.\mvnw.cmd -o test -Dtest=ApiKeyAuthenticationTest`
Expected: PASS, 6 tests.

- [ ] **Step 5: Run the whole suite**

Run: `.\mvnw.cmd -o test`
Expected: PASS. Baseline is 24 tests. **If any M2 authentication test now fails, stop** — the new filter is intercepting a request it should have passed through.

- [ ] **Step 6: Commit**

Message subject: `feat(M3): accept an API key or a token, with the key deciding`

---

## Task 12: 503, not 401, when AuthCore cannot answer

**Files:**
- Modify: `src/main/java/com/gatekeeper/error/GlobalErrorWebExceptionHandler.java`
- Test: `src/test/java/com/gatekeeper/apikey/IntrospectionUnavailableTest.java`

- [ ] **Step 1: Write the failing test**

```java
@Test
void answers503WhenAuthCoreCannotBeAsked() {
    authCore.stubFor(post(urlEqualTo(INTROSPECT_PATH)).willReturn(aResponse().withStatus(500)));

    client.get().uri("/api/machine/payments")
            .header("X-API-Key", "ak_whatever")
            .exchange()
            .expectStatus().isEqualTo(503)
            .expectHeader().exists("Retry-After")
            .expectBody()
            .jsonPath("$.error").isEqualTo("service_unavailable")
            .jsonPath("$.status").isEqualTo(503);
}

/**
 * A 401 from introspection means the GATEWAY's credential was refused — our
 * misconfiguration, not the caller's error. It must never be relayed as their 401.
 */
@Test
void answers503WhenTheGatewaysOwnCredentialIsRefused() {
    authCore.stubFor(post(urlEqualTo(INTROSPECT_PATH)).willReturn(aResponse().withStatus(401)));

    client.get().uri("/api/machine/payments")
            .header("X-API-Key", "ak_whatever")
            .exchange()
            .expectStatus().isEqualTo(503);
}
```

- [ ] **Step 2: Run it and confirm it fails**

Run: `.\mvnw.cmd -o test -Dtest=IntrospectionUnavailableTest`
Expected: FAIL — currently 500, and no `Retry-After`.

- [ ] **Step 3: Map the exception and add the header**

In `GlobalErrorWebExceptionHandler.statusFor(...)`, add a branch beside the two existing ones:

```java
if (error instanceof IntrospectionUnavailableException) {
    return HttpStatus.SERVICE_UNAVAILABLE;
}
```

And in `render(...)`, beside the existing `WWW-Authenticate` branch:

```java
if (status == HttpStatus.SERVICE_UNAVAILABLE) {
    // Tells the caller this is worth retrying, which is the whole reason this path is a
    // 503 and not a 401 — their credential may be perfectly good.
    builder = builder.header(HttpHeaders.RETRY_AFTER, "5");
}
```

Note the existing comment in that method already reasons that `WWW-Authenticate` must not be unconditional because "a 503 or 404 carrying WWW-Authenticate would be wrong and confusing" — that reasoning now has a live case. Leave that comment intact.

- [ ] **Step 4: Run and confirm it passes**

Run: `.\mvnw.cmd -o test -Dtest=IntrospectionUnavailableTest`
Expected: PASS.

- [ ] **Step 5: Commit**

Message subject: `feat(M3): say 503 when the key cannot be checked, not 401`

---

## Task 13: Stamp the key caller's identity

**Files:**
- Modify: `src/main/java/com/gatekeeper/identity/IdentityStampFilter.java`
- Test: `src/test/java/com/gatekeeper/identity/IdentityPropagationTest.java` (extend)

- [ ] **Step 1: Write the failing test**

Add to the existing test class:

```java
@Test
void stampsTheSubjectForAnApiKeyCaller() {
    authCore.stubFor(post(urlEqualTo(INTROSPECT_PATH)).willReturn(okJson("""
            {"active":true,"name":"reporting","scopes":["payments:read"]}""")));
    authCore.stubFor(get(urlEqualTo("/api/machine/payments"))
            .willReturn(okJson("{}")));

    client.get().uri("/api/machine/payments")
            .header("X-API-Key", "ak_valid")
            .exchange()
            .expectStatus().isOk();

    authCore.verify(getRequestedFor(urlEqualTo("/api/machine/payments"))
            .withHeader("X-GK-Subject", equalTo("apikey:reporting")));
}

/** No tenant exists for a key, so no header — not a blank one a downstream might misread. */
@Test
void stampsNoTenantForAnApiKeyCaller() {
    authCore.stubFor(post(urlEqualTo(INTROSPECT_PATH)).willReturn(okJson("""
            {"active":true,"name":"reporting","scopes":["payments:read"]}""")));
    authCore.stubFor(get(urlEqualTo("/api/machine/payments"))
            .willReturn(okJson("{}")));

    client.get().uri("/api/machine/payments")
            .header("X-API-Key", "ak_valid")
            .exchange()
            .expectStatus().isOk();

    authCore.verify(getRequestedFor(urlEqualTo("/api/machine/payments"))
            .withoutHeader("X-GK-Tenant"));
}
```

Note the existing class stubs a JWKS endpoint and mints tokens via `TestKey`; leave all of that in place — these two tests are additive and the JWT stamping tests must keep passing unchanged.

- [ ] **Step 2: Run it and confirm it fails**

Run: `.\mvnw.cmd -o test -Dtest=IdentityPropagationTest`
Expected: FAIL — no `X-GK-Subject` is stamped; the filter's `.filter(JwtAuthenticationToken.class::isInstance)` drops the key caller.

- [ ] **Step 3: Extend the filter**

Replace the `filter`/`map` chain so it handles both principal types:

```java
@Override
public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
    return ReactiveSecurityContextHolder.getContext()
            .map(SecurityContext::getAuthentication)
            .map(authentication -> stamp(exchange, authentication))
            .defaultIfEmpty(exchange)
            .flatMap(chain::filter);
}

private static ServerWebExchange stamp(ServerWebExchange exchange, Authentication authentication) {
    if (authentication instanceof JwtAuthenticationToken jwtAuthentication) {
        return stampJwt(exchange, jwtAuthentication.getToken());
    }
    if (authentication instanceof ApiKeyAuthenticationToken apiKeyAuthentication) {
        return stampApiKey(exchange, apiKeyAuthentication);
    }
    return exchange;
}

/**
 * Subject only. A key has no tenant — api_keys has no such column, and M4 writes one rule
 * for tenant-less principals covering both keys and client-credentials tokens. Scopes are
 * not stamped either: scopes and permissions are different vocabularies, and the only
 * downstream that acts on a key's scopes is AuthCore, which re-derives them from the key.
 */
private static ServerWebExchange stampApiKey(
        ServerWebExchange exchange, ApiKeyAuthenticationToken authentication) {
    return exchange.mutate()
            .request(request -> request.headers(headers ->
                    headers.set(SUBJECT, "apikey:" + authentication.getName())))
            .build();
}
```

Keep the existing JWT logic verbatim as `stampJwt`.

- [ ] **Step 4: Run and confirm it passes**

Run: `.\mvnw.cmd -o test -Dtest=IdentityPropagationTest`
Expected: PASS, existing tests plus the two new ones.

- [ ] **Step 5: Commit**

Message subject: `feat(M3): stamp the subject for an API-key caller`

---

## Task 14: Prove the tests actually test something

No new production code. This task exists because in M0–M2 an anti-spoofing suite passed with the filter it covered deleted entirely.

Work in a **scratch copy**, never on the branch. Revert every mutation before moving on.

- [ ] **Step 1: Delete the TTL clamp**

In `ttlFor`, return `properties.cacheTtl()` unconditionally.
Run: `.\mvnw.cmd -o test -Dtest=ApiKeyReactiveAuthenticationManagerTest`
Expected: FAIL on the expiry-clamp test. **If it passes, that test is worthless — rewrite it.**

- [ ] **Step 2: Delete the self-introspection guard**

Remove the `result.scopes().contains(INTROSPECTION_SCOPE)` branch.
Expected: FAIL on the gateway-key-replay test.

- [ ] **Step 3: Delete the no-fallthrough behaviour**

Make the API-key filter continue the chain on failure instead of invoking the failure handler.
Run: `.\mvnw.cmd -o test -Dtest=ApiKeyAuthenticationTest`
Expected: FAIL on the invalid-key-plus-valid-token row. **If every row still passes, the precedence table is untested.**

- [ ] **Step 3b: Delete the non-2xx status handling in `IntrospectionClient`**

Remove the `.onStatus(...)` block, leaving bare `.retrieve().bodyToMono(...)`.
Run: `.\mvnw.cmd -o test -Dtest=IntrospectionClientTest+ApiKeyAuthenticationTest`
Expected: FAIL on the redirect test. **If the redirect test passes, it is not testing what it claims** — a 3xx is not an error to `retrieve()`, so this must fail.

Then also remove the manager's trailing `.switchIfEmpty(...)` guard and confirm a redirect-answering AuthCore lets a bad key fall through to the JWT path. That fallthrough is the security property; if no test catches it, add one before continuing.

- [ ] **Step 4: Delete the timeout**

Remove `.timeout(properties.timeout())`.
Expected: the slow-AuthCore test FAILS (hangs to its `verify(Duration)` limit).

- [ ] **Step 5: Delete the whole filter registration**

Remove the `.addFilterAt(...)` line.
Expected: **more than one** test fails. If only one does, the coverage is too narrow.

- [ ] **Step 6: Restore everything and confirm green**

Run: `git status` — expected: clean. Then `.\mvnw.cmd -o test` — expected: all pass.

- [ ] **Step 7: Commit any test improvements the mutations exposed**

Message subject: `test(M3): close the gaps mutation testing found`

---

## Task 15: Run it against the real thing

Reading a diff did not catch the cross-tenant leak, the missing `WWW-Authenticate`, or the unreachable 403 branch in M0–M2. Booting the services did.

- [ ] **Step 1: Start everything**

```bash
docker compose up -d postgres redis
```

Then AuthCore (built from the Part A merge), ledger-service, and GateKeeper, each with `.\mvnw.cmd -o spring-boot:run`.

- [ ] **Step 2: The demo key reaches AuthCore's machine route**

```bash
curl.exe -i -H "X-API-Key: ak_demo_reporting_job_local_only_0000000000" http://localhost:8081/api/machine/payments
```

Expected: `200`, and the body's `authenticatedVia` reads `api-key`.

- [ ] **Step 3: The ledger route refuses it, as designed**

```bash
curl.exe -i -H "X-API-Key: ak_demo_reporting_job_local_only_0000000000" http://localhost:8081/api/ledger/entries
```

Expected: `401` **from ledger-service**, not from the gateway. This is section 8 of the design. Confirm it is what actually happens rather than what the document predicts — and note which service answered.

- [ ] **Step 4: A bad key is refused**

```bash
curl.exe -i -H "X-API-Key: ak_not_a_real_key" http://localhost:8081/api/machine/payments
```

Expected: `401`, JSON error shape, `WWW-Authenticate: Bearer`.

- [ ] **Step 5: The gateway's own key is refused as a caller credential**

```bash
curl.exe -i -H "X-API-Key: ak_gatekeeper_introspection_local_only_00000" http://localhost:8081/api/machine/payments
```

Expected: `401`. **A `200` here is a privilege-escalation bug — stop and fix it.**

- [ ] **Step 6: Caching actually caches**

Run step 2 twice, then check AuthCore's log for introspection calls, or:

```bash
docker compose exec redis redis-cli KEYS "gatekeeper:apikey:*"
```

Expected: one key, named by a 64-character hex hash. **If the raw `ak_...` key appears anywhere in that output, stop — the cache is storing credentials.**

- [ ] **Step 7: AuthCore down yields 503**

Stop AuthCore, wait for the cache TTL to lapse, then repeat step 2.
Expected: `503` with `Retry-After`, not `401` and not a hang.

- [ ] **Step 8: A bearer token still works exactly as before**

Get a token via the client-credentials grant and call `/api/machine/payments`.
Expected: `200`, `authenticatedVia` reads `bearer-jwt`.

- [ ] **Step 9: Record what you found**

Anything that differed from this plan or the design goes in the design doc or the handoff — not only in a commit message.

---

## Task 16: Merge and update the docs

- [ ] **Step 1: Full suite, both repos**

Expected: green in each.

- [ ] **Step 2: Merge each GateKeeper task branch with `--no-ff`, then push both repos.**

- [ ] **Step 3: Update `README.md`**

Add API-key authentication to the capability list and the request-flow description. Do **not** claim keys reach every route — say plainly that a key authenticates at the gateway and that ledger-service accepts bearer tokens only.

- [ ] **Step 4: Update `docs/superpowers/HANDOFF-M3-M6.md`**

Mark M3 done, record the new commit hashes and test counts in the table in §1, and move anything M3 deferred into §5 against the milestone that owns it. At minimum:

- The gateway-key rotation debt (design §5), owner M9.
- `X-API-Key` stripping on routes that cannot use it, owner M4.
- **AuthCore's seeded demo API key lapses permanently after a year.** Found during Task 4's review, pre-existing, not introduced by M3. `DataSeeder.seedApiKey()` guards on `existsByName` alone and so never revisits an existing row, while the demo key is seeded with a 365-day expiry — so once it expires nothing re-seeds it, and local development silently loses its demo key with no error explaining why. The same name-only guard means editing a key's *value* in source has no effect after first boot either. Contrast `upsert(RegisteredClient)`, which deliberately re-seeds every boot. Not fixed in M3; commented in place so the cause sits next to the symptom.
- **`DataSeeder` runs unconditionally in every profile.** No `@Profile` or `@Conditional` anywhere in the project, so seeded users, `machine-secret`, the demo key and now the gateway key are created on every boot including production. Pre-existing and cross-cutting; M9 owns key *rotation*, not seeder gating, so this wants a deployment-readiness milestone rather than being smuggled into M3.
- **AuthCore returns a redirect, not an error, to a client sending `Accept: text/html`.** Found during Task 2's review and pre-existing, not introduced by M3. Jackson-only converters cannot satisfy `text/html`, so writing any response body throws `HttpMediaTypeNotAcceptableException`, which escapes the controller's own handler and takes the same forward-to-`/error` path into the fallthrough chain. It affects well-formed requests too, not just malformed ones. Low practical risk — GateKeeper is a JSON client and has no reason to send that header — and GateKeeper is hardened against it regardless, since it refuses any non-2xx. Record it; do not fix it inside M3.

- [ ] **Step 5: Commit.**

Message subject: `docs: record what M3 built and what it deferred`

---

## Definition of done

From the design, §14 — every line needs evidence, not assertion:

- [ ] The seeded demo key authenticates through GateKeeper and reaches AuthCore's machine route.
- [ ] An unknown, disabled, or expired key is refused with 401 in the platform error shape.
- [ ] A bearer JWT still authenticates exactly as it did before M3.
- [ ] AuthCore unreachable produces 503, not 401, and not a hang.
- [ ] A repeated request inside the cache TTL performs one introspection, proven by request count.
- [ ] The introspection endpoint refuses an unauthenticated caller.
- [ ] The gateway's own introspection key is refused when presented as an ordinary caller credential.
- [ ] Both repos green, each with its own branch, its own review, and its own merge.
