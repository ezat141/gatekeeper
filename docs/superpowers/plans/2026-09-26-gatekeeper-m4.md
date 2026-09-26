# GateKeeper M4 — Route-to-Scope Authorization and Tenant Check Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the gateway decide what an authenticated caller may reach — a per-route scope table with deny by default, wrapped in a tenant check — and refuse with `403` in the platform's JSON shape, for bearer-token and API-key callers alike.

**Architecture:** `RouteScopeAuthorizationManager` holds the rule table and is wrapped by `TenantAuthorizationManager`; the pair is plugged into the existing chain with one `.anyExchange().access(...)`. A denial travels as a `GatewayAccessDeniedException` carrying a `Reason`, because Spring Security 7.0.6 discards the `AuthorizationResult` on its way to the handler. A new `JsonServerAccessDeniedHandler` renders every `403` with a fixed `detail`. The ledger route stops forwarding `X-API-Key`.

**Tech Stack:** Spring Boot 4.0.7, Spring Cloud 2025.1.2, Spring Security 7.0.6, Spring Framework 7.0.8, WebFlux, reactive Redis, WireMock 3.13.2, JUnit 6.0.3.

Design: [`docs/superpowers/specs/2026-09-26-gatekeeper-m4-design.md`](../specs/2026-09-26-gatekeeper-m4-design.md). Where this plan and the spec disagree, the spec wins — say so rather than silently following one.

---

## Environment rules — read before the first command

These cost real time in M0–M3. They are not optional.

- **`.\mvnw.cmd`, never `mvn`.** System Maven is 3.2.5. Use `-o` (offline): M4 adds no dependency, so every build here can run offline.
- **Redis must be running for the GateKeeper suite.** Without it 15 tests fail and 4 error on `RedisConnectionFailureException`, which reads like a regression and is not one. Start it from the authcore directory: `docker compose up -d redis`. Docker Desktop stops often; check it first when Redis refuses connections.
- **`curl.exe`, never `curl`** in PowerShell; `curl` is an alias for `Invoke-WebRequest`.
- **`&&` does not work in Windows PowerShell 5.1.** Use `;` or `if ($?) { ... }`.
- **`git commit -m` breaks on quotes.** Write a message file with a file-writing tool and use `git commit -F <file>`.
- **Never write a commit message with `Set-Content -Encoding utf8`** — it emits a BOM that lands in the commit subject.
- **No Claude attribution anywhere.** No `Co-Authored-By` trailer, no "Generated with Claude Code" line — in commits, merge commits, or PR text. This is a standing rule for these repositories.
- **Verify names against the jar before writing them.** `jar tf <jar> | grep ClassName`, `javap -cp <jar> <FQCN>`. Every Spring Security name in this plan was checked against the 7.0.6 jars; anything you add that is not in this plan gets the same check.
- **Jackson 3.** `ObjectMapper` is `tools.jackson.databind.ObjectMapper`. This plan does not need one; if you reach for it, you are probably re-serialising the error body by hand, which the design forbids.
- **Branches:** every task gets `feature/m4-task-N` off `master`, merged back with `git merge --no-ff`. The `m4-` prefix matters: M0–M3 already used `feature/task-6` … `feature/task-15`, and several of those branches still exist.

**This is a single-repo milestone.** Everything is in `D:\courses\My CV\My cv\ProjectsCVs\gatekeeper`. AuthCore and ledger-service are only started, never modified — Task 6 needs them running.

---

## File structure

| File | Responsibility |
|---|---|
| `src/main/java/com/gatekeeper/authz/Reason.java` | Create — the four reasons a request is refused, each with its fixed `detail` |
| `src/main/java/com/gatekeeper/authz/GatewayAccessDeniedException.java` | Create — an `AccessDeniedException` that carries a `Reason` |
| `src/main/java/com/gatekeeper/authz/RouteScopeAuthorizationManager.java` | Create — the rule table |
| `src/main/java/com/gatekeeper/authz/TenantAuthorizationManager.java` | Create — the tenant check wrapped around the table |
| `src/main/java/com/gatekeeper/error/ErrorBody.java` | Modify — optional `detail` |
| `src/main/java/com/gatekeeper/error/CodecWriterContext.java` | Create — the `ServerResponse.Context` both committing handlers share |
| `src/main/java/com/gatekeeper/error/JsonServerAuthenticationEntryPoint.java` | Modify — use `CodecWriterContext` |
| `src/main/java/com/gatekeeper/error/JsonServerAccessDeniedHandler.java` | Create — the `403` |
| `src/main/java/com/gatekeeper/config/GatewaySecurityConfig.java` | Modify — plug in the managers and the handler |
| `src/main/resources/application.yml` | Modify — `RemoveRequestHeader=X-API-Key` on the ledger route |
| `src/test/java/com/gatekeeper/support/Principals.java` | Create — JWT and API-key `Authentication`s for unit tests |
| `src/test/java/com/gatekeeper/error/JsonServerAccessDeniedHandlerTest.java` | Create |
| `src/test/java/com/gatekeeper/authz/RouteScopeAuthorizationManagerTest.java` | Create |
| `src/test/java/com/gatekeeper/authz/TenantAuthorizationManagerTest.java` | Create |
| `src/test/java/com/gatekeeper/authz/AuthorizationTest.java` | Create — end-to-end allow/deny matrix |
| Six existing test classes | Modify — tokens gain scopes, key callers move off the ledger route (Task 4) |

**Why `com.gatekeeper.authz` is its own package:** it mirrors `apikey` and `identity`, it is the package the implementation plan's structure names, and it keeps route rules out of `GatewaySecurityConfig`, where the M2 Javadoc warned they would be buried.

**Why `Reason` carries its own `detail`:** the four strings and the four reasons are one table. Keeping them in one enum means a new reason cannot be added without its wire text, and the handler cannot map one to the wrong string.

---

## Task 1: The denial vocabulary and the 403 handler

**Files:**
- Create: `src/main/java/com/gatekeeper/authz/Reason.java`
- Create: `src/main/java/com/gatekeeper/authz/GatewayAccessDeniedException.java`
- Create: `src/main/java/com/gatekeeper/error/CodecWriterContext.java`
- Create: `src/main/java/com/gatekeeper/error/JsonServerAccessDeniedHandler.java`
- Modify: `src/main/java/com/gatekeeper/error/ErrorBody.java`
- Modify: `src/main/java/com/gatekeeper/error/JsonServerAuthenticationEntryPoint.java`
- Test: `src/test/java/com/gatekeeper/error/JsonServerAccessDeniedHandlerTest.java`

- [ ] **Step 1: Branch**

```bash
git checkout master
git checkout -b feature/m4-task-1
```

- [ ] **Step 2: Write the failing test**

`src/test/java/com/gatekeeper/error/JsonServerAccessDeniedHandlerTest.java`:

```java
package com.gatekeeper.error;

import com.gatekeeper.authz.GatewayAccessDeniedException;
import com.gatekeeper.authz.Reason;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpResponse;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.access.AccessDeniedException;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

class JsonServerAccessDeniedHandlerTest {

    private final JsonServerAccessDeniedHandler handler =
            new JsonServerAccessDeniedHandler(ServerCodecConfigurer.create());

    @ParameterizedTest
    @EnumSource(Reason.class)
    void rendersEachReasonAsItsOwnDetail(Reason reason) {
        MockServerWebExchange exchange = exchangeFor("/api/ledger/entries");

        handler.handle(exchange, new GatewayAccessDeniedException(reason)).block();

        assertForbiddenWithDetail(exchange, "/api/ledger/entries", reason.detail());
    }

    /**
     * A denial that did not come from the gateway's own managers carries no {@link Reason}.
     * Its message is a framework string never meant for a wire contract, so it must not be
     * echoed — the generic detail stands in for it.
     */
    @Test
    void rendersAPlainDenialWithTheGenericDetailRatherThanItsMessage() {
        MockServerWebExchange exchange = exchangeFor("/api/machine/payments");

        handler.handle(exchange, new AccessDeniedException("Access Denied (internal)")).block();

        assertForbiddenWithDetail(exchange, "/api/machine/payments",
                JsonServerAccessDeniedHandler.GENERIC_DETAIL);
    }

    /** Two reasons sharing a detail would make a caller unable to tell them apart. */
    @Test
    void everyReasonHasADistinctDetail() {
        assertThat(Arrays.stream(Reason.values()).map(Reason::detail).distinct())
                .hasSize(Reason.values().length);
    }

    private static MockServerWebExchange exchangeFor(String path) {
        return MockServerWebExchange.from(MockServerHttpRequest.get(path));
    }

    private static void assertForbiddenWithDetail(
            MockServerWebExchange exchange, String path, String detail) {
        MockServerHttpResponse response = exchange.getResponse();
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(response.getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_JSON);
        // The platform rule, stated in ledger-service's handler too: a 403 carries no challenge.
        assertThat(response.getHeaders().get(HttpHeaders.WWW_AUTHENTICATE)).isNull();
        assertThat(response.getBodyAsString().block()).isEqualTo(
                "{\"error\":\"forbidden\",\"status\":403,\"path\":\"%s\",\"detail\":\"%s\"}"
                        .formatted(path, detail));
    }
}
```

- [ ] **Step 3: Run it to make sure it fails**

```bash
.\mvnw.cmd -o test -Dtest=JsonServerAccessDeniedHandlerTest
```

Expected: compilation failure — `Reason`, `GatewayAccessDeniedException` and `JsonServerAccessDeniedHandler` do not exist.

- [ ] **Step 4: Create `Reason`**

`src/main/java/com/gatekeeper/authz/Reason.java`:

```java
package com.gatekeeper.authz;

/**
 * Why the gateway refused a request. Each reason carries the one {@code detail} string a
 * caller sees for it, so the reason and its wire text cannot drift apart — see the M4
 * design, section 7.
 *
 * <p>Every string is authored here. None of them ever comes from an exception message.
 */
public enum Reason {

    MISSING_SCOPE("the credential does not carry the scope this route requires"),
    API_KEY_NOT_ACCEPTED("this route does not accept API keys"),
    TENANT_MISMATCH("the request names a tenant other than the token's"),
    NO_RULE("no rule permits this method and path");

    private final String detail;

    Reason(String detail) {
        this.detail = detail;
    }

    public String detail() {
        return detail;
    }
}
```

- [ ] **Step 5: Create `GatewayAccessDeniedException`**

`src/main/java/com/gatekeeper/authz/GatewayAccessDeniedException.java`:

```java
package com.gatekeeper.authz;

import org.springframework.security.access.AccessDeniedException;

/**
 * A denial that remembers why.
 *
 * <p>This exists because Spring Security 7.0.6 gives a manager no other way to tell the
 * access-denied handler anything. {@code ReactiveAuthorizationManager.verify()} turns every
 * {@code false} decision into {@code new AccessDeniedException("Access Denied")}, discarding
 * the decision itself, and {@code authorizeExchange} wraps every manager in the {@code final}
 * {@code DelegatingReactiveAuthorizationManager}, so overriding {@code verify()} is never
 * reached. A manager that denies by returning this exception as an error from {@code
 * authorize()} gets its reason through both wrappers unchanged, to {@code
 * ExceptionTranslationWebFilter} and on to the handler. Verified in the bytecode; see the M4
 * design, section 7.
 */
public class GatewayAccessDeniedException extends AccessDeniedException {

    private final Reason reason;

    public GatewayAccessDeniedException(Reason reason) {
        super(reason.detail());
        this.reason = reason;
    }

    public Reason reason() {
        return reason;
    }
}
```

- [ ] **Step 6: Give `ErrorBody` an optional `detail`**

Replace the body of `src/main/java/com/gatekeeper/error/ErrorBody.java` from the class Javadoc down with:

```java
/**
 * The one JSON error shape the platform renders for a refused or failed request, shared by
 * {@link GlobalErrorWebExceptionHandler} (exceptions that reach the WebFlux error-handling
 * layer), {@link JsonServerAuthenticationEntryPoint} (the 401 Spring Security commits
 * directly) and {@link JsonServerAccessDeniedHandler} (the 403 it commits the same way).
 *
 * <p>Three call sites building the same shape independently is exactly how it drifts apart
 * over time, so the construction lives in one place.
 *
 * <p>{@code detail} is present only when a caller supplies one — today only the 403 does.
 * ledger-service's {@code ErrorBody} has the identical overload, so the two services agree on
 * the field's name and on its absence when there is nothing to say.
 */
final class ErrorBody {

    private ErrorBody() {
    }

    static Map<String, Object> of(HttpStatus status, String path) {
        return of(status, path, null);
    }

    static Map<String, Object> of(HttpStatus status, String path, String detail) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", status.getReasonPhrase().toLowerCase(Locale.ROOT).replace(' ', '_'));
        body.put("status", status.value());
        body.put("path", path);
        if (detail != null) {
            body.put("detail", detail);
        }
        return body;
    }
}
```

The imports at the top of the file are unchanged.

- [ ] **Step 7: Extract the writer context both handlers need**

`src/main/java/com/gatekeeper/error/CodecWriterContext.java`:

```java
package com.gatekeeper.error;

import org.springframework.http.codec.HttpMessageWriter;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.reactive.result.view.ViewResolver;

import java.util.List;

/**
 * {@link ServerResponse#writeTo} needs a {@link ServerResponse.Context} to know which writers
 * are available. Both handlers that commit a response outside the WebFlux error-handling
 * layer — {@link JsonServerAuthenticationEntryPoint} and {@link
 * JsonServerAccessDeniedHandler} — supply the application's configured writers and no view
 * resolvers, which is how {@code AbstractErrorWebExceptionHandler} satisfies the same
 * requirement for itself. One class, so the two cannot come to write the shape differently.
 */
final class CodecWriterContext implements ServerResponse.Context {

    private final ServerCodecConfigurer codecConfigurer;

    CodecWriterContext(ServerCodecConfigurer codecConfigurer) {
        this.codecConfigurer = codecConfigurer;
    }

    @Override
    public List<HttpMessageWriter<?>> messageWriters() {
        return codecConfigurer.getWriters();
    }

    @Override
    public List<ViewResolver> viewResolvers() {
        return List.of();
    }
}
```

In `JsonServerAuthenticationEntryPoint.java`:
- replace `.flatMap(response -> response.writeTo(exchange, new WriterContext()));` with `.flatMap(response -> response.writeTo(exchange, new CodecWriterContext(codecConfigurer)));`
- delete the inner `WriterContext` class and its Javadoc;
- delete the now-unused imports `org.springframework.http.codec.HttpMessageWriter`, `org.springframework.web.reactive.result.view.ViewResolver` and `java.util.List`.

- [ ] **Step 8: Create the handler**

`src/main/java/com/gatekeeper/error/JsonServerAccessDeniedHandler.java`:

```java
package com.gatekeeper.error;

import com.gatekeeper.authz.GatewayAccessDeniedException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * The 403 counterpart of {@link JsonServerAuthenticationEntryPoint}, needed for the same
 * reason: {@code ExceptionTranslationWebFilter} hands an access denial straight to this
 * handler, which commits the response itself, so nothing reaches {@link
 * GlobalErrorWebExceptionHandler}. Left at the default, a 403 would be the one refusal with an
 * empty body. For a bearer caller it would be worse: the resource server's default handler
 * stamps {@code WWW-Authenticate: Bearer error="insufficient_scope"} on every denial,
 * including a tenant mismatch that no scope could ever fix.
 *
 * <p>{@code detail} is always a string the gateway authored — the denial's {@code Reason}, or
 * {@link #GENERIC_DETAIL} for a denial that carries none. It never echoes {@link
 * AccessDeniedException#getMessage()}.
 *
 * <p>No {@code WWW-Authenticate}. The caller is authenticated, and no challenge would help
 * them. ledger-service's handler states the same rule, and the two services must agree.
 */
@Component
public class JsonServerAccessDeniedHandler implements ServerAccessDeniedHandler {

    static final String GENERIC_DETAIL = "the credential does not permit this request";

    private final ServerCodecConfigurer codecConfigurer;

    public JsonServerAccessDeniedHandler(ServerCodecConfigurer codecConfigurer) {
        this.codecConfigurer = codecConfigurer;
    }

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, AccessDeniedException denied) {
        String detail = denied instanceof GatewayAccessDeniedException gatewayDenial
                ? gatewayDenial.reason().detail()
                : GENERIC_DETAIL;
        String path = exchange.getRequest().getPath().value();
        Map<String, Object> body = ErrorBody.of(HttpStatus.FORBIDDEN, path, detail);

        return ServerResponse.status(HttpStatus.FORBIDDEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .flatMap(response -> response.writeTo(exchange, new CodecWriterContext(codecConfigurer)));
    }
}
```

- [ ] **Step 9: Run the test to make sure it passes**

```bash
.\mvnw.cmd -o test -Dtest=JsonServerAccessDeniedHandlerTest
```

Expected: PASS, 6 tests (4 reasons, the generic denial, distinctness).

- [ ] **Step 10: Make it fail on purpose**

In `JsonServerAccessDeniedHandler.handle`, temporarily replace `: GENERIC_DETAIL;` with `: denied.getMessage();`. Rerun Step 9. Expected: `rendersAPlainDenialWithTheGenericDetailRatherThanItsMessage` fails, reading `Access Denied (internal)`. That is the guard against echoing a framework message. Revert the change.

Then temporarily change `.contentType(MediaType.APPLICATION_JSON)` to `.contentType(MediaType.TEXT_PLAIN)`. Expected: every test except `everyReasonHasADistinctDetail` fails. Revert.

- [ ] **Step 11: Run the whole suite**

Redis running (see Environment rules).

```bash
.\mvnw.cmd -o test
```

Expected: PASS, 76 tests (70 + 6). Nothing is wired yet, so no existing behaviour changes. The 401 tests in `ErrorShapeTest` and `ApiKeyAuthenticationTest` prove the entry-point refactor in Step 7 changed nothing.

- [ ] **Step 12: Commit**

Message file contents:

```
feat(M4): a 403 in the platform's JSON shape, with a reason

Adds the four reasons the gateway will refuse a request for, each with
the one detail string a caller sees, and a handler that renders them.
Nothing is wired yet; that waits for the rules that produce them.

The reason travels as an AccessDeniedException subclass because Spring
Security 7.0.6 discards the AuthorizationResult between a manager and
the handler. The writer context the 401 entry point kept to itself is
now shared, so the two committing handlers write the shape one way.
```

```bash
git add src/main/java/com/gatekeeper/authz src/main/java/com/gatekeeper/error src/test/java/com/gatekeeper/error/JsonServerAccessDeniedHandlerTest.java
git commit -F <message-file>
```

- [ ] **Step 13: Review, then merge**

Spec-compliance review, then code-quality review, each by a reviewer told not to trust this task's report. Fix and re-review until clean. Then:

```bash
git checkout master
git merge --no-ff feature/m4-task-1
```

Merge-commit message: `Merge branch 'feature/m4-task-1'` — no trailer.

---

## Task 2: The rule table

**Files:**
- Create: `src/test/java/com/gatekeeper/support/Principals.java`
- Create: `src/main/java/com/gatekeeper/authz/RouteScopeAuthorizationManager.java`
- Test: `src/test/java/com/gatekeeper/authz/RouteScopeAuthorizationManagerTest.java`

- [ ] **Step 1: Branch**

```bash
git checkout master
git checkout -b feature/m4-task-2
```

- [ ] **Step 2: Create the test principals**

`src/test/java/com/gatekeeper/support/Principals.java`:

```java
package com.gatekeeper.support;

import com.gatekeeper.apikey.ApiKeyAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Arrays;
import java.util.List;

/**
 * Authenticated callers exactly as the gateway's two authentication paths produce them, for
 * unit tests that exercise authorization without a Spring context.
 *
 * <p>Scopes become {@code SCOPE_*} authorities on both kinds of principal. That is what
 * Spring's default {@code JwtGrantedAuthoritiesConverter} derives from a token's {@code scope}
 * claim — GateKeeper configures no converter of its own — and what M3's {@code
 * ApiKeyReactiveAuthenticationManager} derives from a key's introspected scopes.
 */
public final class Principals {

    private Principals() {
    }

    /** A JWT caller with no {@code tenant} claim — the shape of a client-credentials token. */
    public static Authentication jwt(String... scopes) {
        return jwtInTenant(null, scopes);
    }

    /** A JWT caller whose token carries {@code tenant}, as every user token does. */
    public static Authentication jwtInTenant(String tenant, String... scopes) {
        Jwt.Builder token = Jwt.withTokenValue("test-token")
                .header("alg", "RS256")
                .subject("ezzat")
                .claim("scope", List.of(scopes));
        if (tenant != null) {
            token.claim("tenant", tenant);
        }
        return new JwtAuthenticationToken(token.build(), scopeAuthorities(scopes));
    }

    /**
     * A JWT caller holding an authority spelled like a permission ({@code payments:write})
     * rather than a scope ({@code SCOPE_payments:write}). The gateway maps no permissions, so
     * this can only arise from a future converter change — and must never satisfy a scope rule.
     */
    public static Authentication jwtWithBareAuthority(String authority) {
        Jwt token = Jwt.withTokenValue("test-token")
                .header("alg", "RS256")
                .subject("ezzat")
                .build();
        return new JwtAuthenticationToken(token, List.of(new SimpleGrantedAuthority(authority)));
    }

    /** An API-key caller named {@code reporting}, as introspection authenticates one. */
    public static Authentication apiKey(String... scopes) {
        return new ApiKeyAuthenticationToken("reporting", scopeAuthorities(scopes));
    }

    private static List<GrantedAuthority> scopeAuthorities(String... scopes) {
        return Arrays.stream(scopes)
                .<GrantedAuthority>map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope))
                .toList();
    }
}
```

- [ ] **Step 3: Write the failing test**

`src/test/java/com/gatekeeper/authz/RouteScopeAuthorizationManagerTest.java`:

```java
package com.gatekeeper.authz;

import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.HttpMethod;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import reactor.core.publisher.Mono;

import java.util.stream.Stream;

import static com.gatekeeper.support.Principals.apiKey;
import static com.gatekeeper.support.Principals.jwt;
import static com.gatekeeper.support.Principals.jwtWithBareAuthority;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.HttpMethod.DELETE;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.HEAD;
import static org.springframework.http.HttpMethod.OPTIONS;
import static org.springframework.http.HttpMethod.PATCH;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.HttpMethod.PUT;

/**
 * Pins the whole table in the M4 design, section 4, row by row. The rules are evaluated in
 * order and the first match decides, so a reordering that changes any outcome fails here.
 *
 * <p>Every refusal asserts its specific {@link Reason}, never merely "denied": a missing scope
 * and a missing rule are different facts, and the caller is told which.
 */
class RouteScopeAuthorizationManagerTest {

    static final String GRANTED = "granted";
    static final String DENIED_WITHOUT_REASON = "denied without a reason";

    private final RouteScopeAuthorizationManager manager = new RouteScopeAuthorizationManager();

    static Stream<Arguments> table() {
        return Stream.of(
                // /actuator/info — authenticated, GET only
                row(GET, "/actuator/info", "jwt[]", jwt(), GRANTED),
                row(GET, "/actuator/info", "key[]", apiKey(), GRANTED),
                row(POST, "/actuator/info", "jwt[]", jwt(), Reason.NO_RULE),

                // /api/accounts/** — authenticated, any method; AuthCore decides the rest
                row(GET, "/api/accounts/me", "jwt[]", jwt(), GRANTED),
                row(GET, "/api/accounts/me", "key[]", apiKey(), GRANTED),
                row(POST, "/api/accounts/ezzat/payments", "jwt[]", jwt(), GRANTED),
                row(DELETE, "/api/accounts/ezzat", "jwt[]", jwt(), GRANTED),

                // /api/machine/** — scope, either credential
                row(GET, "/api/machine/payments", "jwt[read]", jwt("payments:read"), GRANTED),
                row(GET, "/api/machine/payments", "key[read]", apiKey("payments:read"), GRANTED),
                row(GET, "/api/machine/payments", "jwt[write]", jwt("payments:write"), Reason.MISSING_SCOPE),
                row(GET, "/api/machine/payments", "key[]", apiKey(), Reason.MISSING_SCOPE),
                row(POST, "/api/machine/payments", "jwt[write]", jwt("payments:write"), GRANTED),
                row(POST, "/api/machine/payments", "key[write]", apiKey("payments:write"), GRANTED),
                row(POST, "/api/machine/payments", "jwt[read]", jwt("payments:read"), Reason.MISSING_SCOPE),
                row(POST, "/api/machine/payments", "key[read]", apiKey("payments:read"), Reason.MISSING_SCOPE),
                row(PUT, "/api/machine/payments", "jwt[read,write]", jwt("payments:read", "payments:write"), Reason.NO_RULE),
                row(DELETE, "/api/machine/payments", "jwt[read,write]", jwt("payments:read", "payments:write"), Reason.NO_RULE),
                row(HEAD, "/api/machine/payments", "jwt[read,write]", jwt("payments:read", "payments:write"), Reason.NO_RULE),
                row(OPTIONS, "/api/machine/payments", "jwt[read,write]", jwt("payments:read", "payments:write"), Reason.NO_RULE),

                // /api/ledger/** — JWT principal and scope
                row(GET, "/api/ledger/entries", "jwt[read]", jwt("payments:read"), GRANTED),
                row(GET, "/api/ledger/whoami", "jwt[read]", jwt("payments:read"), GRANTED),
                row(GET, "/api/ledger/whoami", "jwt[openid,profile]", jwt("openid", "profile"), Reason.MISSING_SCOPE),
                row(POST, "/api/ledger/entries", "jwt[write]", jwt("payments:write"), GRANTED),
                row(POST, "/api/ledger/entries", "jwt[read]", jwt("payments:read"), Reason.MISSING_SCOPE),
                // The credential type is decided before the scope: a key is refused as a key
                // whether or not it happens to carry the scope.
                row(GET, "/api/ledger/entries", "key[read]", apiKey("payments:read"), Reason.API_KEY_NOT_ACCEPTED),
                row(GET, "/api/ledger/entries", "key[]", apiKey(), Reason.API_KEY_NOT_ACCEPTED),
                row(POST, "/api/ledger/entries", "key[write]", apiKey("payments:write"), Reason.API_KEY_NOT_ACCEPTED),
                row(PUT, "/api/ledger/entries", "jwt[read,write]", jwt("payments:read", "payments:write"), Reason.NO_RULE),
                row(PATCH, "/api/ledger/entries", "jwt[read,write]", jwt("payments:read", "payments:write"), Reason.NO_RULE),
                row(DELETE, "/api/ledger/entries", "jwt[read,write]", jwt("payments:read", "payments:write"), Reason.NO_RULE),
                row(HEAD, "/api/ledger/entries", "jwt[read,write]", jwt("payments:read", "payments:write"), Reason.NO_RULE),
                row(OPTIONS, "/api/ledger/entries", "jwt[read,write]", jwt("payments:read", "payments:write"), Reason.NO_RULE),

                // Everything else — deny by default
                row(GET, "/api/unknown/thing", "jwt[read,write]", jwt("payments:read", "payments:write"), Reason.NO_RULE),
                row(POST, "/api/internal/api-keys/introspect", "key[read]", apiKey("payments:read"), Reason.NO_RULE),
                row(GET, "/actuator/env", "jwt[read,write]", jwt("payments:read", "payments:write"), Reason.NO_RULE),
                row(GET, "/", "jwt[read,write]", jwt("payments:read", "payments:write"), Reason.NO_RULE));
    }

    @ParameterizedTest(name = "{0} {1} as {2} -> {3}")
    @MethodSource("table")
    void decidesEveryRowOfTheTable(HttpMethod method, String path, Authentication caller, Object expected) {
        assertThat(outcome(method, path, Mono.just(caller))).isEqualTo(expected);
    }

    /**
     * The edge checks scope; the downstream checks permission. A token holding a
     * permission-shaped authority but no scope must not pass a scope rule — otherwise a future
     * converter that maps {@code permissions} would silently turn every permission into a
     * grant the client was never given.
     */
    @Test
    void doesNotAcceptAPermissionInPlaceOfAScope() {
        assertThat(outcome(POST, "/api/machine/payments", Mono.just(jwtWithBareAuthority("payments:write"))))
                .isEqualTo(Reason.MISSING_SCOPE);
    }

    /**
     * With no authentication there is no reason to report: ExceptionTranslationWebFilter
     * sends a principal-less exchange to the 401 entry point before any access-denied handler
     * runs. So the answer must be a plain denial, not a reasoned one, on every kind of row.
     */
    @Test
    void deniesAnUnauthenticatedCallerWithoutAReason() {
        assertThat(outcome(GET, "/api/accounts/me", Mono.empty())).isEqualTo(DENIED_WITHOUT_REASON);
        assertThat(outcome(GET, "/api/machine/payments", Mono.empty())).isEqualTo(DENIED_WITHOUT_REASON);
        assertThat(outcome(GET, "/api/unknown/thing", Mono.empty())).isEqualTo(DENIED_WITHOUT_REASON);
    }

    private Object outcome(HttpMethod method, String path, Mono<Authentication> caller) {
        AuthorizationContext context = new AuthorizationContext(
                MockServerWebExchange.from(MockServerHttpRequest.method(method, path)));
        try {
            AuthorizationResult result = manager.authorize(caller, context).block();
            return result != null && result.isGranted() ? GRANTED : DENIED_WITHOUT_REASON;
        } catch (GatewayAccessDeniedException denied) {
            return denied.reason();
        }
    }

    private static Arguments row(HttpMethod method, String path, String callerName,
                                 Authentication caller, Object expected) {
        return Arguments.of(method, path, Named.of(callerName, caller), expected);
    }
}
```

- [ ] **Step 4: Run it to make sure it fails**

```bash
.\mvnw.cmd -o test -Dtest=RouteScopeAuthorizationManagerTest
```

Expected: compilation failure — `RouteScopeAuthorizationManager` does not exist.

- [ ] **Step 5: Write the manager**

`src/main/java/com/gatekeeper/authz/RouteScopeAuthorizationManager.java`:

```java
package com.gatekeeper.authz;

import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Optional;

import static org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers.anyExchange;
import static org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers.pathMatchers;

/**
 * What each route requires, and nothing else — the tenant check wraps this in {@link
 * TenantAuthorizationManager}. The table is the M4 design, section 4.
 *
 * <p><strong>The edge checks scope, the downstream checks permission.</strong> A scope is what
 * the client application was granted on the user's behalf; a permission is what the user may
 * do. Every rule here reads {@code SCOPE_*} authorities, which a JWT and an API key both carry
 * (M3 made the key's scopes the same shape), so one rule covers both credentials with no
 * branching on mechanism.
 *
 * <p><strong>Rules are evaluated in order; the first match decides.</strong> A rule inserted
 * above an overlapping one silently shadows it, which is why the test pins every row.
 *
 * <p><strong>Deny by default lives in this table</strong>, as its last rule, so that a route
 * added later without a rule fails closed with a reason of its own. Spring's delegating
 * wrapper has a fallback too — a plain {@code false} decision — but the last rule here matches
 * every exchange, so that fallback is never reached.
 *
 * <p><strong>A refusal is an error, not a {@code false} decision.</strong> See {@link
 * GatewayAccessDeniedException} for why that is the only way the reason reaches the handler.
 * The one plain {@code false} this class returns is for a caller with no authentication, who
 * is sent to the 401 entry point before any reason could be rendered.
 */
public class RouteScopeAuthorizationManager implements ReactiveAuthorizationManager<AuthorizationContext> {

    private static final AuthorizationResult GRANTED = new AuthorizationDecision(true);
    private static final AuthorizationResult UNAUTHENTICATED = new AuthorizationDecision(false);

    private static final List<Rule> RULES = List.of(
            new Rule(pathMatchers(HttpMethod.GET, "/actuator/info"), authenticated()),
            // Authenticated only, deliberately. AuthCore's real checks here depend on the
            // request's arguments (@PreAuthorize with #ownerId, hasRole), which a route rule
            // cannot see — and this is why authcore-accounts is a separate route from
            // authcore-machine: a scope rule attaches to the machine route without forcing a
            // hollow one onto this one.
            new Rule(pathMatchers("/api/accounts/**"), authenticated()),
            // Mirrors AuthCore's own URL rules for this route exactly: defence in depth.
            new Rule(pathMatchers(HttpMethod.GET, "/api/machine/**"), scope("payments:read")),
            new Rule(pathMatchers(HttpMethod.POST, "/api/machine/**"), scope("payments:write")),
            // ledger-service is a JWT-only resource server; a key caller could only ever get
            // its 401, so the key is refused here instead.
            new Rule(pathMatchers(HttpMethod.GET, "/api/ledger/**"), jwtWithScope("payments:read")),
            new Rule(pathMatchers(HttpMethod.POST, "/api/ledger/**"), jwtWithScope("payments:write")),
            new Rule(anyExchange(), refuse(Reason.NO_RULE)));

    @Override
    public Mono<AuthorizationResult> authorize(Mono<Authentication> authentication, AuthorizationContext context) {
        return firstRuleMatching(context.getExchange())
                .flatMap(rule -> authentication
                        .filter(Authentication::isAuthenticated)
                        .flatMap(caller -> decide(rule.requirement().refusal(caller)))
                        .switchIfEmpty(Mono.just(UNAUTHENTICATED)));
    }

    private static Mono<Rule> firstRuleMatching(ServerWebExchange exchange) {
        return Flux.fromIterable(RULES)
                .concatMap(rule -> rule.matcher().matches(exchange)
                        .filter(ServerWebExchangeMatcher.MatchResult::isMatch)
                        .map(match -> rule))
                .next();
    }

    private static Mono<AuthorizationResult> decide(Optional<Reason> refusal) {
        return refusal
                .<Mono<AuthorizationResult>>map(reason -> Mono.error(new GatewayAccessDeniedException(reason)))
                .orElseGet(() -> Mono.just(GRANTED));
    }

    private static Requirement authenticated() {
        return caller -> Optional.empty();
    }

    private static Requirement scope(String scope) {
        String authority = "SCOPE_" + scope;
        return caller -> caller.getAuthorities().stream()
                .anyMatch(granted -> authority.equals(granted.getAuthority()))
                ? Optional.empty()
                : Optional.of(Reason.MISSING_SCOPE);
    }

    /**
     * The credential type is checked before the scope. This chain authenticates exactly two
     * kinds of caller — a {@link JwtAuthenticationToken} or an API key — so anything that is
     * not a JWT here is a key.
     */
    private static Requirement jwtWithScope(String scope) {
        Requirement scopeRequirement = scope(scope);
        return caller -> caller instanceof JwtAuthenticationToken
                ? scopeRequirement.refusal(caller)
                : Optional.of(Reason.API_KEY_NOT_ACCEPTED);
    }

    private static Requirement refuse(Reason reason) {
        return caller -> Optional.of(reason);
    }

    private record Rule(ServerWebExchangeMatcher matcher, Requirement requirement) {
    }

    @FunctionalInterface
    private interface Requirement {
        /** Empty to grant; otherwise why the caller is refused. */
        Optional<Reason> refusal(Authentication caller);
    }
}
```

- [ ] **Step 6: Run the test to make sure it passes**

```bash
.\mvnw.cmd -o test -Dtest=RouteScopeAuthorizationManagerTest
```

Expected: PASS, 38 tests (36 table rows + 2).

- [ ] **Step 7: Make it fail on purpose, three ways**

Each is a temporary edit, reverted before the next.

1. Swap the two machine rules' scopes (`payments:read` on POST, `payments:write` on GET). Expected: seven of the eight machine GET/POST rows fail. The survivor is `GET` as `key[]`, which is refused for a missing scope either way.
2. Change the ledger rules from `jwtWithScope(...)` to `scope(...)`. Expected: `key[read]` on `GET` and `key[write]` on `POST` read `granted`, and `key[]` reads `MISSING_SCOPE` — three failures.
3. Move the `anyExchange()` rule to the top of the list. Expected: every `GRANTED` row fails. This is the ordering property the class Javadoc warns about.

- [ ] **Step 8: Commit**

Message file contents:

```
feat(M4): the route-to-scope rule table

Each route's requirement, evaluated in order, deny by default. Machine
mirrors AuthCore's own scope rules; ledger additionally refuses API
keys, which that JWT-only service could only ever answer with 401;
accounts stays authenticated-only because AuthCore's real checks there
depend on arguments no route rule can see.

The test pins every row with its specific reason, so a reordering or a
widened rule that changes any outcome fails.
```

```bash
git add src/main/java/com/gatekeeper/authz/RouteScopeAuthorizationManager.java src/test/java/com/gatekeeper/support/Principals.java src/test/java/com/gatekeeper/authz/RouteScopeAuthorizationManagerTest.java
git commit -F <message-file>
```

- [ ] **Step 9: Review, then merge**

As Task 1 Step 13, with branch `feature/m4-task-2`.

---

## Task 3: The tenant check

**Files:**
- Create: `src/main/java/com/gatekeeper/authz/TenantAuthorizationManager.java`
- Test: `src/test/java/com/gatekeeper/authz/TenantAuthorizationManagerTest.java`

- [ ] **Step 1: Branch**

```bash
git checkout master
git checkout -b feature/m4-task-3
```

- [ ] **Step 2: Write the failing test**

`src/test/java/com/gatekeeper/authz/TenantAuthorizationManagerTest.java`:

```java
package com.gatekeeper.authz;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import reactor.core.publisher.Mono;

import java.net.URI;

import static com.gatekeeper.support.Principals.apiKey;
import static com.gatekeeper.support.Principals.jwt;
import static com.gatekeeper.support.Principals.jwtInTenant;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * The M4 design, section 5: every tenant a request names must equal the token's own, a
 * request naming none passes, and a caller whose credential carries no tenant is never
 * checked.
 *
 * <p>The delegate here stands in for the rule table, so these tests are about the tenant
 * check alone.
 */
class TenantAuthorizationManagerTest {

    static final String GRANTED = "granted";
    static final String DENIED_WITHOUT_REASON = "denied without a reason";

    static final ReactiveAuthorizationManager<AuthorizationContext> GRANTING =
            (authentication, context) -> Mono.just(new AuthorizationDecision(true));

    private final TenantAuthorizationManager manager = new TenantAuthorizationManager(GRANTING);

    private final Authentication acmeUser = jwtInTenant("acme", "payments:read");

    // --- A request that names no tenant -------------------------------------------------

    @Test
    void passesARequestThatNamesNoTenant() {
        assertThat(outcome(acmeUser, request("/api/accounts/me"))).isEqualTo(GRANTED);
    }

    // --- The header ----------------------------------------------------------------------

    @Test
    void passesAHeaderNamingTheTokensOwnTenant() {
        assertThat(outcome(acmeUser, request("/api/accounts/me").header("X-Tenant", "acme")))
                .isEqualTo(GRANTED);
    }

    @Test
    void refusesAHeaderNamingAnotherTenant() {
        assertThat(outcome(acmeUser, request("/api/accounts/me").header("X-Tenant", "default")))
                .isEqualTo(Reason.TENANT_MISMATCH);
    }

    /** Header names are case-insensitive in HTTP; a check keyed on one spelling is bypassed. */
    @Test
    void readsTheHeaderWhateverItsNameCasing() {
        assertThat(outcome(acmeUser, request("/api/accounts/me").header("x-tenant", "default")))
                .isEqualTo(Reason.TENANT_MISMATCH);
    }

    /** Every value must match, not merely one of them. */
    @Test
    void refusesTwoHeadersWhenEitherNamesAnotherTenant() {
        assertThat(outcome(acmeUser, request("/api/accounts/me").header("X-Tenant", "acme", "default")))
                .isEqualTo(Reason.TENANT_MISMATCH);
    }

    /** Values are compared raw, never split, so a list cannot smuggle a second tenant past. */
    @Test
    void refusesACommaSeparatedValue() {
        assertThat(outcome(acmeUser, request("/api/accounts/me").header("X-Tenant", "acme,default")))
                .isEqualTo(Reason.TENANT_MISMATCH);
    }

    /** A blank value is a named tenant, and it is not the token's. Stricter than AuthCore. */
    @Test
    void refusesABlankValue() {
        assertThat(outcome(acmeUser, request("/api/accounts/me").header("X-Tenant", "")))
                .isEqualTo(Reason.TENANT_MISMATCH);
    }

    /** AuthCore compares with equals; so does the gateway. */
    @Test
    void comparesCaseSensitively() {
        assertThat(outcome(acmeUser, request("/api/accounts/me").header("X-Tenant", "ACME")))
                .isEqualTo(Reason.TENANT_MISMATCH);
    }

    // --- The query parameter -------------------------------------------------------------

    @Test
    void refusesAQueryParameterNamingAnotherTenant() {
        assertThat(outcome(acmeUser, request("/api/accounts/me?tenant=default")))
                .isEqualTo(Reason.TENANT_MISMATCH);
    }

    /**
     * {@code ac%6De} decodes to {@code acme}. Passing proves the check reads decoded values,
     * as AuthCore's {@code getParameter} does; comparing the raw text would refuse it.
     */
    @Test
    void comparesTheDecodedQueryValue() {
        assertThat(outcome(acmeUser, request("/api/accounts/me?tenant=ac%6De"))).isEqualTo(GRANTED);
    }

    /** {@code ?tenant} with no value still names a tenant — an empty one. */
    @Test
    void refusesAValuelessQueryParameter() {
        assertThat(outcome(acmeUser, request("/api/accounts/me?tenant")))
                .isEqualTo(Reason.TENANT_MISMATCH);
    }

    @Test
    void refusesWhenTheHeaderMatchesButTheQueryDoesNot() {
        assertThat(outcome(acmeUser, request("/api/accounts/me?tenant=default").header("X-Tenant", "acme")))
                .isEqualTo(Reason.TENANT_MISMATCH);
    }

    // --- Callers with no tenant ----------------------------------------------------------

    /**
     * A client-credentials token carries no tenant claim. AuthCore does not tenant-check it,
     * and neither does the gateway — the one rule for tenant-less principals that the M3
     * design's section 8 anticipated.
     */
    @Test
    void neverChecksATokenWithNoTenantClaim() {
        assertThat(outcome(jwt("payments:read"), request("/api/machine/payments?tenant=default")
                .header("X-Tenant", "acme"))).isEqualTo(GRANTED);
    }

    /** API keys are tenant-less by construction — the same rule, not a special case. */
    @Test
    void neverChecksAnApiKey() {
        assertThat(outcome(apiKey("payments:read"), request("/api/machine/payments")
                .header("X-Tenant", "default"))).isEqualTo(GRANTED);
    }

    // --- The rule table decides first ----------------------------------------------------

    /** A missing scope must read as a missing scope, never masked by a tenant message. */
    @Test
    void reportsTheTablesReasonWhenBothWouldRefuse() {
        TenantAuthorizationManager refusingScope = new TenantAuthorizationManager(
                (authentication, context) -> Mono.error(new GatewayAccessDeniedException(Reason.MISSING_SCOPE)));

        assertThat(outcome(refusingScope, acmeUser, request("/api/accounts/me").header("X-Tenant", "default")))
                .isEqualTo(Reason.MISSING_SCOPE);
    }

    /** A plain denial from the table — an unauthenticated caller — passes through unchanged. */
    @Test
    void passesAPlainDenialThroughUnchanged() {
        TenantAuthorizationManager denying = new TenantAuthorizationManager(
                (authentication, context) -> Mono.just(new AuthorizationDecision(false)));

        assertThat(outcome(denying, acmeUser, request("/api/accounts/me").header("X-Tenant", "default")))
                .isEqualTo(DENIED_WITHOUT_REASON);
    }

    // --- Helpers -------------------------------------------------------------------------

    /** Built from a URI so a percent-escape reaches the request exactly as written. */
    private static MockServerHttpRequest.BaseBuilder<?> request(String uri) {
        return MockServerHttpRequest.method(HttpMethod.GET, URI.create(uri));
    }

    private Object outcome(Authentication caller, MockServerHttpRequest.BaseBuilder<?> request) {
        return outcome(manager, caller, request);
    }

    private static Object outcome(TenantAuthorizationManager manager, Authentication caller,
                                  MockServerHttpRequest.BaseBuilder<?> request) {
        AuthorizationContext context = new AuthorizationContext(MockServerWebExchange.from(request));
        try {
            AuthorizationResult result = manager.authorize(Mono.just(caller), context).block();
            return result != null && result.isGranted() ? GRANTED : DENIED_WITHOUT_REASON;
        } catch (GatewayAccessDeniedException denied) {
            return denied.reason();
        }
    }
}
```

- [ ] **Step 3: Run it to make sure it fails**

```bash
.\mvnw.cmd -o test -Dtest=TenantAuthorizationManagerTest
```

Expected: compilation failure — `TenantAuthorizationManager` does not exist.

- [ ] **Step 4: Write the manager**

`src/main/java/com/gatekeeper/authz/TenantAuthorizationManager.java`:

```java
package com.gatekeeper.authz;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.stream.Stream;

/**
 * Refuses a request that names a tenant other than the token's. The M4 design, section 5.
 *
 * <p>No routed path carries a tenant. What a request <em>can</em> name is the tenant AuthCore
 * resolves it against: the {@code X-Tenant} header, or the {@code tenant} request parameter.
 * Every value of either must equal the token's {@code tenant} claim exactly — case-sensitive,
 * compared raw and never split, a blank counting as a name. A request naming no tenant passes.
 * This is stricter than AuthCore where it acts, and it needs to know neither which tenants
 * exist nor the order AuthCore consults its sources in.
 *
 * <p>Mirrors AuthCore's class of the same name: the wrapped rule decides first, and a caller
 * with no tenant claim — a client-credentials token, or any API key — is never checked. That
 * is the single rule for tenant-less principals the M3 design's section 8 anticipated.
 *
 * <p><strong>Deliberately not inspected:</strong> the subdomain, because the gateway does not
 * forward the client's {@code Host}; and the request body, which AuthCore's {@code
 * getParameter} would also read for a form POST. A tenant named in a form body passes here and
 * is refused by AuthCore's own check. This is defence in depth; AuthCore stays the authority.
 */
public class TenantAuthorizationManager implements ReactiveAuthorizationManager<AuthorizationContext> {

    static final String TENANT_HEADER = "X-Tenant";
    static final String TENANT_PARAMETER = "tenant";
    private static final String TENANT_CLAIM = "tenant";

    private final ReactiveAuthorizationManager<AuthorizationContext> delegate;

    public TenantAuthorizationManager(ReactiveAuthorizationManager<AuthorizationContext> delegate) {
        this.delegate = delegate;
    }

    @Override
    public Mono<AuthorizationResult> authorize(Mono<Authentication> authentication, AuthorizationContext context) {
        return delegate.authorize(authentication, context)
                .flatMap(result -> result.isGranted()
                        ? tenantChecked(result, authentication, context.getExchange().getRequest())
                        : Mono.just(result));
    }

    private static Mono<AuthorizationResult> tenantChecked(
            AuthorizationResult granted, Mono<Authentication> authentication, ServerHttpRequest request) {
        return authentication
                .mapNotNull(TenantAuthorizationManager::tenantClaimOf)
                .flatMap(tenant -> namedTenants(request).allMatch(tenant::equals)
                        ? Mono.just(granted)
                        : Mono.<AuthorizationResult>error(new GatewayAccessDeniedException(Reason.TENANT_MISMATCH)))
                .defaultIfEmpty(granted);
    }

    private static String tenantClaimOf(Authentication authentication) {
        return authentication instanceof JwtAuthenticationToken jwt
                ? jwt.getToken().getClaimAsString(TENANT_CLAIM)
                : null;
    }

    /**
     * Query values arrive decoded, as AuthCore's {@code getParameter} sees them. A valueless
     * {@code ?tenant} yields a {@code null}, which equals no tenant and is therefore refused.
     */
    private static Stream<String> namedTenants(ServerHttpRequest request) {
        return Stream.concat(
                request.getHeaders().getOrEmpty(TENANT_HEADER).stream(),
                request.getQueryParams().getOrDefault(TENANT_PARAMETER, List.of()).stream());
    }
}
```

- [ ] **Step 5: Run the test to make sure it passes**

```bash
.\mvnw.cmd -o test -Dtest=TenantAuthorizationManagerTest
```

Expected: PASS, 16 tests.

If `refusesAValuelessQueryParameter` fails because `getQueryParams()` drops a valueless parameter rather than yielding `null`, **stop and report it** — do not delete the test. It would mean `?tenant` is invisible to the gateway, and the design must say whether that matters (AuthCore's `getParameter` returns `""` for it, which names no existing tenant and falls through to `default`).

- [ ] **Step 6: Make it fail on purpose, three ways**

Each is a temporary edit, reverted before the next.

1. In `namedTenants`, return only the header stream. Expected: the three query tests that expect a refusal fail.
2. Replace `tenant::equals` with `tenant::equalsIgnoreCase`. Expected: `comparesCaseSensitively` fails.
3. In `authorize`, call `tenantChecked` whatever the delegate returned — change the ternary to always take the first branch. Expected: `passesAPlainDenialThroughUnchanged` fails, reading `TENANT_MISMATCH`. The table's plain denial, the one that sends an unauthenticated caller to the 401, has been replaced by a reasoned 403.

- [ ] **Step 7: Commit**

Message file contents:

```
feat(M4): refuse a request that names another tenant

Every tenant named in X-Tenant or the tenant query parameter must equal
the token's own claim; a request naming none passes, and a caller with
no tenant claim, token or key, is never checked. The wrapped rule table
decides first, so a missing scope is never reported as a tenant problem.

Stricter than AuthCore where it acts, without copying AuthCore's
resolution order or its fallback to the default tenant.
```

```bash
git add src/main/java/com/gatekeeper/authz/TenantAuthorizationManager.java src/test/java/com/gatekeeper/authz/TenantAuthorizationManagerTest.java
git commit -F <message-file>
```

- [ ] **Step 8: Review, then merge**

As Task 1 Step 13, with branch `feature/m4-task-3`.

---

## Task 4: Wire it in, end to end

This is the task that changes behaviour, so it is the one where existing tests break. **Every change to an existing test is inspected individually**: a test gaining a scope so it can keep asserting the same thing is correct; a test whose assertion is weakened is not. The list in Step 6 is complete — a failure not on it is a finding, not something to patch.

**Files:**
- Test: `src/test/java/com/gatekeeper/authz/AuthorizationTest.java`
- Modify: `src/main/java/com/gatekeeper/config/GatewaySecurityConfig.java`
- Modify: `src/main/resources/application.yml`
- Modify: `src/test/java/com/gatekeeper/routing/RoutingTest.java`
- Modify: `src/test/java/com/gatekeeper/auth/JwtAuthenticationTest.java`
- Modify: `src/test/java/com/gatekeeper/auth/KeyRotationTest.java`
- Modify: `src/test/java/com/gatekeeper/error/ErrorShapeTest.java`
- Modify: `src/test/java/com/gatekeeper/identity/IdentityPropagationTest.java`
- Modify: `src/test/java/com/gatekeeper/apikey/ApiKeyAuthenticationTest.java`

- [ ] **Step 1: Branch, and start Redis**

```bash
git checkout master
git checkout -b feature/m4-task-4
```

From the authcore directory: `docker compose up -d redis`.

- [ ] **Step 2: Write the failing integration test**

`src/test/java/com/gatekeeper/authz/AuthorizationTest.java`:

```java
package com.gatekeeper.authz;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.gatekeeper.apikey.ApiKeyAuthenticationConverter;
import com.gatekeeper.support.TestKey;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
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
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * The M4 allow/deny matrix through the real chain: the rule table, the tenant check, the 403
 * handler, and the ledger route's header filter.
 *
 * <p><strong>Every 403 here also asserts the downstream received nothing.</strong> A 403 that
 * forwarded the request anyway would be worse than no check at all. The catch-all stub answers
 * 200 for every downstream path, so a request that leaked would show up twice: as the wrong
 * status, and in the request log.
 *
 * <p>API keys are fresh per test, for the reason {@code ApiKeyAuthenticationTest} gives:
 * Redis persists between tests, so a fixed key would let one test's cached answer decide
 * another's outcome.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class AuthorizationTest {

    static final String ISSUER = "http://localhost:8080";
    static final String INTROSPECT_PATH = "/api/internal/api-keys/introspect";

    static WireMockServer downstream;
    static TestKey signingKey;

    @Autowired
    WebTestClient client;

    @BeforeAll
    static void start() {
        signingKey = TestKey.generate("k1");
        downstream = new WireMockServer(options().dynamicPort());
        downstream.start();
        downstream.stubFor(get(urlEqualTo("/oauth2/jwks"))
                .willReturn(okJson(TestKey.jwksDocument(signingKey))));
        // Any key this class never marked active reads as inactive.
        downstream.stubFor(post(urlEqualTo(INTROSPECT_PATH))
                .atPriority(10)
                .willReturn(okJson("""
                        {"active":false}""")));
        // Every other downstream path, any method: 200. Lowest priority.
        downstream.stubFor(any(anyUrl())
                .atPriority(20)
                .willReturn(okJson("{}")));
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
        registry.add("gatekeeper.api-key.introspection-uri", () -> downstream.baseUrl() + INTROSPECT_PATH);
    }

    // --- The plan's acceptance criteria -------------------------------------------------

    @Test
    void refusesALedgerWriteWithoutTheWriteScope() {
        expectForbidden(client.post().uri("/api/ledger/entries")
                        .header(HttpHeaders.AUTHORIZATION, bearer("acme", "payments:read"))
                        .exchange(),
                "/api/ledger/entries", Reason.MISSING_SCOPE);

        assertThat(downstream.findAll(anyRequestedFor(urlPathEqualTo("/ledger/entries")))).isEmpty();
    }

    @Test
    void proxiesALedgerWriteWithTheWriteScope() {
        client.post().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, bearer("acme", "payments:write"))
                .exchange()
                .expectStatus().isOk();

        assertThat(downstream.findAll(postRequestedFor(urlEqualTo("/ledger/entries")))).hasSize(1);
    }

    @Test
    void refusesARequestNamingAnotherTenantInTheHeader() {
        expectForbidden(client.get().uri("/api/accounts/me")
                        .header(HttpHeaders.AUTHORIZATION, bearer("acme"))
                        .header("X-Tenant", "default")
                        .exchange(),
                "/api/accounts/me", Reason.TENANT_MISMATCH);

        assertThat(downstream.findAll(anyRequestedFor(urlPathEqualTo("/api/accounts/me")))).isEmpty();
    }

    @Test
    void refusesARequestNamingAnotherTenantInTheQuery() {
        expectForbidden(client.get().uri("/api/accounts/me?tenant=default")
                        .header(HttpHeaders.AUTHORIZATION, bearer("acme"))
                        .exchange(),
                "/api/accounts/me", Reason.TENANT_MISMATCH);

        assertThat(downstream.findAll(anyRequestedFor(urlPathEqualTo("/api/accounts/me")))).isEmpty();
    }

    @Test
    void proxiesARequestNamingTheTokensOwnTenant() {
        client.get().uri("/api/accounts/me")
                .header(HttpHeaders.AUTHORIZATION, bearer("acme"))
                .header("X-Tenant", "acme")
                .exchange()
                .expectStatus().isOk();

        assertThat(downstream.findAll(getRequestedFor(urlEqualTo("/api/accounts/me")))).hasSize(1);
    }

    /** A client-credentials token has no tenant claim, so naming one is not checked. */
    @Test
    void proxiesATenantlessTokenWhateverTenantItNames() {
        client.get().uri("/api/machine/payments")
                .header(HttpHeaders.AUTHORIZATION, bearer(null, "payments:read"))
                .header("X-Tenant", "default")
                .exchange()
                .expectStatus().isOk();
    }

    // --- API keys --------------------------------------------------------------------------

    /** The 403 shape for a key caller — the same single wiring as for a bearer caller. */
    @Test
    void refusesAnApiKeyOnTheLedgerRoute() {
        String rawKey = stubActiveKey("payments:read");

        expectForbidden(client.get().uri("/api/ledger/entries")
                        .header(ApiKeyAuthenticationConverter.HEADER_NAME, rawKey)
                        .exchange(),
                "/api/ledger/entries", Reason.API_KEY_NOT_ACCEPTED);

        assertThat(downstream.findAll(anyRequestedFor(urlPathEqualTo("/ledger/entries")))).isEmpty();
    }

    @Test
    void refusesAnApiKeyWithoutTheWriteScopeOnAMachineWrite() {
        String rawKey = stubActiveKey("payments:read");

        expectForbidden(client.post().uri("/api/machine/payments")
                        .header(ApiKeyAuthenticationConverter.HEADER_NAME, rawKey)
                        .exchange(),
                "/api/machine/payments", Reason.MISSING_SCOPE);

        assertThat(downstream.findAll(anyRequestedFor(urlPathEqualTo("/api/machine/payments")))).isEmpty();
    }

    /**
     * The machine route is where a key works end to end — and AuthCore re-authenticates the
     * key itself, so the header must still reach it. Guards against the ledger route's
     * header filter being applied more widely than the one route.
     */
    @Test
    void proxiesAnApiKeyOnTheMachineRouteWithTheKeyStillAttached() {
        String rawKey = stubActiveKey("payments:read");

        client.get().uri("/api/machine/payments")
                .header(ApiKeyAuthenticationConverter.HEADER_NAME, rawKey)
                .exchange()
                .expectStatus().isOk();

        downstream.verify(getRequestedFor(urlEqualTo("/api/machine/payments"))
                .withHeader(ApiKeyAuthenticationConverter.HEADER_NAME, equalTo(rawKey)));
    }

    /**
     * A blank X-API-Key rides the JWT path (M3's precedence rules), so it would otherwise be
     * forwarded to a service that can do nothing with it. The M3 item deferred to M4.
     */
    @Test
    void doesNotForwardAnApiKeyHeaderToTheLedger() {
        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, bearer("acme", "payments:read"))
                .header(ApiKeyAuthenticationConverter.HEADER_NAME, "")
                .exchange()
                .expectStatus().isOk();

        downstream.verify(getRequestedFor(urlEqualTo("/ledger/entries"))
                .withoutHeader(ApiKeyAuthenticationConverter.HEADER_NAME));
    }

    // --- Deny by default -------------------------------------------------------------------

    @Test
    void refusesAnAuthenticatedCallerOnAPathNoRuleCovers() {
        expectForbidden(client.get().uri("/api/unknown/thing")
                        .header(HttpHeaders.AUTHORIZATION, bearer("acme", "payments:read", "payments:write"))
                        .exchange(),
                "/api/unknown/thing", Reason.NO_RULE);
    }

    @Test
    void refusesAMethodTheLedgerDoesNotServe() {
        expectForbidden(client.delete().uri("/api/ledger/entries")
                        .header(HttpHeaders.AUTHORIZATION, bearer("acme", "payments:read", "payments:write"))
                        .exchange(),
                "/api/ledger/entries", Reason.NO_RULE);

        assertThat(downstream.findAll(anyRequestedFor(urlPathEqualTo("/ledger/entries")))).isEmpty();
    }

    /** No credential is still 401, not 403 — whichever rule the path matches. */
    @Test
    void stillAnswersAnAnonymousCallerWith401() {
        client.get().uri("/api/unknown/thing")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().valueMatches(HttpHeaders.WWW_AUTHENTICATE, "Bearer.*")
                .expectBody()
                .jsonPath("$.error").isEqualTo("unauthorized")
                .jsonPath("$.detail").doesNotExist();
    }

    // --- Helpers ---------------------------------------------------------------------------

    private static void expectForbidden(WebTestClient.ResponseSpec response, String path, Reason reason) {
        response.expectStatus().isForbidden()
                .expectHeader().doesNotExist(HttpHeaders.WWW_AUTHENTICATE)
                .expectBody()
                .jsonPath("$.error").isEqualTo("forbidden")
                .jsonPath("$.status").isEqualTo(403)
                .jsonPath("$.path").isEqualTo(path)
                .jsonPath("$.detail").isEqualTo(reason.detail());
    }

    /** A bearer token in {@code tenant}, or with no tenant claim when {@code tenant} is null. */
    private static String bearer(String tenant, String... scopes) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("scope", List.of(scopes));
        if (tenant != null) {
            claims.put("tenant", tenant);
        }
        return "Bearer " + signingKey.mint(ISSUER, "ezzat", Instant.now().plus(5, ChronoUnit.MINUTES), claims);
    }

    /** Registers a fresh key as active with the given scopes, and returns it. */
    private static String stubActiveKey(String... scopes) {
        String rawKey = "ak_test_" + UUID.randomUUID();
        String scopeList = String.join("\",\"", scopes);
        downstream.stubFor(post(urlEqualTo(INTROSPECT_PATH))
                .atPriority(1)
                .withRequestBody(equalToJson("{\"key\":\"" + rawKey + "\"}"))
                .willReturn(okJson("""
                        {"active":true,"name":"reporting","scopes":["%s"],"expiresAt":"%s"}"""
                        .formatted(scopeList, Instant.now().plus(1, ChronoUnit.HOURS)))));
        return rawKey;
    }
}
```

- [ ] **Step 3: Run it to make sure it fails**

```bash
.\mvnw.cmd -o test -Dtest=AuthorizationTest
```

Expected: FAIL. Every `expectForbidden` test fails, reading `200` instead of `403`, because nothing is wired yet. `doesNotForwardAnApiKeyHeaderToTheLedger` fails too, because the blank header reaches ledger. The `isOk` and 401 tests pass already.

**If `doesNotForwardAnApiKeyHeaderToTheLedger` passes here, stop and report it.** It would mean the blank header is already being dropped before it reaches ledger, so the test cannot prove the filter. The premise of the M4 design's section 6 would then be wrong and must be corrected there before continuing.

- [ ] **Step 4: Wire the managers and the handler**

In `src/main/java/com/gatekeeper/config/GatewaySecurityConfig.java`:

Add imports:

```java
import com.gatekeeper.authz.RouteScopeAuthorizationManager;
import com.gatekeeper.authz.TenantAuthorizationManager;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
```

Replace the second paragraph of the class Javadoc (`<p>Only authentication is decided here. Route-level authorization is M4; mixing the two now would bury the route rules inside this method later.`) with:

```java
 * <p>Authentication is decided by the two filters configured below. Authorization is
 * decided by {@link RouteScopeAuthorizationManager}, wrapped in {@link
 * TenantAuthorizationManager} — in {@code com.gatekeeper.authz}, so the route rules live in a
 * class of their own rather than inside this method.
 *
 * <p>The access-denied handler is set once, on {@code exceptionHandling}, and that one
 * setting covers bearer and key callers alike: {@code ServerHttpSecurity} consults the
 * resource server's own bearer handler only when no explicit handler is configured (verified
 * in the 7.0.6 bytecode). Setting it on {@code oauth2ResourceServer} as well would be dead
 * configuration.
```

Change the `securityWebFilterChain` signature and body to:

```java
    @Bean
    public SecurityWebFilterChain securityWebFilterChain(
            ServerHttpSecurity http, ReactiveJwtDecoder jwtDecoder,
            ServerAuthenticationEntryPoint authenticationEntryPoint,
            ServerAccessDeniedHandler accessDeniedHandler,
            ApiKeyReactiveAuthenticationManager apiKeyAuthenticationManager) {

        return http
                // A credential arrives on every request, so a session would add server state
                // and CSRF exposure for nothing.
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .authorizeExchange(exchange -> exchange
                        .pathMatchers("/actuator/health", "/actuator/health/**").permitAll()
                        .anyExchange().access(
                                new TenantAuthorizationManager(new RouteScopeAuthorizationManager())))
                .exceptionHandling(handling -> handling.accessDeniedHandler(accessDeniedHandler))
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .bearerTokenConverter(bearerConverterDeferringToApiKey())
                        .jwt(jwt -> jwt.jwtDecoder(jwtDecoder)))
                .addFilterAt(apiKeyAuthenticationWebFilter(apiKeyAuthenticationManager, authenticationEntryPoint),
                        SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }
```

In the Javadoc of `apiKeyAuthenticationWebFilter`, the sentence `so a key-authenticated request satisfies {@code anyExchange() .authenticated()}` becomes `so a key-authenticated request is authenticated by the time the rule table runs`.

- [ ] **Step 5: Stop forwarding `X-API-Key` to ledger**

In `src/main/resources/application.yml`, the ledger route becomes:

```yaml
            - id: ledger
              uri: ${gatekeeper.downstream.ledger}
              predicates:
                - Path=/api/ledger/**
              filters:
                - StripPrefix=1
                # ledger-service is JWT-only, and a key caller is refused before reaching it
                # (RouteScopeAuthorizationManager). What remains is a JWT caller sending a
                # blank X-API-Key, which would otherwise be forwarded to a service that can do
                # nothing with it. The AuthCore routes keep the header: AuthCore
                # re-authenticates the key itself.
                - RemoveRequestHeader=X-API-Key
```

- [ ] **Step 6: Run the new test, then the whole suite**

```bash
.\mvnw.cmd -o test -Dtest=AuthorizationTest
```

Expected: PASS, 13 tests.

```bash
.\mvnw.cmd -o test
```

Expected: FAIL. These failures, and only these, are expected, each because the caller now needs a scope or is now a key on the ledger route:

| Class | Tests | Why |
|---|---|---|
| `RoutingTest` | three of four — not the accounts test, which needs no scope | tokens carry no scope; the unmatched path now answers 403 |
| `JwtAuthenticationTest` | `proxiesARequestWithAValidToken` | no scope |
| `KeyRotationTest` | all three | no scope |
| `ErrorShapeTest` | `rendersAClaimWithAControlCharacterAsUnauthorizedNotServerError` | no scope, so 403 before the header is ever forwarded |
| `IdentityPropagationTest` | all seven | no scope; the two key tests hit the ledger route |
| `ApiKeyAuthenticationTest` | the six that expect a 200 from the ledger route — not the health-probe test | tokens carry no scope, and keys hit the ledger route |

**Any other failure is a finding.** Stop and report it rather than editing the test.

- [ ] **Step 7: `RoutingTest` — scopes, and the unmatched path**

Add `import java.util.List;` and `import static com.github.tomakehurst.wiremock.client.WireMock.anyRequestedFor;`.

`bearerToken()` becomes:

```java
    private static String bearerToken() {
        return "Bearer " + key.mint("http://localhost:8080", "ezzat",
                Instant.now().plus(5, ChronoUnit.MINUTES),
                Map.of("tenant", "acme", "scope", List.of("payments:read")));
    }
```

`doesNotRouteAnUnmatchedPath` is an intended behaviour change — an unrouted path used to reach routing and 404; it is now refused before routing. Replace it with:

```java
    /**
     * A path matching no route is refused before routing ever runs: the rule table denies by
     * default (M4). It used to reach routing and answer 404; either way, no downstream sees it.
     */
    @Test
    void refusesAnUnmatchedPathBeforeRouting() {
        client.get().uri("/api/unknown/thing")
                .header(HttpHeaders.AUTHORIZATION, bearerToken())
                .exchange().expectStatus().isForbidden();
        downstream.verify(0, anyRequestedFor(urlEqualTo("/api/unknown/thing")));
    }
```

Update the class Javadoc's first sentence to: `The gateway authenticates and authorizes every request, so these assertions carry a valid bearer token with the scope each route requires, and are purely about whether a permitted request reaches the right downstream at the right path.`

- [ ] **Step 8: `JwtAuthenticationTest` — one scope**

In `proxiesARequestWithAValidToken`, the claims become `Map.of("tenant", "acme", "permissions", List.of("payments:read"), "scope", List.of("payments:read"))`.

Replace the class Javadoc with:

```java
/**
 * Answers exactly one question: is this a valid, unexpired token from AuthCore. Whether the
 * caller may reach a particular route is {@code AuthorizationTest}'s; the one success case
 * here carries the scope the ledger route requires so that it can keep asserting only
 * authentication.
 */
```

- [ ] **Step 9: `KeyRotationTest` — one scope**

Add `import java.util.List;`. In `callWith`, the claims become `Map.of("tenant", "acme", "scope", List.of("payments:read"))`.

- [ ] **Step 10: `ErrorShapeTest` — one scope, so the header still reaches Netty**

In `rendersAClaimWithAControlCharacterAsUnauthorizedNotServerError`, the claims become:

```java
                Map.of("tenant", "acme", "scope", List.of("payments:read"),
                        "permissions", List.of("evil\r\nX-Injected: yes")));
```

Without the scope, the request is refused 403 before `NettyRoutingFilter` ever sees the header, and the test would stop testing what its Javadoc says. It must still expect 401.

- [ ] **Step 11: `IdentityPropagationTest` — scopes, and keys off the ledger route**

Add a stub in `start()`, after the ledger stub:

```java
        downstream.stubFor(get(urlEqualTo("/api/machine/payments"))
                .willReturn(aResponse().withStatus(200).withBody("[]")));
```

`tokenFor` becomes:

```java
    private static String tokenFor(String subject, String tenant, List<String> permissions) {
        return activeKey.mint(ISSUER, subject, Instant.now().plus(5, ChronoUnit.MINUTES),
                Map.of("tenant", tenant, "permissions", permissions, "scope", List.of("payments:read")));
    }
```

In `omitsHeadersForClaimsTheTokenDoesNotCarry` and `stripsASpoofedHeaderTheStampFilterWouldNotOverwrite`, the machine token's claims change from `Map.of()` to `Map.of("scope", List.of("payments:read"))`. A client-credentials token always carries its scopes; it is `tenant` and `permissions` it lacks, which is what those tests are about.

In `stampsTheSubjectForAnApiKeyCaller` and `stampsNoTenantForAnApiKeyCaller`, replace `"/api/ledger/entries"` with `"/api/machine/payments"` in the request, and `urlEqualTo("/ledger/entries")` with `urlEqualTo("/api/machine/payments")` in the verification. The machine route is where a key caller reaches a downstream at all now.

- [ ] **Step 12: `ApiKeyAuthenticationTest` — scopes, and keys off the ledger route**

This class is about authentication precedence. The route it runs over was incidental, and a key caller is now refused on ledger, so the class moves to the machine route, where both credential types are permitted.

- Rename the constant: `static final String MACHINE_PATH = "/api/machine/payments";` replacing `LEDGER_PATH`, and every use of `LEDGER_PATH` with `MACHINE_PATH`.
- In `startFakeAuthCore()`, the stub `get(urlEqualTo("/ledger/entries"))` becomes `get(urlEqualTo(MACHINE_PATH))`.
- In `authenticatesAsTheKeyWhenAValidTokenIsAlsoPresent`, `getRequestedFor(urlEqualTo("/ledger/entries"))` becomes `getRequestedFor(urlEqualTo(MACHINE_PATH))`.
- In `proxiesARequestWithOnlyAValidToken` and `authenticatesViaTheTokenWhenTheKeyHeaderIsBlank`, add `"scope", List.of("payments:read")` to the claims map. The other tokens in this class stay as they are: in every other test the key decides and the token is never consulted.
- In the class Javadoc, the sentence `route-level authorization is still M4 — so a 200 here means only "the gateway's own security chain let the request through," never "the credential was appropriate for the route."` becomes `every credential here carries payments:read, which is what GET on the machine route requires — so a 200 means the gateway authenticated the caller as the credential the precedence table says should win.`

- [ ] **Step 13: Run the whole suite**

```bash
.\mvnw.cmd -o test
```

Expected: PASS, 143 tests (76 after Task 1, + 38 + 16 unit, + 13 integration; the edited classes keep their counts). Record the actual number: Task 7 puts it in the README and the handoff.

- [ ] **Step 14: Commit**

Message file contents:

```
feat(M4): authorize every route at the edge, deny by default

Plugs the rule table and the tenant check into the chain and renders
every refusal through the JSON access-denied handler. Set once, on
exceptionHandling, the handler covers bearer and key callers alike;
the resource server's own bearer handler is consulted only when no
explicit one is configured.

The ledger route stops forwarding X-API-Key, the item M3 deferred.
Existing tests gain the scope their route now requires, and the API-key
precedence and stamping tests move to the machine route, where a key
caller can still reach a downstream. None of their assertions changed.
```

```bash
git add src/main src/test
git commit -F <message-file>
```

- [ ] **Step 15: Review, then merge**

As Task 1 Step 13, with branch `feature/m4-task-4`. Both reviewers get the Step 6 table and check every edit to an existing test against it: a scope added or a path moved is correct, and anything else is a finding.

---

## Task 5: Prove the tests actually test something

The M2 anti-spoofing suite passed with its filter deleted. That is why this task is routine. Each mutation is a temporary edit on `master` after Task 4's merge, never committed, reverted with `git checkout -- <file>` before the next.

- [ ] **Step 1: Remove the tenant wrapper**

In `GatewaySecurityConfig`, `.access(new TenantAuthorizationManager(new RouteScopeAuthorizationManager()))` → `.access(new RouteScopeAuthorizationManager())`.

```bash
.\mvnw.cmd -o test -Dtest=AuthorizationTest
```

Expected: `refusesARequestNamingAnotherTenantInTheHeader` and `refusesARequestNamingAnotherTenantInTheQuery` fail. Revert.

- [ ] **Step 2: Let API keys onto the ledger route**

In `RouteScopeAuthorizationManager`, both ledger rules: `jwtWithScope(...)` → `scope(...)`.

```bash
.\mvnw.cmd -o test -Dtest=AuthorizationTest
```

Expected: `refusesAnApiKeyOnTheLedgerRoute` fails. Revert.

- [ ] **Step 3: Replace deny-by-default with authenticated**

In `RouteScopeAuthorizationManager`, `new Rule(anyExchange(), refuse(Reason.NO_RULE))` → `new Rule(anyExchange(), authenticated())`.

```bash
.\mvnw.cmd -o test -Dtest="AuthorizationTest,RoutingTest"
```

Expected: `refusesAnAuthenticatedCallerOnAPathNoRuleCovers`, `refusesAMethodTheLedgerDoesNotServe` and `RoutingTest.refusesAnUnmatchedPathBeforeRouting` fail. Revert.

- [ ] **Step 4: Remove the access-denied wiring**

In `GatewaySecurityConfig`, delete `.exceptionHandling(handling -> handling.accessDeniedHandler(accessDeniedHandler))`.

```bash
.\mvnw.cmd -o test -Dtest=AuthorizationTest
```

Expected: every `expectForbidden` test fails — the JWT ones *and* the key ones — on the missing `detail` or a present `WWW-Authenticate`. **If only the JWT ones fail, or only the key ones, stop:** the single-wiring claim in the design's section 7 is wrong. Revert.

- [ ] **Step 5: Forward `X-API-Key` to ledger again**

In `application.yml`, delete the `- RemoveRequestHeader=X-API-Key` line.

```bash
.\mvnw.cmd -o test -Dtest=AuthorizationTest
```

Expected: `doesNotForwardAnApiKeyHeaderToTheLedger` fails. Revert.

- [ ] **Step 6: Read only the header for the tenant**

In `TenantAuthorizationManager.namedTenants`, return only `request.getHeaders().getOrEmpty(TENANT_HEADER).stream()`.

```bash
.\mvnw.cmd -o test -Dtest="AuthorizationTest,TenantAuthorizationManagerTest"
```

Expected: `refusesARequestNamingAnotherTenantInTheQuery` fails, along with the query tests in the unit class. Revert.

- [ ] **Step 7: Confirm the tree is clean**

```bash
git status --short
```

Expected: no output. Any mutation that did not fail its named test is a finding. Record it, fix the test in its own task branch, and rerun that mutation.

---

## Task 6: Run it against the real thing

Reading a diff did not catch the cross-tenant leak, the missing `WWW-Authenticate`, or the unreachable 403 branch in M0–M2. Booting the services did.

- [ ] **Step 1: Start everything**

From the authcore directory: `docker compose up -d postgres redis`. Then, each in its own terminal: AuthCore, ledger-service, and GateKeeper, each with `.\mvnw.cmd -o spring-boot:run` from its own directory.

- [ ] **Step 2: Obtain the three tokens**

**Machine token (`authcore-machine`, both scopes, no tenant):**

```bash
curl.exe -s -u authcore-machine:machine-secret -d "grant_type=client_credentials&scope=payments:read%20payments:write" http://localhost:8080/oauth2/token
```

**Read-only `acme` user (`authcore-spa`, `payments:read` only).** In a private browser window, log in as `ezzat` / `acme-password`:

```
http://localhost:8080/oauth2/authorize?response_type=code&client_id=authcore-spa&redirect_uri=http://127.0.0.1:8080/authorized&scope=openid%20payments:read&code_challenge=jOE5exqeFE_I-Pd0J6sXoCuGr4fI1i-07DziFgujcnQ&code_challenge_method=S256&tenant=acme
```

```bash
curl.exe -s -X POST http://localhost:8080/oauth2/token -d "grant_type=authorization_code&client_id=authcore-spa&code=PASTE_CODE&redirect_uri=http://127.0.0.1:8080/authorized&code_verifier=authcore-test-code-verifier-minimum-43-chars-00"
```

**Writing `acme` admin (`authcore-client`, both scopes).** In a new private window, log in as `alice` / `alice-password` and grant both scopes on the consent screen:

```
http://localhost:8080/oauth2/authorize?response_type=code&client_id=authcore-client&redirect_uri=http://127.0.0.1:8080/authorized&scope=openid%20payments:read%20payments:write&tenant=acme
```

```bash
curl.exe -s -u authcore-client:secret -X POST http://localhost:8080/oauth2/token -d "grant_type=authorization_code&code=PASTE_CODE&redirect_uri=http://127.0.0.1:8080/authorized"
```

Use `localhost` for every token call, never `127.0.0.1` — the gateway pins the issuer, and a token issued at `127.0.0.1` is refused 401.

- [ ] **Step 3: Drive the matrix**

`MACHINE`, `SPA` and `ALICE` are the three access tokens from Step 2. Every call goes to the gateway on `:8081`. For each 403, note from the body which service answered: the gateway's carries `detail`, and AuthCore's and ledger's do not, or carry a different one.

| # | Request | Expected |
|---|---|---|
| 1 | `-H "X-API-Key: ak_demo_reporting_job_local_only_0000000000"` `GET /api/machine/payments` | `200` |
| 2 | same key, `-X POST /api/machine/payments` | `403` from the gateway, `MISSING_SCOPE` detail |
| 3 | same key, `GET /api/ledger/entries` | `403` from the gateway, `API_KEY_NOT_ACCEPTED` detail |
| 4 | `MACHINE`, `-X POST /api/ledger/entries` with a JSON body `{"reference":"LDG-9001","amount":10,"currency":"EUR"}` | passes the edge; `403` **from ledger** (no permissions) |
| 5 | `ALICE`, same POST | `201` |
| 6 | `SPA`, same POST | `403` from the gateway, `MISSING_SCOPE` — the SPA client was never granted write |
| 7 | `SPA`, `GET /api/ledger/entries` | `200`, `LDG-1001` and `LDG-1002` only |
| 8 | `SPA`, `-H "X-Tenant: default"` `GET /api/accounts/me` | `403` from the gateway, `TENANT_MISMATCH` |
| 9 | `SPA`, `-H "X-Tenant: acme"` `GET /api/accounts/me` | `200` from AuthCore |
| 10 | `SPA`, `GET /api/unknown` | `403` from the gateway, `NO_RULE` |
| 11 | no credential, `GET /api/unknown` | `401`, `WWW-Authenticate: Bearer` |

Call 4 needs `-H "Content-Type: application/json"` and `-d` with the body. On Windows, write the body to a file and pass `-d @body.json`, which avoids quoting trouble.

- [ ] **Step 4: Settle the two assumptions in the design's section 5**

**The client's `Host` does not reach AuthCore.**

```bash
curl.exe -i -H "Authorization: Bearer SPA" -H "X-Tenant: acme" -H "Host: default.localhost:8081" http://localhost:8081/api/accounts/me
```

Expected: `200`. AuthCore resolves the subdomain *before* `X-Tenant`, so if the gateway forwarded this `Host`, AuthCore would resolve `default` and answer `403`. A `403` here means the gateway preserves `Host`, and the subdomain is a tenant source the gateway fails to check. **Stop and report it.**

**A tenant in a form body passes the edge and is refused by AuthCore.**

```bash
curl.exe -i -H "Authorization: Bearer ALICE" -H "Content-Type: application/x-www-form-urlencoded" -d "tenant=default" http://localhost:8081/api/accounts/alice/payments
```

Expected: `403` from **AuthCore**, not the gateway — the body carries no gateway `detail`. For contrast, repeat it with `-H "X-Tenant: default"` added: `403` from the gateway, with `TENANT_MISMATCH`.

- [ ] **Step 5: Record what you found**

Anything that differed from this plan or the design goes into the design doc or the handoff, not only into a commit message. In particular, record the outcomes of Step 4 in the design's section 5, replacing "an assumption until the run in §9 confirms it" with what the run showed.

---

## Task 7: Documentation

- [ ] **Step 1: Branch**

```bash
git checkout master
git checkout -b feature/m4-task-7
```

- [ ] **Step 2: README**

Update `README.md`:

- **Line 11, the scope statement:** it covers M0–M4. Route-level authorization is built; rate limiting and revocation are planned and not built.
- **Line 9:** keep the claim that the gateway does not *own* authorization, and add that it enforces coarse, route-level authorization as defence in depth — scope at the edge, permission and data ownership downstream. The two statements must not read as contradicting each other.
- **The section around line 173–182**, with the `authorizeExchange` snippet and "M2 answers exactly one question": replace it with an **Authorization at the edge** section containing:
  - the rule table from the design's section 4;
  - "the edge checks scope, the downstream checks permission", with the SPA consequence;
  - the tenant check — what it compares, what it deliberately does not inspect, and that an `acme` user must still send `X-Tenant: acme` to reach AuthCore;
  - a sample `403` body, and the four `detail` strings;
  - deny by default, and that an authenticated typo now reads `403`.
- **Known limitations, line 327**, "No route-level authorization": delete it. Add in its place: **"Tenant sources the gateway does not read"** — the request body — and why that is not an escalation.
- **Line 343**, the `gateway` actuator endpoint: it now has an authorization model to hang off; deciding who may read it is still its own decision. It stays off.
- **API-key reach:** anywhere the README says an API key on `/api/ledger/**` gets `401` from ledger, it now gets `403` from the gateway.
- **Roadmap, line 356:** M4 done.
- **Test count:** the number recorded in Task 4 Step 13.

- [ ] **Step 3: M3 design, section 8**

In `docs/superpowers/specs/2026-08-24-gatekeeper-m3-design.md`, the reach table's ledger row changes from `**401 from ledger** — ...` to `**403 at the gateway** since M4 — see the M4 design, section 4`. Below the table, the paragraph beginning "The ledger 401 is the honest cost..." gains one sentence: *M4 moved this refusal to the edge, where it is a 403 naming the reason, and stopped forwarding the key to ledger at all.*

- [ ] **Step 4: The handoff**

In `docs/superpowers/HANDOFF-M3-M6.md`:

- **§1:** GateKeeper's `master` hash and test count; M4 complete; "Next: M5". Rewrite the "GateKeeper today" paragraph so it describes the rule table, the tenant check and the 403 shape rather than saying authorization is M4's job.
- **§5:** mark the two M4 items closed — the 403 empty-body gap, and the separate AuthCore routes (now used as intended) — with a pointer to the M4 design.
- Anything Task 5 or Task 6 found that was not fixed goes here, under the milestone that owns it.

- [ ] **Step 5: Commit**

Message file contents:

```
docs: M4 is built — authorization at the edge

The README described anyExchange().authenticated() as the whole model
and API keys as reaching ledger for a 401. Both stopped being true.
Records the rule table, the scope/permission split, what the tenant
check compares and what it deliberately leaves to AuthCore, and moves
the M3 reach table's ledger row to the gateway's 403.
```

```bash
git add README.md docs/superpowers
git commit -F <message-file>
```

- [ ] **Step 6: The unrelated error, in its own commit**

In `docs/superpowers/specs/2026-08-02-gatekeeper-m0-m2-design.md`, around line 70, the `roles` claim is described as looking like `ROLE_ADMIN`. AuthCore emits it without the prefix: `AuthCoreUser.roleNames()` strips it, so the claim reads `["ADMIN"]` or `["USER"]`. Correct the example and add one clause saying so.

Message file contents:

```
docs: the roles claim carries no ROLE_ prefix

AuthCoreUser.roleNames() strips it before the token customizer writes
the claim, so a token says ADMIN, not ROLE_ADMIN. Downstream converters
add the prefix back when mapping roles to authorities. Found while
designing M4; unrelated to it.
```

```bash
git add docs/superpowers/specs/2026-08-02-gatekeeper-m0-m2-design.md
git commit -F <message-file>
```

- [ ] **Step 7: Review, then merge**

As Task 1 Step 13, with branch `feature/m4-task-7`.

- [ ] **Step 8: Push — only when the user says so**

```bash
git push origin master
```

Do not push feature branches unless asked. Before pushing, run `git log --format=%B origin/master..master | grep -ci "co-authored\|claude"`. It must print `0`.

---

## Definition of done

The M4 design, section 12, box by box:

- [ ] A token without `payments:write` on a ledger write route is refused `403` in the platform shape; the correct scope is proxied — `AuthorizationTest`, Task 6 calls 5–6.
- [ ] A request naming a tenant other than the token's is refused `403`, and the downstream never sees it — `AuthorizationTest`, Task 6 call 8.
- [ ] An API key on the ledger route is refused `403` at the edge; on the machine route it still works end to end — `AuthorizationTest`, Task 6 calls 1 and 3.
- [ ] A request no rule covers is refused `403` when authenticated and `401` when not — `AuthorizationTest`, Task 6 calls 10–11.
- [ ] Every `403` carries its fixed `detail` and no `WWW-Authenticate`, for JWT and key callers alike — `JsonServerAccessDeniedHandlerTest`, `AuthorizationTest`, Task 5 Step 4.
- [ ] The ledger route forwards no `X-API-Key` — `AuthorizationTest`, Task 5 Step 5.
- [ ] Every mutation in Task 5 failed its named test, and Task 6 behaved as tabled.
- [ ] GateKeeper green, each task on its own branch, reviewed, and merged with `--no-ff`.
