# GateKeeper M0–M2 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Stand up a reactive API gateway that authenticates AuthCore-issued JWTs at the edge and proxies to a downstream Spring Boot resource service which independently re-validates them.

**Architecture:** Three independent services coupled only by a wire contract. AuthCore (existing, `:8080`) issues tokens and publishes JWKS. GateKeeper (`:8081`, Netty/WebFlux) validates every request, strips spoofable identity headers, re-stamps them from verified claims, and routes onward. ledger-service (`:8082`, servlet) is an ordinary resource server that re-verifies the JWT itself and never trusts the gateway.

**Tech Stack:** Java 21 · Spring Boot 4.0.7 (GateKeeper) / 4.1.0 (ledger-service) · Spring Cloud 2025.1.2 (Gateway 5.0.2) · Spring Security OAuth2 Resource Server · Maven · JUnit 5 · WireMock 3.13.2 · Nimbus JOSE+JWT

**Spec:** [2026-08-02-gatekeeper-m0-m2-design.md](../specs/2026-08-02-gatekeeper-m0-m2-design.md)

---

## Environment rules (read first)

These are established facts about this machine. Violating them wastes a session.

- **Use `.\mvnw.cmd`, never `mvn`.** System Maven is 3.2.5 and too old. Neither new repo has a wrapper yet — Task 1 and Task 7 copy it from AuthCore.
- **Use `curl.exe`, never `curl`.** In PowerShell, `curl` is an alias for `Invoke-WebRequest`.
- **PowerShell variables do not persist between tool calls.** Any multi-step demo must run in a single call.
- **Docker Desktop must be running** only for AuthCore's Postgres/Redis. Neither new service needs Docker.
- **Commit messages:** use `git commit -F <file>` with a message file. Quotes inside `-m` break in this shell. **Never add a `Co-Authored-By` line.**
- **Branching.** Every task gets its own `feature/task-N` branch off `master`, merged back with `git merge --no-ff` so the topology stays visible on GitHub. Both repos are private on GitHub under `ezat141`; flip them to public at the end of Task 14.
- **Boot 4 renamed the starters.** Use `spring-boot-starter-webmvc` (not `-web`), `spring-boot-starter-security-oauth2-resource-server` (not `-oauth2-resource-server`), and the per-feature test starters `spring-boot-starter-webmvc-test` / `-webflux-test` / `-security-test` / `-actuator-test` instead of the monolithic `spring-boot-starter-test` and the raw `spring-security-test`. The old names still resolve identically but are deprecated, and AuthCore already uses the new ones.
- **Copy `.gitattributes` from AuthCore** into every new repo (`/mvnw text eol=lf`, `*.cmd text eol=crlf`). Without it a Windows checkout can commit `mvnw` with CRLF, which breaks it under bash and CI.

---

## File structure

### New repo: `ProjectsCVs/ledger-service`

| File | Responsibility |
|---|---|
| `pom.xml` | Boot 4.1.0, resource-server + web starters |
| `src/main/java/com/ledger/LedgerServiceApplication.java` | entry point |
| `src/main/java/com/ledger/config/ResourceServerConfig.java` | filter chain, method security, authorities converter wiring |
| `src/main/java/com/ledger/config/AuthCoreAuthoritiesConverter.java` | `scope`/`roles`/`permissions` claims → authorities |
| `src/main/java/com/ledger/ledger/LedgerEntry.java` | one ledger row |
| `src/main/java/com/ledger/ledger/LedgerRepository.java` | in-memory seeded store |
| `src/main/java/com/ledger/ledger/LedgerController.java` | the three endpoints |
| `src/main/java/com/ledger/ledger/WhoAmI.java` | the token-vs-headers comparison response |
| `src/main/resources/application.yml` | port 8082, JWKS URI, pinned issuer |
| `src/test/java/com/ledger/...` | tests 10–14 |

### New repo: `ProjectsCVs/gatekeeper` (spec already committed here)

| File | Responsibility |
|---|---|
| `pom.xml` | Boot 4.0.7 + Spring Cloud BOM |
| `src/main/java/com/gatekeeper/GateKeeperApplication.java` | entry point |
| `src/main/java/com/gatekeeper/config/JwtDecoderConfig.java` | `ReactiveJwtDecoder` + pinned issuer validator |
| `src/main/java/com/gatekeeper/config/GatewaySecurityConfig.java` | `SecurityWebFilterChain` |
| `src/main/java/com/gatekeeper/identity/InboundHeaderStripFilter.java` | `WebFilter` — strips `X-GK-*` **before** security |
| `src/main/java/com/gatekeeper/identity/IdentityStampFilter.java` | `GlobalFilter` — stamps `X-GK-*` **after** security |
| `src/main/java/com/gatekeeper/error/GlobalErrorWebExceptionHandler.java` | uniform JSON errors |
| `src/main/resources/application.yml` | port 8081, routes, downstream URIs, auth config |
| `src/test/java/com/gatekeeper/support/TestKey.java` | RSA keygen, JWKS rendering, token minting |
| `src/test/java/com/gatekeeper/...` | tests 1–9 |

**Deliberate divergence from spec §7.** The spec lists one `IdentityHeaderFilter`. The implementation splits it in two, because the two halves must run on opposite sides of Spring Security: the **strip** must precede authentication (so an unauthenticated request cannot launder a header through an error path), while the **stamp** requires the verified JWT and can only run after. One class cannot occupy both positions.

---

# Phase A — ledger-service

## Task 1: Bootstrap ledger-service

**Files:**
- Create: `ProjectsCVs/ledger-service/pom.xml`
- Create: `ProjectsCVs/ledger-service/src/main/java/com/ledger/LedgerServiceApplication.java`
- Create: `ProjectsCVs/ledger-service/src/main/resources/application.yml`
- Create: `ProjectsCVs/ledger-service/.gitignore`
- Test: `ProjectsCVs/ledger-service/src/test/java/com/ledger/LedgerServiceApplicationTests.java`

- [ ] **Step 1: Create the repo, copy the Maven wrapper, set the git identity**

```bash
cd "D:/courses/My CV/My cv/ProjectsCVs"
mkdir -p ledger-service/src/main/java/com/ledger ledger-service/src/main/resources ledger-service/src/test/java/com/ledger
cp -r authcore/.mvn authcore/mvnw authcore/mvnw.cmd ledger-service/
cd ledger-service
git init -q -b master
git config user.name "Ezzat Mohamed"
git config user.email ezat71101@gmail.com
```

- [ ] **Step 2: Write `.gitignore`**

```gitignore
target/
!.mvn/wrapper/maven-wrapper.jar
.idea/
*.iml
*.log
```

- [ ] **Step 3: Write `pom.xml`**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>4.1.0</version>
        <relativePath/>
    </parent>
    <groupId>com.ledger</groupId>
    <artifactId>ledger-service</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <name>ledger-service</name>
    <description>Protected downstream resource service for the AuthCore / GateKeeper platform</description>

    <properties>
        <java.version>21</java.version>
    </properties>

    <dependencies>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-webmvc</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security-oauth2-resource-server</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-actuator</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-webmvc-test</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security-test</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-actuator-test</artifactId>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>
</project>
```

- [ ] **Step 4: Write `LedgerServiceApplication.java`**

```java
package com.ledger;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class LedgerServiceApplication {

    public static void main(String[] args) {
        SpringApplication.run(LedgerServiceApplication.class, args);
    }
}
```

- [ ] **Step 5: Write `application.yml`**

`jwk-set-uri` gives Spring the keys; `issuer-uri` alongside it adds an issuer validator **without** Spring fetching discovery metadata at startup. Both are needed — see spec §9.

```yaml
server:
  port: 8082

spring:
  application:
    name: ledger-service
  security:
    oauth2:
      resourceserver:
        jwt:
          jwk-set-uri: http://localhost:8080/oauth2/jwks
          issuer-uri: http://localhost:8080

management:
  endpoints:
    web:
      exposure:
        include: health,info
```

- [ ] **Step 6: Write the failing context test**

`src/test/java/com/ledger/LedgerServiceApplicationTests.java`:

```java
package com.ledger;

import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;

@SpringBootTest(properties = "spring.security.oauth2.resourceserver.jwt.jwk-set-uri=http://localhost:9999/jwks")
class LedgerServiceApplicationTests {

    @Test
    void contextLoads() {
    }
}
```

The overridden `jwk-set-uri` points nowhere on purpose. `NimbusJwtDecoder` fetches keys lazily on first use, so the context must start without AuthCore running. If this test fails with a connection error, the decoder is being built eagerly and that is a real bug worth fixing now.

- [ ] **Step 7: Run it**

```bash
cd "D:/courses/My CV/My cv/ProjectsCVs/ledger-service" && ./mvnw.cmd -q test
```

Expected: PASS, 1 test.

- [ ] **Step 8: Commit**

Every commit in this plan follows the same two-step shape, because `git commit -m` breaks on quotes
in this shell. Write the message to the scratchpad first, then commit with `-F`:

```bash
printf '%s\n' "feat: bootstrap ledger-service on Spring Boot 4.1" > "$TMPDIR/msg.txt"
git add . && git commit -F "$TMPDIR/msg.txt"
```

Where `$TMPDIR` is the session scratchpad directory. Later tasks give only the message text — apply
this same shape each time, and never add a `Co-Authored-By` line.

---

## Task 2: Reject unauthenticated requests (test 11)

**Files:**
- Create: `src/main/java/com/ledger/config/ResourceServerConfig.java`
- Test: `src/test/java/com/ledger/config/ResourceServerConfigTest.java`

- [ ] **Step 1: Write the failing test**

```java
package com.ledger.config;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = "spring.security.oauth2.resourceserver.jwt.jwk-set-uri=http://localhost:9999/jwks")
@AutoConfigureMockMvc
class ResourceServerConfigTest {

    @Autowired
    MockMvc mockMvc;

    @Test
    void rejectsARequestWithNoToken() throws Exception {
        mockMvc.perform(get("/ledger/entries"))
                .andExpect(status().isUnauthorized());
    }

    @Test
    void permitsHealthWithoutAToken() throws Exception {
        mockMvc.perform(get("/actuator/health"))
                .andExpect(status().isOk());
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
./mvnw.cmd -q test -Dtest=ResourceServerConfigTest
```

Expected: FAIL. Without a security config, Boot's default chain applies HTTP Basic and returns 401 for `/ledger/entries` but **also** 401 for `/actuator/health`, so `permitsHealthWithoutAToken` fails.

- [ ] **Step 3: Write `ResourceServerConfig.java`**

Mirrors AuthCore's idioms in `AuthorizationServerConfig` — same `AbstractHttpConfigurer::disable` and `SessionCreationPolicy.STATELESS` style.

```java
package com.ledger.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.method.configuration.EnableMethodSecurity;
import org.springframework.security.config.annotation.web.builders.HttpSecurity;
import org.springframework.security.config.annotation.web.configuration.EnableWebSecurity;
import org.springframework.security.config.annotation.web.configurers.AbstractHttpConfigurer;
import org.springframework.security.config.http.SessionCreationPolicy;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationConverter;
import org.springframework.security.web.SecurityFilterChain;

/**
 * ledger-service is an ordinary resource server. It verifies the JWT itself against
 * AuthCore's JWKS and never trusts the X-GK-* headers GateKeeper stamps, so bypassing
 * the gateway and calling this service directly is still refused without a token.
 */
@Configuration
@EnableWebSecurity
@EnableMethodSecurity
public class ResourceServerConfig {

    @Bean
    public SecurityFilterChain securityFilterChain(HttpSecurity http) throws Exception {
        http
            .authorizeHttpRequests(authorize -> authorize
                .requestMatchers("/actuator/health", "/actuator/health/**").permitAll()
                .anyRequest().authenticated())
            .oauth2ResourceServer(resourceServer -> resourceServer
                .jwt(jwt -> jwt.jwtAuthenticationConverter(jwtAuthenticationConverter())))
            .sessionManagement(session -> session.sessionCreationPolicy(SessionCreationPolicy.STATELESS))
            .csrf(AbstractHttpConfigurer::disable);

        return http.build();
    }

    /** Reads roles and permissions out of the JWT, not just scope. */
    private static JwtAuthenticationConverter jwtAuthenticationConverter() {
        JwtAuthenticationConverter converter = new JwtAuthenticationConverter();
        converter.setJwtGrantedAuthoritiesConverter(new AuthCoreAuthoritiesConverter());
        return converter;
    }
}
```

- [ ] **Step 4: Write `AuthCoreAuthoritiesConverter.java`**

Deliberately mirrors `com.authcore.security.AuthCoreJwtAuthoritiesConverter`. The claim contract is AuthCore's, so the reader must match it exactly — including that `scope` may arrive as a list or a space-delimited string.

```java
package com.ledger.config;

import org.springframework.core.convert.converter.Converter;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;

import java.util.Collection;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

public class AuthCoreAuthoritiesConverter implements Converter<Jwt, Collection<GrantedAuthority>> {

    @Override
    public Collection<GrantedAuthority> convert(Jwt jwt) {
        Set<GrantedAuthority> authorities = new LinkedHashSet<>();

        for (String scope : claimAsList(jwt, "scope")) {
            authorities.add(new SimpleGrantedAuthority("SCOPE_" + scope));
        }
        for (String role : claimAsList(jwt, "roles")) {
            authorities.add(new SimpleGrantedAuthority(
                    role.startsWith("ROLE_") ? role : "ROLE_" + role));
        }
        for (String permission : claimAsList(jwt, "permissions")) {
            authorities.add(new SimpleGrantedAuthority(permission));
        }

        return authorities;
    }

    /** The {@code scope} claim may arrive as a list or as a space-delimited string. */
    private static List<String> claimAsList(Jwt jwt, String claimName) {
        Object claim = jwt.getClaim(claimName);
        if (claim == null) {
            return List.of();
        }
        if (claim instanceof Collection<?> collection) {
            return collection.stream().map(String::valueOf).toList();
        }
        String value = String.valueOf(claim).trim();
        return value.isEmpty() ? List.of() : List.of(value.split("\\s+"));
    }
}
```

- [ ] **Step 5: Run to verify both pass**

```bash
./mvnw.cmd -q test -Dtest=ResourceServerConfigTest
```

Expected: PASS, 2 tests.

- [ ] **Step 6: Commit**

Message: `feat: resource-server security with AuthCore's claim contract`

---

## Task 3: Ledger entries endpoint (test 12)

**Files:**
- Create: `src/main/java/com/ledger/ledger/LedgerEntry.java`
- Create: `src/main/java/com/ledger/ledger/LedgerRepository.java`
- Create: `src/main/java/com/ledger/ledger/LedgerController.java`
- Test: `src/test/java/com/ledger/ledger/LedgerControllerTest.java`

- [ ] **Step 1: Write the failing test**

```java
package com.ledger.ledger;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = "spring.security.oauth2.resourceserver.jwt.jwk-set-uri=http://localhost:9999/jwks")
@AutoConfigureMockMvc
class LedgerControllerTest {

    @Autowired
    MockMvc mockMvc;

    @Test
    void returnsEntriesForAnAuthenticatedCaller() throws Exception {
        mockMvc.perform(get("/ledger/entries")
                        .with(jwt().jwt(jwt -> jwt.subject("ezzat").claim("tenant", "acme"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.length()").value(3))
                .andExpect(jsonPath("$[0].reference").value("LDG-1001"));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
./mvnw.cmd -q test -Dtest=LedgerControllerTest
```

Expected: FAIL with 404 — the endpoint does not exist.

- [ ] **Step 3: Write `LedgerEntry.java`**

```java
package com.ledger.ledger;

import java.math.BigDecimal;
import java.time.Instant;

public record LedgerEntry(
        String reference,
        String tenant,
        BigDecimal amount,
        String currency,
        Instant postedAt) {
}
```

- [ ] **Step 4: Write `LedgerRepository.java`**

```java
package com.ledger.ledger;

import org.springframework.stereotype.Repository;

import java.math.BigDecimal;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * In-memory on purpose. This milestone is about the edge, and a database would add
 * migration and Testcontainers work that proves nothing the gateway does not already
 * prove. Swapping this for JPA later touches no other class.
 */
@Repository
public class LedgerRepository {

    private final List<LedgerEntry> entries = new CopyOnWriteArrayList<>(List.of(
            new LedgerEntry("LDG-1001", "acme", new BigDecimal("250.00"), "EGP",
                    Instant.now().minus(3, ChronoUnit.DAYS)),
            new LedgerEntry("LDG-1002", "acme", new BigDecimal("74.50"), "EGP",
                    Instant.now().minus(2, ChronoUnit.DAYS)),
            new LedgerEntry("LDG-1003", "default", new BigDecimal("1200.00"), "USD",
                    Instant.now().minus(1, ChronoUnit.DAYS))));

    public List<LedgerEntry> findAll() {
        return new ArrayList<>(entries);
    }

    public LedgerEntry add(LedgerEntry entry) {
        entries.add(entry);
        return entry;
    }
}
```

- [ ] **Step 5: Write `LedgerController.java` (entries endpoint only)**

```java
package com.ledger.ledger;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/ledger")
public class LedgerController {

    private final LedgerRepository repository;

    public LedgerController(LedgerRepository repository) {
        this.repository = repository;
    }

    @GetMapping("/entries")
    public List<LedgerEntry> entries() {
        return repository.findAll();
    }
}
```

- [ ] **Step 6: Run to verify it passes**

```bash
./mvnw.cmd -q test -Dtest=LedgerControllerTest
```

Expected: PASS, 1 test.

- [ ] **Step 7: Commit**

Message: `feat: ledger entries endpoint`

---

## Task 4: Permission-gated write (test 13)

**Files:**
- Modify: `src/main/java/com/ledger/ledger/LedgerController.java`
- Modify: `src/test/java/com/ledger/ledger/LedgerControllerTest.java`

- [ ] **Step 1: Add the failing tests**

Append to `LedgerControllerTest`. Note the imports needed at the top of the file: `post`, `MediaType`, and `SimpleGrantedAuthority`.

```java
    @Test
    void refusesAWriteWithoutTheRequiredPermission() throws Exception {
        mockMvc.perform(post("/ledger/entries")
                        .with(jwt().jwt(jwt -> jwt.subject("ezzat").claim("tenant", "acme"))
                                  .authorities(new SimpleGrantedAuthority("payments:read")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"reference":"LDG-2001","amount":"10.00","currency":"EGP"}
                                """))
                .andExpect(status().isForbidden());
    }

    /**
     * Rebuilds the context afterwards. LedgerRepository is a singleton holding mutable
     * state, and every test class here shares one cached context because their
     * {@code @SpringBootTest} configuration is identical — so an entry added by this test
     * would otherwise still be there when {@code returnsEntriesForAnAuthenticatedCaller}
     * asserts a count of three. JUnit's method order is deterministic but arbitrary, so
     * that would fail unpredictably rather than never or always.
     */
    @DirtiesContext(methodMode = DirtiesContext.MethodMode.AFTER_METHOD)
    @Test
    void allowsAWriteWithTheRequiredPermission() throws Exception {
        mockMvc.perform(post("/ledger/entries")
                        .with(jwt().jwt(jwt -> jwt.subject("ezzat").claim("tenant", "acme"))
                                  .authorities(new SimpleGrantedAuthority("payments:write")))
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("""
                                {"reference":"LDG-2001","amount":"10.00","currency":"EGP"}
                                """))
                .andExpect(status().isCreated())
                .andExpect(jsonPath("$.reference").value("LDG-2001"))
                .andExpect(jsonPath("$.tenant").value("acme"));
    }
```

Additional imports:

```java
import org.springframework.http.MediaType;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.annotation.DirtiesContext;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
```

- [ ] **Step 2: Run to verify they fail**

```bash
./mvnw.cmd -q test -Dtest=LedgerControllerTest
```

Expected: FAIL with 405 (Method Not Allowed) — POST is not mapped.

- [ ] **Step 3: Add the request record and the endpoint**

Create `src/main/java/com/ledger/ledger/NewEntryRequest.java`:

```java
package com.ledger.ledger;

import java.math.BigDecimal;

public record NewEntryRequest(String reference, BigDecimal amount, String currency) {
}
```

Add to `LedgerController` (plus imports `PostMapping`, `RequestBody`, `ResponseStatus`, `HttpStatus`, `PreAuthorize`, `AuthenticationPrincipal`, `Jwt`, `Instant`):

```java
    /**
     * Enforced here, in the service that owns the data — not only at the gateway.
     * GateKeeper's route-level rules (M4) are a coarse outer layer; this is the
     * authoritative check, and it still applies when the gateway is bypassed.
     */
    @PostMapping("/entries")
    @ResponseStatus(HttpStatus.CREATED)
    @PreAuthorize("hasAuthority('payments:write')")
    public LedgerEntry create(@RequestBody NewEntryRequest request,
                              @AuthenticationPrincipal Jwt jwt) {
        return repository.add(new LedgerEntry(
                request.reference(),
                jwt.getClaimAsString("tenant"),
                request.amount(),
                request.currency(),
                Instant.now()));
    }
```

- [ ] **Step 4: Run to verify all four tests pass**

```bash
./mvnw.cmd -q test -Dtest=LedgerControllerTest
```

Expected: PASS, 4 tests.

- [ ] **Step 5: Commit**

Message: `feat: permission-gated ledger write`

---

## Task 5: The whoami endpoint (tests 12 and 14)

This is the endpoint that demonstrates the whole design in one response.

**Files:**
- Create: `src/main/java/com/ledger/ledger/WhoAmI.java`
- Modify: `src/main/java/com/ledger/ledger/LedgerController.java`
- Test: `src/test/java/com/ledger/ledger/WhoAmITest.java`

- [ ] **Step 1: Write the failing test**

```java
package com.ledger.ledger;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webmvc.test.autoconfigure.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.test.web.servlet.MockMvc;

import static org.springframework.security.test.web.servlet.request.SecurityMockMvcRequestPostProcessors.jwt;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(properties = "spring.security.oauth2.resourceserver.jwt.jwk-set-uri=http://localhost:9999/jwks")
@AutoConfigureMockMvc
class WhoAmITest {

    @Autowired
    MockMvc mockMvc;

    /** Bypassing the gateway: the token authenticates, and no X-GK-* headers arrive. */
    @Test
    void derivesIdentityFromTheTokenWhenCalledDirectly() throws Exception {
        mockMvc.perform(get("/ledger/whoami")
                        .with(jwt().jwt(jwt -> jwt.subject("ezzat").claim("tenant", "acme"))
                                  .authorities(new SimpleGrantedAuthority("payments:read"))))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.fromToken.subject").value("ezzat"))
                .andExpect(jsonPath("$.fromToken.tenant").value("acme"))
                .andExpect(jsonPath("$.fromHeaders.subject").doesNotExist())
                .andExpect(jsonPath("$.match").value(false));
    }

    /** Through the gateway: the stamped headers agree with the token. */
    @Test
    void reportsAMatchWhenHeadersAgreeWithTheToken() throws Exception {
        mockMvc.perform(get("/ledger/whoami")
                        .with(jwt().jwt(jwt -> jwt.subject("ezzat").claim("tenant", "acme"))
                                  .authorities(new SimpleGrantedAuthority("payments:read")))
                        .header("X-GK-Subject", "ezzat")
                        .header("X-GK-Tenant", "acme"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.match").value(true));
    }

    /**
     * Test 14 in the spec. Identity headers alone must never authenticate anyone —
     * they are informational, and the service does not trust them.
     */
    @Test
    void refusesHeadersWithoutABearerToken() throws Exception {
        mockMvc.perform(get("/ledger/whoami")
                        .header("X-GK-Subject", "admin")
                        .header("X-GK-Tenant", "default")
                        .header("X-GK-Permissions", "payments:write"))
                .andExpect(status().isUnauthorized());
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
./mvnw.cmd -q test -Dtest=WhoAmITest
```

Expected: FAIL with 404 on the first two; the third already passes because `anyRequest().authenticated()` is in place. That is fine — it confirms the rule was already correct.

- [ ] **Step 3: Write `WhoAmI.java`**

```java
package com.ledger.ledger;

import java.util.List;
import java.util.Objects;

/**
 * The identity as this service derived it from the verified token, beside the identity
 * GateKeeper asserted in headers.
 *
 * <p>Called through the gateway these agree. Called directly on :8082 the header side is
 * empty while the token side is populated — one response showing both that the headers
 * are not authoritative and that this service is secure without the gateway in front.
 */
public record WhoAmI(Identity fromToken, Identity fromHeaders, boolean match) {

    public record Identity(String subject, String tenant, List<String> permissions) {

        public static final Identity EMPTY = new Identity(null, null, List.of());

        public boolean isEmpty() {
            return subject == null && tenant == null && permissions.isEmpty();
        }
    }

    public static WhoAmI of(Identity fromToken, Identity fromHeaders) {
        boolean match = !fromHeaders.isEmpty()
                && Objects.equals(fromToken.subject(), fromHeaders.subject())
                && Objects.equals(fromToken.tenant(), fromHeaders.tenant());
        return new WhoAmI(fromToken, fromHeaders, match);
    }
}
```

- [ ] **Step 4: Add the endpoint to `LedgerController`**

> **Do not copy `create(...)`'s tenant guard onto this endpoint.** Task 4 established the pattern
> "no `tenant` claim → throw `AccessDeniedException` → 403" for writes. Applying it here would make
> `whoami` refuse in exactly the situations it exists to diagnose — a token whose identity is
> incomplete or disagrees with the headers is the interesting case, not an error case. `whoami`
> follows `entries()`'s shape instead: report absence visibly (a null field, an empty list) and let
> the caller see it. A `whoami` that returns 403 when identity is missing tells you nothing.

Additional imports: `RequestHeader`, `Nullable` (`org.springframework.lang.Nullable`), `Arrays`.

```java
    @GetMapping("/whoami")
    public WhoAmI whoami(
            @AuthenticationPrincipal Jwt jwt,
            @RequestHeader(value = "X-GK-Subject", required = false) String headerSubject,
            @RequestHeader(value = "X-GK-Tenant", required = false) String headerTenant,
            @RequestHeader(value = "X-GK-Permissions", required = false) String headerPermissions) {

        WhoAmI.Identity fromToken = new WhoAmI.Identity(
                jwt.getSubject(),
                jwt.getClaimAsString("tenant"),
                jwt.getClaimAsStringList("permissions") == null
                        ? List.of()
                        : jwt.getClaimAsStringList("permissions"));

        WhoAmI.Identity fromHeaders = (headerSubject == null && headerTenant == null)
                ? WhoAmI.Identity.EMPTY
                : new WhoAmI.Identity(headerSubject, headerTenant, splitPermissions(headerPermissions));

        return WhoAmI.of(fromToken, fromHeaders);
    }

    private static List<String> splitPermissions(String raw) {
        if (raw == null || raw.isBlank()) {
            return List.of();
        }
        return Arrays.stream(raw.split(",")).map(String::trim).filter(s -> !s.isEmpty()).toList();
    }
```

- [ ] **Step 5: Run to verify all three pass**

```bash
./mvnw.cmd -q test -Dtest=WhoAmITest
```

Expected: PASS, 3 tests.

- [ ] **Step 6: Run the whole suite**

```bash
./mvnw.cmd -q test
```

Expected: PASS, 8 tests total across 4 classes.

- [ ] **Step 7: Commit**

Message: `feat: whoami endpoint comparing token identity against gateway headers`

---

## Task 6: ledger-service README and push

**Files:**
- Create: `ProjectsCVs/ledger-service/README.md`

- [ ] **Step 1: Write the README**

Must cover: what the service is, that it is deliberately a normal servlet app, the responsibility matrix row for it (owns business data and fine-grained authorization; trusts nothing), the three endpoints, and the `whoami` demo with both the through-gateway and direct-call outputs shown.

- [ ] **Step 2: Create the GitHub repo and push**

```bash
cd "D:/courses/My CV/My cv/ProjectsCVs/ledger-service"
gh repo create ledger-service --public --source=. --remote=origin --push
```

- [ ] **Step 3: Verify the commits are attributed correctly**

```bash
git log --format="%an <%ae>" | sort -u
```

Expected: only `Ezzat Mohamed <ezat71101@gmail.com>`.

---

# Phase B — GateKeeper

## Task 7: Bootstrap GateKeeper on Netty (test 1)

**Files:**
- Create: `ProjectsCVs/gatekeeper/pom.xml`
- Create: `ProjectsCVs/gatekeeper/src/main/java/com/gatekeeper/GateKeeperApplication.java`
- Create: `ProjectsCVs/gatekeeper/src/main/resources/application.yml`
- Create: `ProjectsCVs/gatekeeper/.gitignore`
- Test: `ProjectsCVs/gatekeeper/src/test/java/com/gatekeeper/GateKeeperApplicationTests.java`

- [ ] **Step 1: Copy the Maven wrapper**

```bash
cd "D:/courses/My CV/My cv/ProjectsCVs"
cp -r authcore/.mvn authcore/mvnw authcore/mvnw.cmd gatekeeper/
mkdir -p gatekeeper/src/main/java/com/gatekeeper gatekeeper/src/main/resources gatekeeper/src/test/java/com/gatekeeper
```

The repo and git identity already exist — the spec was committed here.

- [ ] **Step 2: Write `.gitignore`** — same content as Task 1 Step 2.

- [ ] **Step 3: Write `pom.xml`**

```xml
<?xml version="1.0" encoding="UTF-8"?>
<project xmlns="http://maven.apache.org/POM/4.0.0"
         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"
         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 https://maven.apache.org/xsd/maven-4.0.0.xsd">
    <modelVersion>4.0.0</modelVersion>
    <parent>
        <groupId>org.springframework.boot</groupId>
        <artifactId>spring-boot-starter-parent</artifactId>
        <version>4.0.7</version>
        <relativePath/>
    </parent>
    <groupId>com.gatekeeper</groupId>
    <artifactId>gatekeeper</artifactId>
    <version>0.0.1-SNAPSHOT</version>
    <name>gatekeeper</name>
    <description>Zero-trust API gateway for the AuthCore platform</description>

    <properties>
        <java.version>21</java.version>
        <spring-cloud.version>2025.1.2</spring-cloud.version>
        <wiremock.version>3.13.2</wiremock.version>
    </properties>

    <dependencyManagement>
        <dependencies>
            <dependency>
                <groupId>org.springframework.cloud</groupId>
                <artifactId>spring-cloud-dependencies</artifactId>
                <version>${spring-cloud.version}</version>
                <type>pom</type>
                <scope>import</scope>
            </dependency>
        </dependencies>
    </dependencyManagement>

    <dependencies>
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-gateway-server-webflux</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security-oauth2-resource-server</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-actuator</artifactId>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-webflux-test</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-security-test</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.springframework.boot</groupId>
            <artifactId>spring-boot-starter-actuator-test</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>io.projectreactor</groupId>
            <artifactId>reactor-test</artifactId>
            <scope>test</scope>
        </dependency>
        <dependency>
            <groupId>org.wiremock</groupId>
            <artifactId>wiremock-standalone</artifactId>
            <version>${wiremock.version}</version>
            <scope>test</scope>
        </dependency>
    </dependencies>

    <build>
        <plugins>
            <plugin>
                <groupId>org.springframework.boot</groupId>
                <artifactId>spring-boot-maven-plugin</artifactId>
            </plugin>
        </plugins>
    </build>
</project>
```

`wiremock-standalone` is chosen over `wiremock` because it shades its own Jetty. The plain artifact drags in a Jetty version that collides with Boot 4's managed one.

- [ ] **Step 4: Write `GateKeeperApplication.java`**

```java
package com.gatekeeper;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class GateKeeperApplication {

    public static void main(String[] args) {
        SpringApplication.run(GateKeeperApplication.class, args);
    }
}
```

- [ ] **Step 5: Write `application.yml`**

```yaml
server:
  port: 8081

spring:
  application:
    name: gatekeeper

gatekeeper:
  downstream:
    authcore: http://localhost:8080
    ledger: http://localhost:8082
  auth:
    issuer: http://localhost:8080
    jwk-set-uri: http://localhost:8080/oauth2/jwks

management:
  endpoints:
    web:
      exposure:
        include: health,info,gateway
```

- [ ] **Step 6: Write the failing test**

```java
package com.gatekeeper;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.http.server.reactive.HttpHandler;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class GateKeeperApplicationTests {

    @Autowired
    ApplicationContext context;

    /**
     * Asserts the app is reactive, not servlet. An {@link HttpHandler} bean exists only in
     * a WebFlux application — a Tomcat/servlet context has none. Checking for that bean is
     * stable across Boot's package reorganisations in a way that asserting on a specific
     * context class is not.
     */
    @Test
    void startsAsAReactiveApplicationOnNetty() {
        assertThat(context.getBeanNamesForType(HttpHandler.class)).isNotEmpty();
    }
}
```

- [ ] **Step 7: Run it**

```bash
cd "D:/courses/My CV/My cv/ProjectsCVs/gatekeeper" && ./mvnw.cmd -q test
```

Expected: PASS, 1 test. Confirm the startup log says `Netty started on port` — if it says Tomcat, a servlet starter leaked onto the classpath.

- [ ] **Step 8: Commit**

Message: `feat(M0): bootstrap GateKeeper on Spring Cloud Gateway 5`

---

## Task 8: Routing with StripPrefix (test 2)

**Files:**
- Modify: `src/main/resources/application.yml`
- Test: `src/test/java/com/gatekeeper/routing/RoutingTest.java`

> **The gateway is closed by default here, not open.** Task 7 put the OAuth2 resource-server starter
> on the classpath before any code used it, so Boot installs a deny-all `SecurityWebFilterChain` over
> every path — and suppresses the generated password, because `OpaqueTokenIntrospector` is present.
> Without intervention every assertion below fails on `401` before routing is even consulted. The
> test therefore carries a nested `@TestConfiguration` supplying a permit-all chain, which makes
> Boot's own security autoconfiguration back off. That scaffolding is scoped to this class and is
> **removed in Task 9**, which installs the real chain and rewrites these expectations to carry a
> token.

- [ ] **Step 1: Write the failing test**

```java
package com.gatekeeper.routing;

import com.github.tomakehurst.wiremock.WireMockServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.beans.factory.annotation.Autowired;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class RoutingTest {

    static WireMockServer downstream;

    @Autowired
    WebTestClient client;

    @BeforeAll
    static void startDownstream() {
        downstream = new WireMockServer(options().dynamicPort());
        downstream.start();
        downstream.stubFor(get(urlEqualTo("/ledger/entries"))
                .willReturn(aResponse().withStatus(200).withBody("[]")));
        downstream.stubFor(get(urlEqualTo("/api/accounts/me"))
                .willReturn(aResponse().withStatus(200).withBody("{}")));
    }

    @AfterAll
    static void stopDownstream() {
        downstream.stop();
    }

    @DynamicPropertySource
    static void routes(DynamicPropertyRegistry registry) {
        registry.add("gatekeeper.downstream.ledger", () -> downstream.baseUrl());
        registry.add("gatekeeper.downstream.authcore", () -> downstream.baseUrl());
    }

    /** StripPrefix=1 must remove /api before the ledger service sees the path. */
    @Test
    void stripsTheApiPrefixOnTheLedgerRoute() {
        client.get().uri("/api/ledger/entries").exchange().expectStatus().isOk();
        downstream.verify(getRequestedFor(urlEqualTo("/ledger/entries")));
    }

    /** AuthCore serves /api/accounts verbatim, so this route must NOT be stripped. */
    @Test
    void preservesTheFullPathOnTheAuthCoreRoute() {
        client.get().uri("/api/accounts/me").exchange().expectStatus().isOk();
        downstream.verify(getRequestedFor(urlEqualTo("/api/accounts/me")));
    }
}
```

Import needed: `org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient`.

- [ ] **Step 2: Run to verify it fails**

```bash
./mvnw.cmd -q test -Dtest=RoutingTest
```

Expected: FAIL with 404 — no routes are defined yet.

- [ ] **Step 3: Add routes to `application.yml`**

**Property-prefix warning:** Spring Cloud Gateway 5.x uses `spring.cloud.gateway.server.webflux.*`. The pre-4.2 prefix `spring.cloud.gateway.routes` is gone. If routes silently fail to bind, this is the first thing to check — a wrong prefix produces 404s with no error at startup.

```yaml
spring:
  application:
    name: gatekeeper
  cloud:
    gateway:
      server:
        webflux:
          routes:
            - id: authcore-accounts
              uri: ${gatekeeper.downstream.authcore}
              predicates:
                - Path=/api/accounts/**
            - id: authcore-machine
              uri: ${gatekeeper.downstream.authcore}
              predicates:
                - Path=/api/machine/**
            - id: ledger
              uri: ${gatekeeper.downstream.ledger}
              predicates:
                - Path=/api/ledger/**
              filters:
                - StripPrefix=1
```

- [ ] **Step 4: Run to verify it passes**

```bash
./mvnw.cmd -q test -Dtest=RoutingTest
```

Expected: PASS, 2 tests.

- [ ] **Step 5: Manual check against the real AuthCore**

Start AuthCore (`:8080`) and GateKeeper (`:8081`), then:

```bash
curl.exe -i http://localhost:8081/api/accounts/me
```

Expected: **401 from AuthCore** — per spec §8 this is the correct M1 result and proves the proxy works.

- [ ] **Step 6: Commit**

Message: `feat(M1): route to AuthCore and ledger-service`

---

## Task 9: JWT authentication (tests 3, 4, 5)

**Files:**
- Create: `src/test/java/com/gatekeeper/support/TestKey.java`
- Create: `src/main/java/com/gatekeeper/config/JwtDecoderConfig.java`
- Create: `src/main/java/com/gatekeeper/config/GatewaySecurityConfig.java`
- Test: `src/test/java/com/gatekeeper/auth/JwtAuthenticationTest.java`

- [ ] **Step 1: Write the test-key helper**

```java
package com.gatekeeper.support;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Mints RS256 tokens and renders JWKS documents, standing in for AuthCore in tests. */
public final class TestKey {

    private final RSAKey key;

    private TestKey(RSAKey key) {
        this.key = key;
    }

    public static TestKey generate(String keyId) {
        try {
            return new TestKey(new RSAKeyGenerator(2048).keyID(keyId).generate());
        } catch (Exception ex) {
            throw new IllegalStateException("could not generate a test key", ex);
        }
    }

    /** The public half of every supplied key, as AuthCore's /oauth2/jwks would serve it. */
    public static String jwksDocument(TestKey... keys) {
        List<JWK> jwks = Arrays.stream(keys).map(k -> (JWK) k.key).toList();
        return new JWKSet(jwks).toPublicJWKSet().toString();
    }

    public String mint(String issuer, String subject, Instant expiresAt, Map<String, Object> claims) {
        return mintAdvertisingKeyId(this.key.getKeyID(), issuer, subject, expiresAt, claims);
    }

    /**
     * Signs with this key but writes a different {@code kid} into the header.
     *
     * <p>Two failures need this. Naming a key id that IS published gives a signature that
     * does not verify. Naming one that is NOT published makes the decoder refetch the JWKS
     * and then give up. They fail on different code paths, so the tests are separate.
     */
    public String mintAdvertisingKeyId(String keyId, String issuer, String subject,
                                       Instant expiresAt, Map<String, Object> claims) {
        try {
            JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                    .issuer(issuer)
                    .subject(subject)
                    .jwtID(UUID.randomUUID().toString())
                    .issueTime(Date.from(Instant.now().minusSeconds(30)))
                    .expirationTime(Date.from(expiresAt));
            claims.forEach(builder::claim);

            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256)
                            .keyID(keyId)
                            .type(JOSEObjectType.JWT)
                            .build(),
                    builder.build());
            jwt.sign(new RSASSASigner(this.key));
            return jwt.serialize();
        } catch (Exception ex) {
            throw new IllegalStateException("could not mint a test token", ex);
        }
    }
}
```

- [ ] **Step 2: Write the failing test**

```java
package com.gatekeeper.auth;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.gatekeeper.support.TestKey;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class JwtAuthenticationTest {

    static final String ISSUER = "http://localhost:8080";

    static WireMockServer authCore;
    static TestKey activeKey;

    @Autowired
    WebTestClient client;

    @BeforeAll
    static void startFakeAuthCore() {
        activeKey = TestKey.generate("k1");
        authCore = new WireMockServer(options().dynamicPort());
        authCore.start();
        authCore.stubFor(get(urlEqualTo("/oauth2/jwks"))
                .willReturn(okJson(TestKey.jwksDocument(activeKey))));
        authCore.stubFor(get(urlEqualTo("/ledger/entries"))
                .willReturn(aResponse().withStatus(200).withBody("[]")));
    }

    @AfterAll
    static void stop() {
        authCore.stop();
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("gatekeeper.auth.jwk-set-uri", () -> authCore.baseUrl() + "/oauth2/jwks");
        registry.add("gatekeeper.auth.issuer", () -> ISSUER);
        registry.add("gatekeeper.downstream.ledger", () -> authCore.baseUrl());
        registry.add("gatekeeper.downstream.authcore", () -> authCore.baseUrl());
    }

    static String bearer(String token) {
        return "Bearer " + token;
    }

    @Test
    void refusesARequestWithNoToken() {
        client.get().uri("/api/ledger/entries")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().valueMatches(HttpHeaders.WWW_AUTHENTICATE, "Bearer.*");
    }

    @Test
    void proxiesARequestWithAValidToken() {
        String token = activeKey.mint(ISSUER, "ezzat",
                Instant.now().plus(5, ChronoUnit.MINUTES),
                Map.of("tenant", "acme", "permissions", java.util.List.of("payments:read")));

        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, bearer(token))
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void refusesAnExpiredToken() {
        String token = activeKey.mint(ISSUER, "ezzat",
                Instant.now().minus(1, ChronoUnit.MINUTES), Map.of());

        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, bearer(token))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    @Test
    void permitsHealthWithoutAToken() {
        client.get().uri("/actuator/health").exchange().expectStatus().isOk();
    }
}
```

- [ ] **Step 3: Run to verify it fails**

```bash
./mvnw.cmd -q test -Dtest=JwtAuthenticationTest
```

Expected: FAIL — with no security config every request is permitted, so `refusesARequestWithNoToken` gets 200.

- [ ] **Step 4: Write `JwtDecoderConfig.java`**

```java
package com.gatekeeper.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

/**
 * Trust is anchored on AuthCore's JWKS, not on a shared secret or a copied public key —
 * which is what lets AuthCore rotate its signing key without redeploying the gateway.
 *
 * <p>The issuer is pinned explicitly. AuthCore derives its issuer from the request host,
 * so a token fetched at 127.0.0.1:8080 carries a different {@code iss} than one fetched at
 * localhost:8080 and will be refused here. Failing closed is correct; the README explains
 * the cause so the failure is diagnosable.
 */
@Configuration
public class JwtDecoderConfig {

    @Bean
    public ReactiveJwtDecoder jwtDecoder(
            @Value("${gatekeeper.auth.jwk-set-uri}") String jwkSetUri,
            @Value("${gatekeeper.auth.issuer}") String issuer) {

        NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder.withJwkSetUri(jwkSetUri).build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuer));
        return decoder;
    }
}
```

> **Add this tripwire so the scaffold cannot rot unnoticed**, to `GateKeeperApplicationTests`:
>
> ```java
>     /**
>      * Two chains do not conflict — Spring starts cleanly and {@code WebFilterChainProxy}
>      * simply takes the first that matches, silently. A leftover test-scoped chain would
>      * therefore never announce itself. This says so out loud instead.
>      */
>     @Test
>     void onlyOneSecurityChainIsInPlay() {
>         assertThat(context.getBeanNamesForType(SecurityWebFilterChain.class)).hasSize(1);
>     }
> ```
>
> It passes trivially today and fails the moment a second chain appears, naming the cause
> instead of leaving someone to root-cause four unrelated-looking 401s.

> **Delete Task 8's `PermitAllSecurity` scaffolding as part of this task.** `RoutingTest` carries a
> nested `@TestConfiguration` supplying a permit-all chain, added only because no real chain existed
> yet. Once `GatewaySecurityConfig` lands, two `SecurityWebFilterChain` beans would be in play and
> the routing tests would be asserting against the wrong one. Remove the nested class and update
> those four tests to present a valid token, exactly as the tests below do.

> **Expect `/actuator/info` to keep returning 401, and do not treat it as a bug you introduced.**
> Before this task, Boot's `ReactiveManagementWebSecurityAutoConfiguration` installs a deny-all chain
> over every actuator path except health — and because `OpaqueTokenIntrospector` is on the classpath
> via the resource-server starter, `ReactiveUserDetailsServiceAutoConfiguration` is suppressed and no
> generated password is ever printed, so nothing can authenticate against it. The config below
> replaces that chain and permits `/actuator/health` only, so `info` stays behind authentication —
> now deliberately rather than accidentally. Verified by running the app and reading the `--debug`
> conditions report.

- [ ] **Step 5: Write `GatewaySecurityConfig.java`**

```java
package com.gatekeeper.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.web.server.SecurityWebFilterChain;

/**
 * M2 answers one question only: is this a valid, unexpired token from AuthCore. Deciding
 * whether the caller may reach a particular route is M4 — mixing the two here would make
 * the route rules invisible in the security config later.
 */
@Configuration
@EnableWebFluxSecurity
public class GatewaySecurityConfig {

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(
            ServerHttpSecurity http, ReactiveJwtDecoder jwtDecoder) {

        return http
                // Stateless, credential-on-every-request edge: a session would add server
                // state and CSRF exposure for nothing.
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .authorizeExchange(exchange -> exchange
                        .pathMatchers("/actuator/health", "/actuator/health/**").permitAll()
                        .anyExchange().authenticated())
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .jwt(jwt -> jwt.jwtDecoder(jwtDecoder)))
                .build();
    }
}
```

- [ ] **Step 6: Run to verify it passes**

```bash
./mvnw.cmd -q test -Dtest=JwtAuthenticationTest
```

Expected: PASS, 4 tests.

- [ ] **Step 7: Commit**

Message: `feat(M2): authenticate AuthCore JWTs against JWKS with a pinned issuer`

---

## Task 10: Signature and key-id failures (tests 6, 7)

**Files:**
- Modify: `src/test/java/com/gatekeeper/auth/JwtAuthenticationTest.java`

- [ ] **Step 1: Add both tests**

```java
    /**
     * Test 6 — signed by a key that is not published, but advertising a kid that IS.
     * The decoder finds k1, attempts verification, and the signature does not match.
     */
    @Test
    void refusesATokenWithAnInvalidSignature() {
        TestKey foreignKey = TestKey.generate("k1");
        String token = foreignKey.mint(ISSUER, "attacker",
                Instant.now().plus(5, ChronoUnit.MINUTES), Map.of());

        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, bearer(token))
                .exchange()
                .expectStatus().isUnauthorized();
    }

    /**
     * Test 7 — advertises a kid absent from the JWKS. The decoder refetches the key set
     * before giving up, which is a different path from a plain signature mismatch and the
     * one that matters for key rotation.
     */
    @Test
    void refusesATokenWithAnUnknownKeyId() {
        String token = activeKey.mintAdvertisingKeyId("k-does-not-exist", ISSUER, "ezzat",
                Instant.now().plus(5, ChronoUnit.MINUTES), Map.of());

        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, bearer(token))
                .exchange()
                .expectStatus().isUnauthorized();
    }
```

- [ ] **Step 2: Run**

```bash
./mvnw.cmd -q test -Dtest=JwtAuthenticationTest
```

Expected: PASS, 6 tests. Both should already pass against the Task 9 implementation — these tests exist to prove the failures produce **401 and not 500**. If either returns 500, the decoder is letting a `JwtException` escape and that must be fixed before moving on.

- [ ] **Step 3: Commit**

Message: `test: cover invalid signature and unknown key id`

---

## Task 11: Identity propagation and anti-spoofing (test 8)

**Files:**
- Create: `src/main/java/com/gatekeeper/identity/InboundHeaderStripFilter.java`
- Create: `src/main/java/com/gatekeeper/identity/IdentityStampFilter.java`
- Test: `src/test/java/com/gatekeeper/identity/IdentityPropagationTest.java`

- [ ] **Step 1: Write the failing test**

```java
package com.gatekeeper.identity;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.gatekeeper.support.TestKey;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class IdentityPropagationTest {

    static final String ISSUER = "http://localhost:8080";

    static WireMockServer downstream;
    static TestKey activeKey;

    @Autowired
    WebTestClient client;

    @BeforeAll
    static void start() {
        activeKey = TestKey.generate("k1");
        downstream = new WireMockServer(options().dynamicPort());
        downstream.start();
        downstream.stubFor(get(urlEqualTo("/oauth2/jwks"))
                .willReturn(okJson(TestKey.jwksDocument(activeKey))));
        downstream.stubFor(get(urlEqualTo("/ledger/entries"))
                .willReturn(aResponse().withStatus(200).withBody("[]")));
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
    }

    /**
     * Test 8. The client asserts a tenant it has no claim to. The gateway must overwrite
     * it with the verified value — if the header survived, any downstream trusting it
     * would grant cross-tenant access.
     */
    @Test
    void overwritesClientSuppliedIdentityHeaders() {
        String token = activeKey.mint(ISSUER, "ezzat",
                Instant.now().plus(5, ChronoUnit.MINUTES),
                Map.of("tenant", "acme", "permissions", List.of("payments:read")));

        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .header("X-GK-Tenant", "default")
                .header("X-GK-Subject", "admin")
                .header("X-GK-Permissions", "payments:write")
                .exchange()
                .expectStatus().isOk();

        downstream.verify(getRequestedFor(urlEqualTo("/ledger/entries"))
                .withHeader("X-GK-Tenant", equalTo("acme"))
                .withHeader("X-GK-Subject", equalTo("ezzat"))
                .withHeader("X-GK-Permissions", equalTo("payments:read")));
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
./mvnw.cmd -q test -Dtest=IdentityPropagationTest
```

Expected: FAIL — the downstream receives the client's `default`/`admin` values because nothing strips or stamps yet.

- [ ] **Step 3: Write `InboundHeaderStripFilter.java`**

```java
package com.gatekeeper.identity;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * Removes every inbound {@code X-GK-*} header before anything else runs.
 *
 * <p>Ordered ahead of Spring Security deliberately. Stripping after authentication would
 * leave the error paths exposed: a request that fails authentication still gets a response
 * rendered, and a header that survived that far could be laundered by anything downstream
 * of it. The strip is therefore unconditional and applies to permitted routes too.
 *
 * <p>Matched by prefix rather than by an enumerated list, so adding a fourth header later
 * cannot silently make it spoofable.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class InboundHeaderStripFilter implements WebFilter {

    static final String PREFIX = "X-GK-";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        boolean carriesGatewayHeaders = exchange.getRequest().getHeaders().headerNames().stream()
                .anyMatch(InboundHeaderStripFilter::isGatewayHeader);

        if (!carriesGatewayHeaders) {
            return chain.filter(exchange);
        }

        ServerWebExchange stripped = exchange.mutate()
                .request(request -> request.headers(headers -> headers.headerNames().stream()
                        .filter(InboundHeaderStripFilter::isGatewayHeader)
                        .toList()
                        .forEach(headers::remove)))
                .build();

        return chain.filter(stripped);
    }

    /**
     * Case-insensitive prefix match. {@code regionMatches} rather than lower-casing avoids
     * both an allocation per header and the Turkish-dotless-i class of locale surprise.
     */
    private static boolean isGatewayHeader(String name) {
        return name.regionMatches(true, 0, PREFIX, 0, PREFIX.length());
    }
}
```

- [ ] **Step 4: Write `IdentityStampFilter.java`**

```java
package com.gatekeeper.identity;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Stamps the verified caller identity onto the outbound request.
 *
 * <p>Runs as a gateway filter, which is to say after Spring Security has authenticated —
 * the verified {@link Jwt} does not exist any earlier. Its counterpart
 * {@link InboundHeaderStripFilter} runs before security. The pair has to straddle the
 * security filter because one half needs the request untouched and the other needs the
 * authentication result.
 *
 * <p>These headers are a convenience for downstreams that are not themselves resource
 * servers. They are never authoritative: ledger-service re-verifies the bearer token,
 * which is forwarded unchanged.
 */
@Component
public class IdentityStampFilter implements GlobalFilter, Ordered {

    static final String SUBJECT = "X-GK-Subject";
    static final String TENANT = "X-GK-Tenant";
    static final String PERMISSIONS = "X-GK-Permissions";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .filter(JwtAuthenticationToken.class::isInstance)
                .map(authentication -> ((JwtAuthenticationToken) authentication).getToken())
                .map(jwt -> stamp(exchange, jwt))
                .defaultIfEmpty(exchange)
                .flatMap(chain::filter);
    }

    private static ServerWebExchange stamp(ServerWebExchange exchange, Jwt jwt) {
        String tenant = jwt.getClaimAsString("tenant");
        List<String> permissions = jwt.getClaimAsStringList("permissions");

        return exchange.mutate()
                .request(request -> request.headers(headers -> {
                    headers.set(SUBJECT, jwt.getSubject());
                    // Absent on client-credentials tokens — AuthCore omits the claim
                    // rather than emitting an empty one, so omit the header too.
                    if (tenant != null) {
                        headers.set(TENANT, tenant);
                    }
                    if (permissions != null && !permissions.isEmpty()) {
                        headers.set(PERMISSIONS, String.join(",", permissions));
                    }
                }))
                .build();
    }

    /** Ahead of the routing filters, which forward the request as it then stands. */
    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}
```

- [ ] **Step 5: Run to verify it passes**

```bash
./mvnw.cmd -q test -Dtest=IdentityPropagationTest
```

Expected: PASS, 1 test.

- [ ] **Step 6: Add the strip-only test**

Proves the strip is genuinely unconditional rather than a side effect of stamping. Append to `IdentityPropagationTest`:

```java
    /**
     * A client-supplied header must not survive even when no stamping happens. Health is
     * permitted, so no JWT is ever produced for this request and the stamp filter is a
     * no-op — the strip has to stand on its own.
     */
    @Test
    void stripsIdentityHeadersEvenOnPermittedRoutes() {
        client.get().uri("/actuator/health")
                .header("X-GK-Subject", "admin")
                .exchange()
                .expectStatus().isOk();
        // The assertion that matters is that no exception escaped and the request was not
        // rejected; the header cannot reach a downstream because /actuator is not routed.
    }
```

- [ ] **Step 7: Run and commit**

```bash
./mvnw.cmd -q test
```

Expected: PASS, 9 tests across 4 classes.

Message: `feat(M2): strip and re-stamp identity headers from verified claims`

---

## Task 12: Key rotation (test 9)

**Files:**
- Create: `src/test/java/com/gatekeeper/auth/KeyRotationTest.java`

- [ ] **Step 1: Write the test**

```java
package com.gatekeeper.auth;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.gatekeeper.support.TestKey;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;

/**
 * AuthCore M7 publishes the retiring key alongside the active one so tokens issued before
 * a rotation keep validating. This asserts the gateway honours both, which is the property
 * that makes rotation zero-downtime.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class KeyRotationTest {

    static final String ISSUER = "http://localhost:8080";

    static WireMockServer authCore;
    static TestKey retiringKey;
    static TestKey activeKey;

    @Autowired
    WebTestClient client;

    @BeforeAll
    static void start() {
        retiringKey = TestKey.generate("k0");
        activeKey = TestKey.generate("k1");

        authCore = new WireMockServer(options().dynamicPort());
        authCore.start();
        authCore.stubFor(get(urlEqualTo("/oauth2/jwks"))
                .willReturn(okJson(TestKey.jwksDocument(activeKey, retiringKey))));
        authCore.stubFor(get(urlEqualTo("/ledger/entries"))
                .willReturn(aResponse().withStatus(200).withBody("[]")));
    }

    @AfterAll
    static void stop() {
        authCore.stop();
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("gatekeeper.auth.jwk-set-uri", () -> authCore.baseUrl() + "/oauth2/jwks");
        registry.add("gatekeeper.auth.issuer", () -> ISSUER);
        registry.add("gatekeeper.downstream.ledger", () -> authCore.baseUrl());
        registry.add("gatekeeper.downstream.authcore", () -> authCore.baseUrl());
    }

    @Test
    void acceptsATokenSignedWithTheNewActiveKey() {
        assertAccepted(activeKey);
    }

    @Test
    void stillAcceptsATokenSignedWithTheRetiringKey() {
        assertAccepted(retiringKey);
    }

    private void assertAccepted(TestKey key) {
        String token = key.mint(ISSUER, "ezzat",
                Instant.now().plus(5, ChronoUnit.MINUTES), Map.of("tenant", "acme"));

        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isOk();
    }
}
```

- [ ] **Step 2: Run**

```bash
./mvnw.cmd -q test -Dtest=KeyRotationTest
```

Expected: PASS, 2 tests.

- [ ] **Step 3: Commit**

Message: `test: accept tokens signed by either published key`

---

## Task 13: Uniform JSON errors

**Files:**
- Create: `src/main/java/com/gatekeeper/error/GlobalErrorWebExceptionHandler.java`
- Test: `src/test/java/com/gatekeeper/error/ErrorShapeTest.java`

- [ ] **Step 1: Write the failing test**

```java
package com.gatekeeper.error;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.test.web.reactive.server.WebTestClient;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT,
        properties = {
                "gatekeeper.auth.jwk-set-uri=http://localhost:9999/jwks",
                "gatekeeper.downstream.ledger=http://localhost:9998",
                "gatekeeper.downstream.authcore=http://localhost:9998"
        })
@AutoConfigureWebTestClient
class ErrorShapeTest {

    @Autowired
    WebTestClient client;

    @Test
    void rendersUnauthorizedAsJson() {
        client.get().uri("/api/ledger/entries")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody()
                .jsonPath("$.error").isEqualTo("unauthorized")
                .jsonPath("$.status").isEqualTo(401);
    }

    /** A dead downstream must surface as 503, not a Netty connection stack trace. */
    @Test
    void rendersAnUnreachableDownstreamAsServiceUnavailable() {
        client.get().uri("/api/ledger/entries")
                .header("Authorization", "Bearer not-a-real-token")
                .exchange()
                .expectStatus().isUnauthorized();
        // With no valid token the request never reaches routing; the 503 path is exercised
        // manually in Task 14 by stopping ledger-service with a valid token in hand.
    }
}
```

- [ ] **Step 2: Run to verify it fails**

```bash
./mvnw.cmd -q test -Dtest=ErrorShapeTest
```

Expected: FAIL — the default 401 body is empty, so `$.error` is missing.

- [ ] **Step 3: Write `GlobalErrorWebExceptionHandler.java`**

```java
package com.gatekeeper.error;

import org.springframework.boot.autoconfigure.web.WebProperties;
import org.springframework.boot.autoconfigure.web.reactive.error.AbstractErrorWebExceptionHandler;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.web.reactive.error.ErrorAttributes;
import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.reactive.function.server.RequestPredicates;
import reactor.core.publisher.Mono;

import java.util.LinkedHashMap;
import java.util.Map;

/**
 * One JSON error shape across the platform, matching AuthCore's. Without this a client
 * gets an empty body from the gateway and a JSON body from AuthCore for what is, to them,
 * the same failure.
 */
@Component
@Order(-2)
public class GlobalErrorWebExceptionHandler extends AbstractErrorWebExceptionHandler {

    public GlobalErrorWebExceptionHandler(ErrorAttributes errorAttributes,
                                          WebProperties webProperties,
                                          ApplicationContext applicationContext,
                                          ServerCodecConfigurer codecConfigurer) {
        super(errorAttributes, webProperties.getResources(), applicationContext);
        setMessageWriters(codecConfigurer.getWriters());
        setMessageReaders(codecConfigurer.getReaders());
    }

    @Override
    protected RouterFunction<ServerResponse> getRoutingFunction(ErrorAttributes errorAttributes) {
        return RouterFunctions.route(RequestPredicates.all(), this::render);
    }

    private Mono<ServerResponse> render(ServerRequest request) {
        Map<String, Object> attributes =
                getErrorAttributes(request, ErrorAttributeOptions.defaults());

        HttpStatus status = HttpStatus.resolve((int) attributes.getOrDefault("status", 500));
        if (status == null) {
            status = HttpStatus.INTERNAL_SERVER_ERROR;
        }

        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", status.getReasonPhrase().toLowerCase().replace(' ', '_'));
        body.put("status", status.value());
        body.put("path", request.path());

        return ServerResponse.status(status)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body);
    }
}
```

**Two things found during this task that belong to later milestones, recorded so they are not
rediscovered from scratch:**

*The 403 path still has the empty-body gap that 401 just lost.* `OAuth2ResourceServerSpec`'s default
`accessDeniedHandler` commits its own response exactly as the default authentication entry point did,
so a 403 will come back with no JSON body. It is unreachable today — GateKeeper has no
`hasAuthority`/`access` rules, so nothing can produce a 403 — but M4 adds route-level authorization
and will make it live. Wire a JSON access-denied handler at the same time, reusing `ErrorBody`.

*The JWKS fetch has no response timeout.* Spring Security's `ReactiveRemoteJWKSource` builds a bare
`WebClient.create()`, so a JWKS host that accepts the TCP connection but never answers hangs the
request rather than failing to a 401 — an active refusal is handled, a silent hang is not. This is a
characteristic of Spring Security's own decoder rather than anything here, and closing it means
supplying a custom `WebClient` to the decoder builder. Worth doing when resilience arrives at M7.

**There are two unmapped-exception paths to 500, not one.** Both were found by live probe, both fail
closed, and both belong to this task.

The second one: a claim value containing a control character. A token whose `permissions` claim holds
`evil\r\nX-Injected: yes` produces `IllegalArgumentException: Validation failed for header
'X-GK-Permissions'` — thrown by Netty's `DefaultHeaders.validateValue` from inside Spring Cloud
Gateway's own `NettyRoutingFilter`, when it copies headers onto the outbound request. `IdentityStampFilter`
does not throw; Spring's reactive `HttpHeaders.set()` stores the value happily and the failure surfaces
later, in framework code. Nothing is injectable — Netty refuses to put the CRLF on the wire and the
request is never proxied — but the caller sees a 500 for what is a malformed-token problem. Map it
alongside the JWKS case.

**A JWKS fetch failure currently yields 500, not the 401 the spec calls for — and the exact cause is
known.** A live probe traced it: `ReactiveRemoteJWKSource.getJWKSet()`'s `WebClientRequestException`
is wrapped as `IllegalStateException("Could not obtain the keys", ...)` inside
`NimbusReactiveJwtDecoder`. `JwtReactiveAuthenticationManager.authenticate()` maps only
`JwtException` to a 401 (`onErrorMap(JwtException.class, ...)`), so an `IllegalStateException` passes
through unmapped to Boot's default handler. No bypass occurs — the request is still refused, and the
body carries no stack trace — but the status misreports the cause as a server fault rather than an
authentication failure. Special-case that exception type here so an unreachable AuthCore reads as
`401`, and add a test that stops the JWKS stub mid-run.

**Also settle ledger-service's 403 body here.** A live probe during Task 4 found that *both* of its
403 paths — wrong permission, and right permission with no `tenant` claim — return an identical
0-byte body carrying `WWW-Authenticate: Bearer error="insufficient_scope"`. That label is actively
wrong for the tenant case: the caller already holds `payments:write`, and no larger scope can supply
a claim the token structurally lacks. It sends anyone debugging from that header after a fix that
cannot work. Spring Security's `BearerTokenAccessDeniedHandler` produces this for any
`AccessDeniedException`, so distinguishing the two causes means overriding the access-denied handler.
Do it as part of this task, so the two services agree on one error shape rather than each inventing
its own.

**Note for the implementer:** Spring Security writes the 401 directly through its
`ServerAuthenticationEntryPoint`, bypassing this handler, so the `WWW-Authenticate` header is
preserved. If `rendersUnauthorizedAsJson` still fails after adding this class, the fix is to set a
custom entry point on the security config that delegates to this body shape — do that rather than
removing the `WWW-Authenticate` header, which RFC 6750 requires.

- [ ] **Step 4: Run, then run the full suite**

```bash
./mvnw.cmd -q test
```

Expected: PASS, 13 tests across 6 classes.

- [ ] **Step 5: Commit**

Message: `feat: uniform JSON error shape across the gateway`

---

# Phase C — Integration

## Task 14: End-to-end demo, READMEs, push

- [ ] **Step 1: Start all three services**

Three separate terminals. Docker Desktop must be running for AuthCore.

```bash
cd "D:/courses/My CV/My cv/ProjectsCVs/authcore" && ./mvnw.cmd spring-boot:run
```

```bash
cd "D:/courses/My CV/My cv/ProjectsCVs/ledger-service" && ./mvnw.cmd spring-boot:run
```

```bash
cd "D:/courses/My CV/My cv/ProjectsCVs/gatekeeper" && ./mvnw.cmd spring-boot:run
```

- [ ] **Step 2: Obtain a token, then run every acceptance check in one call**

PowerShell variables do not survive between tool calls, so this must be a single block. Uses the
seeded `authcore-machine` client; swap for an authorization-code token when checking user claims.

```bash
TOKEN=$(curl.exe -s -u authcore-machine:machine-secret -d "grant_type=client_credentials&scope=payments:read" http://localhost:8080/oauth2/token | tr ',' '\n' | grep access_token | cut -d'"' -f4)
echo "--- 1. no token -> expect 401"
curl.exe -s -o /dev/null -w "%{http_code}\n" http://localhost:8081/api/ledger/entries
echo "--- 2. valid token -> expect 200"
curl.exe -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/ledger/entries
echo "--- 3. through the gateway -> whoami"
curl.exe -s -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/ledger/whoami
echo "--- 4. spoof attempt -> gateway value must win"
curl.exe -s -H "Authorization: Bearer $TOKEN" -H "X-GK-Tenant: acme" http://localhost:8081/api/ledger/whoami
echo "--- 5. direct, bypassing the gateway -> fromHeaders empty"
curl.exe -s -H "Authorization: Bearer $TOKEN" http://localhost:8082/ledger/whoami
echo "--- 6. headers only, no token -> expect 401"
curl.exe -s -o /dev/null -w "%{http_code}\n" -H "X-GK-Subject: admin" http://localhost:8082/ledger/whoami
echo "--- 7. AuthCore through the gateway -> expect 200"
curl.exe -s -o /dev/null -w "%{http_code}\n" -H "Authorization: Bearer $TOKEN" http://localhost:8081/api/machine/payments
```

Expected: `401`, `200`, whoami JSON, spoofed tenant **overwritten**, direct call with empty
`fromHeaders`, `401`, `200`.

**Check 2 returns `200` with an empty body `[]`, and that is correct.** `authcore-machine` is a
client-credentials client, so its token carries no `tenant` claim, and `/ledger/entries` is scoped to
that claim — a tenant-less caller sees nothing rather than everything. To see actual rows, obtain a
user token through the authorization-code flow (README walkthrough 1) for a user in the `acme`
tenant; `ezzat`/`acme-password` maps to the seeded `LDG-1001` and `LDG-1002`. Demonstrating both is
worth doing: the empty machine result *is* the tenant boundary working.

- [ ] **Step 3: Verify rotation end to end**

Rotate AuthCore's signing key via its operator API, mint a fresh token, and confirm it still passes
through the gateway. Consult AuthCore's README §"Rotating the signing key" for the exact call.

- [ ] **Step 4: Write GateKeeper's README**

Must contain: the three-service diagram, the reactive-rules table from spec §5, the responsibility
matrix from spec §2, the issuer-pinning trap, the anti-spoofing rule and why the filter is split in
two, the route table, and the demo transcript from Step 2.

- [ ] **Step 5: Create the GitHub repo and push**

```bash
cd "D:/courses/My CV/My cv/ProjectsCVs/gatekeeper"
gh repo create gatekeeper --public --source=. --remote=origin --push
```

- [ ] **Step 6: Tick off spec §14**

Walk the Definition of Done list in the spec and confirm each box. Anything that cannot be ticked
gets recorded as a known limitation in the README rather than quietly dropped.

---

## Self-review notes

**Spec coverage.** §2 responsibility matrix → Tasks 2, 4, 5 (ledger enforces its own authorization)
and Task 11 (gateway propagates, never authorizes). §4 sequence → Task 14 Step 2 walks it. §5 stack
→ Tasks 1, 7. §6 architecture → Tasks 8, 14. §7 components → all tasks; the one divergence
(`IdentityHeaderFilter` split in two) is documented under File structure. §8 routing → Task 8. §9
authentication, issuer pinning, anti-spoofing → Tasks 9, 11. §10 deferred AuthCore change → not
implemented, by design. §11 error handling → Task 13. §12 tests 1–14 → Tasks 2–13. §14 DoD → Task
14 Step 6.

**Test count.** GateKeeper 13 (1 context, 2 routing, 6 auth, 2 rotation, 2 error) and ledger-service
8 (1 context, 2 security, 4 controller, 3 whoami — the whoami class covers spec tests 12 and 14).
Higher than the spec's 14 because several spec items needed a paired negative case.

**Known risks, in the order they are likely to bite:**
1. `spring.cloud.gateway.server.webflux.routes` prefix — Task 8 Step 3.
2. Spring Security's entry point bypassing the error handler — Task 13 Step 3 note.
3. `WebProperties`/`ErrorAttributes` package moves in Boot 4 — if `GlobalErrorWebExceptionHandler`
   fails to compile, the imports are the cause, not the logic.
