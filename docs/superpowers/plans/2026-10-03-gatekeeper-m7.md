# GateKeeper M7 — Resilience — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Bound every wait the gateway makes, cut off a failing downstream with a per-downstream circuit breaker, isolate the downstreams with a per-downstream bulkhead, retry idempotent GETs once, answer an unreachable JWKS with 503, and make Lettuce reconnect within 2 s.

**Architecture:** Spring Cloud Gateway's own `CircuitBreaker` and `Retry` route filters, backed by Resilience4j through Spring Cloud CircuitBreaker (breakers and semaphore bulkheads named `authcore` and `ledger`, configured from our strictly bound `gatekeeper.resilience` properties). Global and per-route HTTP-client timeouts. `GlobalErrorWebExceptionHandler` maps every new failure to the platform shape with a fixed `detail`. A downstream 500 passes through untouched and never counts; 502/503/504 count and are replaced, headers included.

**Tech Stack:** Spring Boot 4.0.7, Spring Cloud 2025.1.2 (Gateway server-webflux 5.0.2, CircuitBreaker 5.0.2), Resilience4j 2.3.0, Spring Security 7.0.6, Lettuce 6.8.2, Reactor Netty, JUnit 6, AssertJ, WireMock 3.13.2, reactor-test.

**Spec:** `docs/superpowers/specs/2026-10-03-gatekeeper-m7-design.md`. Read it before any task. Section numbers below refer to it. **The behaviour it fixes is not negotiable in this plan:** a downstream 500 passes through and never counts; 502/503/504 count and are replaced by our shape (headers too); `CircuitBreaker` precedes `Retry`; POST is never retried; a retry costs one rate-limit token; bulkhead refusals never count; JWKS failures are 503, not 401.

---

## Conventions for every task

- **Branch:** `feature/m7-task-N` off `master`; the controller merges with `git merge --no-ff`. Do not merge or push.
- **Build:** `.\mvnw.cmd -o ...` from the repo root, in PowerShell. Never `mvn`. `;` not `&&`. The new dependencies were downloaded into `~/.m2` while planning; if an offline build still reports a missing artifact, run that one build without `-o` and say so.
- **Redis must be running:** `docker ps` shows `authcore-redis-1` Up; else `docker start authcore-redis-1`.
- **Mutations:** Maven may not recompile a file restored with an old timestamp. Use `clean` for every mutation run and the run after restoring; restore with `git checkout -- src/main`.
- **Commits:** message written to a file, `git commit -F <file>`, UTF-8 without BOM. **No `Co-Authored-By` line and no mention of Claude or any AI tool, anywhere — an absolute rule of the repo owner.**
- **Files:** end every file with a newline; committed blobs LF.
- **Never a single-digit port** for a "closed port" in tests: Reactor Netty 1.3.6 mis-parses `localhost:9` in the gateway's routing call as a host name (verified). Bind `new ServerSocket(0)`, read its port, close it.
- **Verify, don't assume:** where a step says "verify", use `javap`/`jar tf` on the jar in `~/.m2`. Facts already verified while planning are stated as such.
- **A test that passes the moment you write it has proven nothing.** Each task says how to see it fail.

## File map

| File | Task | Responsibility |
|---|---|---|
| `src/main/java/com/gatekeeper/redis/RedisConfig.java` | 1 | Lettuce reconnect delay |
| `pom.xml` | 2 | Spring Cloud CircuitBreaker (Resilience4j) starter, `resilience4j-bulkhead` |
| `src/main/java/com/gatekeeper/resilience/ResilienceProperties.java` | 2 | `gatekeeper.resilience`, strict, validated |
| `src/main/resources/application.yml` | 2–7 | The values, the routes' timeouts and filters |
| `src/main/java/com/gatekeeper/config/JwtDecoderConfig.java` | 3 | JWKS `WebClient` with timeouts |
| `src/main/java/com/gatekeeper/config/JwksFetchLogging.java` | 3 | WARN once / INFO on recovery for JWKS fetches |
| `src/main/java/com/gatekeeper/error/GlobalErrorWebExceptionHandler.java` | 3–7 | One mapping per failure: status, `detail`, `Retry-After`; strips downstream headers |
| `src/main/java/com/gatekeeper/resilience/ResilienceConfig.java` | 5, 7 | Breakers and bulkheads for `authcore` and `ledger`; transition logging |

---

### Task 1: Lettuce reconnects within 2 s (spec §3)

**Files:**
- Modify: `src/main/java/com/gatekeeper/redis/RedisConfig.java`
- Test: `src/test/java/com/gatekeeper/redis/ReconnectDelayTest.java`

- [ ] **Step 1: Branch**

`git checkout master; git checkout -b feature/m7-task-1`

- [ ] **Step 2: Verify the two APIs this task uses**

```powershell
$m2 = "$env:USERPROFILE\.m2\repository"
javap -cp (Get-ChildItem -Recurse "$m2\org\springframework\boot\spring-boot-data-redis\4.0.7" -Filter *.jar | Where-Object Name -notmatch 'sources|javadoc' | Select-Object -First 1).FullName org.springframework.boot.data.redis.autoconfigure.ClientResourcesBuilderCustomizer
javap -cp (Get-ChildItem -Recurse "$m2\io\lettuce\lettuce-core\6.8.2.RELEASE" -Filter lettuce-core-6.8.2.RELEASE.jar).FullName io.lettuce.core.resource.Delay
```

Expected: `void customize(io.lettuce.core.resource.ClientResources$Builder)`; `Delay` has `static Delay fullJitter(java.time.Duration, java.time.Duration, long, java.util.concurrent.TimeUnit)` and `public abstract java.time.Duration createDelay(long)`. If `createDelay` returns something other than `Duration`, adapt the test's assertions to it and say so.

Semantics (verified in the 6.8.2 source while planning): `fullJitter(lower, upper, base, unit)` gives, for attempt *n*, `t = min(upper, base·2^(n−1))`, then `t/2 + random(0, t/2)`, clamped to `[lower, upper]`. With `(100 ms, 2 s, 100, MILLISECONDS)`: attempt 1 → 100 ms; attempt 5 → 800–1600 ms; attempt 6 onward → 1000–2000 ms. Exponential, jittered, never above 2 s, never below 100 ms.

- [ ] **Step 3: Write the failing test**

`src/test/java/com/gatekeeper/redis/ReconnectDelayTest.java`:

```java
package com.gatekeeper.redis;

import io.lettuce.core.resource.Delay;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.connection.lettuce.LettuceConnectionFactory;

import java.time.Duration;
import java.util.HashSet;
import java.util.Set;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Lettuce reconnects within 2 s of Redis returning, not after its default backoff of up to 30 s.
 * The M7 design, section 3: in M6's live run the revocation check refused every bearer token for
 * 17.8 s after Redis was back, waiting for that backoff.
 */
@SpringBootTest
class ReconnectDelayTest {

    @Autowired
    LettuceConnectionFactory connectionFactory;

    @Test
    void neverWaitsMoreThanTwoSecondsNorLessThanAHundredMillis() {
        for (long attempt = 1; attempt <= 40; attempt++) {
            Duration delay = RedisConfig.RECONNECT_DELAY.createDelay(attempt);
            assertThat(delay).as("attempt %d", attempt)
                    .isBetween(Duration.ofMillis(100), Duration.ofSeconds(2));
        }
    }

    /** Exponential: the first attempt is quick, later ones back off to at least half the cap. */
    @Test
    void backsOffExponentially() {
        assertThat(RedisConfig.RECONNECT_DELAY.createDelay(1)).isEqualTo(Duration.ofMillis(100));
        assertThat(RedisConfig.RECONNECT_DELAY.createDelay(20)).isGreaterThanOrEqualTo(Duration.ofSeconds(1));
    }

    /** Jitter, so several gateway instances do not all reconnect in the same instant. */
    @Test
    void isJittered() {
        Set<Duration> seen = new HashSet<>();
        for (int i = 0; i < 200; i++) {
            seen.add(RedisConfig.RECONNECT_DELAY.createDelay(10));
        }
        assertThat(seen).hasSizeGreaterThan(1);
    }

    /** The client actually in use carries it, not Lettuce's default. */
    @Test
    void isTheDelayTheClientUses() {
        Delay inUse = connectionFactory.getClientResources().reconnectDelay();

        assertThat(inUse.getClass().getSimpleName()).isEqualTo("FullJitterDelay");
        assertThat(inUse.createDelay(40)).isLessThanOrEqualTo(Duration.ofSeconds(2));
    }
}
```

- [ ] **Step 4: Run to see it fail**

Run: `.\mvnw.cmd -o -q test "-Dtest=ReconnectDelayTest"`
Expected: COMPILATION ERROR — `RedisConfig.RECONNECT_DELAY` does not exist.

- [ ] **Step 5: Implement**

Replace `src/main/java/com/gatekeeper/redis/RedisConfig.java` with:

```java
package com.gatekeeper.redis;

import io.lettuce.core.resource.Delay;
import org.springframework.boot.data.redis.autoconfigure.ClientResourcesBuilderCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;

import java.time.Duration;
import java.util.concurrent.TimeUnit;

@Configuration
public class RedisConfig {

    /**
     * How long Lettuce waits between reconnect attempts: exponential from 100 ms, capped at 2 s, with
     * jitter. The M7 design, section 3.
     *
     * <p>Lettuce's default is exponential up to 30 s. In M6's live run the gateway reconnected 17 s
     * after Redis was back, and the revocation check refused every bearer token until then. With a
     * 2 s cap it reconnects within about 2 s, and the revocation breaker's next probe — at most one
     * 5 s window later — closes it. Client-wide: the rate limiter and the API-key cache recover faster
     * too. Jitter keeps several instances from reconnecting in the same instant. A Redis that accepts
     * and never answers is unchanged: each attempt is still bounded by Lettuce's handshake timeout.
     *
     * <p>{@code fullJitter} is stateless, so one instance serves every connection.
     */
    static final Delay RECONNECT_DELAY =
            Delay.fullJitter(Duration.ofMillis(100), Duration.ofSeconds(2), 100, TimeUnit.MILLISECONDS);

    /** One step for every consumer, so one Redis costs one connection attempt at a time. */
    @Bean
    public RedisConnectionStep redisConnectionStep(ReactiveStringRedisTemplate redis) {
        return new RedisConnectionStep(redis);
    }

    @Bean
    public ClientResourcesBuilderCustomizer reconnectQuickly() {
        return builder -> builder.reconnectDelay(RECONNECT_DELAY);
    }
}
```

- [ ] **Step 6: Run the test, then make it fail on purpose**

Run: `.\mvnw.cmd -o -q test "-Dtest=ReconnectDelayTest"` — expected 4 pass.

Then comment out the `reconnectQuickly` bean (keep the constant), run with `clean`: `isTheDelayTheClientUses` must fail (the class is Lettuce's default). Restore.

- [ ] **Step 7: Full suite and commit**

Run: `.\mvnw.cmd -o test` — expected `Tests run: 282, Failures: 0, Errors: 0` (278 + 4).

```
fix(M7): reconnect to Redis within 2 s, not after up to 30

Lettuce's default reconnect backoff is exponential up to 30 s; in M6's
live run the revocation check refused bearer tokens for 17.8 s after
Redis returned. A full-jitter delay from 100 ms capped at 2 s brings
recovery to about 7 s at worst, for every Redis consumer.
```

---

### Task 2: Dependencies and `gatekeeper.resilience` (spec §10–§12)

**Files:**
- Modify: `pom.xml`
- Create: `src/main/java/com/gatekeeper/resilience/ResilienceProperties.java`
- Modify: `src/main/resources/application.yml`
- Test: `src/test/java/com/gatekeeper/resilience/ResiliencePropertiesTest.java`

- [ ] **Step 1: Branch**

`git checkout master; git checkout -b feature/m7-task-2`

- [ ] **Step 2: Add the dependencies**

In `pom.xml`, after the `spring-boot-starter-data-redis-reactive` dependency, add:

```xml
        <!-- M7: Spring Cloud Gateway's CircuitBreaker filter, backed by Resilience4j. Brings
             resilience4j-spring-boot3, which supplies the registries. -->
        <dependency>
            <groupId>org.springframework.cloud</groupId>
            <artifactId>spring-cloud-starter-circuitbreaker-reactor-resilience4j</artifactId>
        </dependency>
        <!-- Not brought by the starter (it is optional there). With it on the classpath Spring Cloud
             CircuitBreaker puts a semaphore bulkhead inside every breaker. The M7 design, section 10. -->
        <dependency>
            <groupId>io.github.resilience4j</groupId>
            <artifactId>resilience4j-bulkhead</artifactId>
        </dependency>
```

Versions come from Spring Cloud's BOM (CircuitBreaker 5.0.2, Resilience4j 2.3.0). Check: `.\mvnw.cmd -o -q dependency:tree "-Dincludes=io.github.resilience4j"` lists 2.3.0 only.

- [ ] **Step 3: Write the failing test**

`src/test/java/com/gatekeeper/resilience/ResiliencePropertiesTest.java`:

```java
package com.gatekeeper.resilience;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/** Bound strictly and validated at startup, as in M5 and M6. The M7 design, section 12. */
class ResiliencePropertiesTest {

    static final String[] VALID = {
            "gatekeeper.resilience.jwks-timeout=2s",
            "gatekeeper.resilience.response-timeout-millis.authcore-accounts=5000",
            "gatekeeper.resilience.response-timeout-millis.authcore-machine=5000",
            "gatekeeper.resilience.response-timeout-millis.ledger=5000",
            "gatekeeper.resilience.breaker.sliding-window-size=20",
            "gatekeeper.resilience.breaker.minimum-calls=10",
            "gatekeeper.resilience.breaker.failure-rate-threshold=50",
            "gatekeeper.resilience.breaker.open-for=10s",
            "gatekeeper.resilience.breaker.trial-calls=3",
            "gatekeeper.resilience.bulkhead.max-concurrent-calls=50",
    };

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(TestConfig.class);

    @Test
    void bindsAValidConfiguration() {
        runner.withPropertyValues(VALID).run(context -> {
            assertThat(context).hasNotFailed();
            ResilienceProperties properties = context.getBean(ResilienceProperties.class);
            assertThat(properties.jwksTimeout()).isEqualTo(Duration.ofSeconds(2));
            assertThat(properties.responseTimeoutMillis()).containsEntry("ledger", 5000L);
            assertThat(properties.breaker().openFor()).isEqualTo(Duration.ofSeconds(10));
            assertThat(properties.breaker().failureRateThreshold()).isEqualTo(50f);
            assertThat(properties.bulkhead().maxConcurrentCalls()).isEqualTo(50);
        });
    }

    @Test
    void refusesAMissingBlock() {
        runner.run(context -> assertThat(messageChain(context.getStartupFailure()))
                .contains("gatekeeper.resilience"));
    }

    @Test
    void refusesANonPositiveRouteTimeout() {
        refuses("gatekeeper.resilience.response-timeout-millis.ledger=0", "response-timeout-millis");
    }

    @Test
    void refusesMinimumCallsAboveTheWindow() {
        refuses("gatekeeper.resilience.breaker.minimum-calls=21", "minimum-calls");
    }

    @Test
    void refusesAFailureRateOutsideOneToAHundred() {
        refuses("gatekeeper.resilience.breaker.failure-rate-threshold=0", "failure-rate-threshold");
        refuses("gatekeeper.resilience.breaker.failure-rate-threshold=101", "failure-rate-threshold");
    }

    @Test
    void refusesAZeroBulkhead() {
        refuses("gatekeeper.resilience.bulkhead.max-concurrent-calls=0", "max-concurrent-calls");
    }

    /** A typo fails the boot rather than leaving the breaker on Resilience4j's defaults. */
    @Test
    void refusesAnUnknownKey() {
        refuses("gatekeeper.resilience.breaker.open-fro=5s", "open-fro");
    }

    private void refuses(String override, String expectedInMessage) {
        runner.withPropertyValues(VALID).withPropertyValues(override)
                .run(context -> assertThat(messageChain(context.getStartupFailure())).contains(expectedInMessage));
    }

    private static String messageChain(Throwable failure) {
        assertThat(failure).as("startup failure").isNotNull();
        StringBuilder chain = new StringBuilder();
        for (Throwable t = failure; t != null; t = t.getCause()) {
            if (t.getMessage() != null) {
                chain.append(t.getMessage()).append(' ');
            }
        }
        return chain.toString();
    }

    @Configuration
    @EnableConfigurationProperties(ResilienceProperties.class)
    static class TestConfig {
    }
}
```

- [ ] **Step 4: Run to see it fail**

Run: `.\mvnw.cmd -o -q test "-Dtest=ResiliencePropertiesTest"` — expected COMPILATION ERROR.

- [ ] **Step 5: Implement the properties**

`src/main/java/com/gatekeeper/resilience/ResilienceProperties.java`:

```java
package com.gatekeeper.resilience;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;
import java.util.Map;

/**
 * {@code gatekeeper.resilience}. The M7 design, sections 4 to 12.
 *
 * <p>Strictly bound: an unknown key fails the boot. That is why the breakers and bulkheads are
 * configured from here rather than from Resilience4j's own {@code resilience4j.*} properties, which
 * would also bind but ignore a misspelt key and leave the breaker on its defaults. No defaults in code:
 * {@code application.yml} supplies every value, and a missing one fails the boot.
 *
 * @param jwksTimeout           connect and response timeout for fetching AuthCore's key set
 * @param responseTimeoutMillis each route's response timeout, by route id, in milliseconds. Plain
 *                              milliseconds because the routes' {@code metadata} refers to these values,
 *                              and Spring Cloud Gateway parses a route's {@code response-timeout} with
 *                              {@code Long.parseLong}, silently ignoring anything else
 * @param breaker               the circuit breaker each downstream gets
 * @param bulkhead              the bulkhead each downstream gets
 */
@ConfigurationProperties(prefix = "gatekeeper.resilience", ignoreUnknownFields = false)
public record ResilienceProperties(
        Duration jwksTimeout,
        Map<String, Long> responseTimeoutMillis,
        Breaker breaker,
        Bulkhead bulkhead) {

    public ResilienceProperties {
        if (jwksTimeout == null || jwksTimeout.isZero() || jwksTimeout.isNegative()) {
            throw new IllegalArgumentException("gatekeeper.resilience.jwks-timeout must be a positive duration");
        }
        if (responseTimeoutMillis == null || responseTimeoutMillis.isEmpty()) {
            throw new IllegalArgumentException("gatekeeper.resilience.response-timeout-millis must name every route");
        }
        responseTimeoutMillis.forEach((route, millis) -> {
            if (millis == null || millis <= 0) {
                throw new IllegalArgumentException(
                        "gatekeeper.resilience.response-timeout-millis." + route + " must be positive");
            }
        });
        if (breaker == null) {
            throw new IllegalArgumentException("gatekeeper.resilience.breaker is required");
        }
        if (bulkhead == null) {
            throw new IllegalArgumentException("gatekeeper.resilience.bulkhead is required");
        }
        responseTimeoutMillis = Map.copyOf(responseTimeoutMillis);
    }

    /**
     * @param slidingWindowSize    how many of the latest calls the failure rate is judged over
     * @param minimumCalls         how many calls the window needs before it judges at all
     * @param failureRateThreshold the failure percentage, 1 to 100, at which it opens
     * @param openFor              how long it stays open before letting trial calls through
     * @param trialCalls           how many trial calls decide whether it closes again
     */
    public record Breaker(int slidingWindowSize, int minimumCalls, float failureRateThreshold,
                          Duration openFor, int trialCalls) {

        public Breaker {
            if (slidingWindowSize < 1) {
                throw new IllegalArgumentException("gatekeeper.resilience.breaker.sliding-window-size must be at least 1");
            }
            if (minimumCalls < 1 || minimumCalls > slidingWindowSize) {
                throw new IllegalArgumentException(
                        "gatekeeper.resilience.breaker.minimum-calls must be between 1 and sliding-window-size");
            }
            if (failureRateThreshold < 1 || failureRateThreshold > 100) {
                throw new IllegalArgumentException(
                        "gatekeeper.resilience.breaker.failure-rate-threshold must be between 1 and 100");
            }
            if (openFor == null || openFor.isZero() || openFor.isNegative()) {
                throw new IllegalArgumentException("gatekeeper.resilience.breaker.open-for must be a positive duration");
            }
            if (trialCalls < 1) {
                throw new IllegalArgumentException("gatekeeper.resilience.breaker.trial-calls must be at least 1");
            }
        }
    }

    /** @param maxConcurrentCalls how many requests may be in flight to one downstream at once */
    public record Bulkhead(int maxConcurrentCalls) {

        public Bulkhead {
            if (maxConcurrentCalls < 1) {
                throw new IllegalArgumentException(
                        "gatekeeper.resilience.bulkhead.max-concurrent-calls must be at least 1");
            }
        }
    }
}
```

Note `refusesAMissingBlock`: with no `gatekeeper.resilience.*` property, Boot 4.0.7 constructs the record with nulls (verified in M6 for `RevocationProperties`), so the first check throws with a message containing `gatekeeper.resilience`.

- [ ] **Step 6: Add the production values**

In `src/main/resources/application.yml`, as a sibling of `revocation:` under `gatekeeper:` (two-space indent), after the `revocation:` block:

```yaml
  resilience:
    # Fetching AuthCore's key set: connect and response timeout. Past it, bearer tokens that need a
    # key fetch are refused 503 KEYS_UNAVAILABLE rather than left hanging. The M7 design, section 4.
    jwks-timeout: 2s
    # Each route's response timeout, by route id, in PLAIN MILLISECONDS: the routes' metadata refers
    # to these, and Spring Cloud Gateway silently ignores a non-numeric route timeout. A timeout is
    # answered 504 DOWNSTREAM_TIMEOUT. The M7 design, section 5.
    response-timeout-millis:
      authcore-accounts: 5000
      authcore-machine: 5000
      ledger: 5000
    # One breaker per downstream (authcore, ledger). It counts connect errors, timeouts and
    # downstream 502/503/504 — never a 500, which is the downstream's own answer. The M7 design,
    # sections 6 and 7.
    breaker:
      sliding-window-size: 20
      minimum-calls: 10
      failure-rate-threshold: 50
      open-for: 10s
      trial-calls: 3
    # One semaphore bulkhead per downstream: beyond this many requests in flight, refused at once
    # 503 DOWNSTREAM_BUSY. A refusal never counts as a breaker failure. The M7 design, section 10.
    bulkhead:
      max-concurrent-calls: 50
```

- [ ] **Step 7: Run, then the suite**

Run: `.\mvnw.cmd -o -q test "-Dtest=ResiliencePropertiesTest"` — expected 7 pass.

Run: `.\mvnw.cmd -o test` — expected 289 (282 + 7), 0 failures. This also proves the new starter starts cleanly with nothing using it yet. If anything else in the suite changes (an actuator health component, a log line a test asserts), report it.

- [ ] **Step 8: Commit**

```
feat(M7): add the resilience dependencies and gatekeeper.resilience

Spring Cloud CircuitBreaker with Resilience4j and its semaphore
bulkhead, and the strictly bound, validated properties every M7 value
comes from: the JWKS timeout, each route's response timeout in plain
milliseconds, and the breaker's and bulkhead's limits.
```

---

### Task 3: The JWKS fetch times out, and an unreachable key set is 503 (spec §4, §8, §14)

**Files:**
- Modify: `src/main/java/com/gatekeeper/config/JwtDecoderConfig.java`
- Create: `src/main/java/com/gatekeeper/config/JwksFetchLogging.java`
- Modify: `src/main/java/com/gatekeeper/error/GlobalErrorWebExceptionHandler.java`
- Modify: `src/main/resources/application.yml` (two comments)
- Modify: `src/test/java/com/gatekeeper/error/UnreachableJwksErrorShapeTest.java`
- Test: `src/test/java/com/gatekeeper/config/JwksTimeoutTest.java`, `src/test/java/com/gatekeeper/config/JwksFetchLoggingTest.java`

- [ ] **Step 1: Branch**

`git checkout master; git checkout -b feature/m7-task-3`

- [ ] **Step 2: Write the failing tests**

`src/test/java/com/gatekeeper/config/JwksTimeoutTest.java`:

```java
package com.gatekeeper.config;

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
import java.net.Socket;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A key set that accepts the connection and never answers. Before M7 the request hung; now it is
 * refused 503 KEYS_UNAVAILABLE within about the JWKS timeout. The M7 design, section 4.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class JwksTimeoutTest {

    static final String ISSUER = "http://localhost:8080";
    static final List<Socket> held = new CopyOnWriteArrayList<>();
    static ServerSocket silent;
    static TestKey key;

    @Autowired
    WebTestClient client;

    @BeforeAll
    static void start() throws IOException {
        key = TestKey.generate("k1");
        silent = new ServerSocket(0);
        Thread acceptor = new Thread(() -> {
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
    }

    @AfterAll
    static void stop() throws IOException {
        silent.close();
        for (Socket socket : held) {
            socket.close();
        }
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("gatekeeper.auth.jwk-set-uri", () -> "http://localhost:" + silent.getLocalPort() + "/oauth2/jwks");
        registry.add("gatekeeper.auth.issuer", () -> ISSUER);
        registry.add("gatekeeper.resilience.jwks-timeout", () -> "300ms");
    }

    @Test
    void refusesWith503WithinTheTimeoutInsteadOfHanging() {
        String token = key.mint(ISSUER, "ezzat", Instant.now().plus(5, ChronoUnit.MINUTES),
                Map.of("tenant", "acme", "scope", List.of("payments:read")));
        long started = System.nanoTime();

        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isEqualTo(503)
                .expectHeader().valueEquals(HttpHeaders.RETRY_AFTER, "5")
                .expectHeader().doesNotExist(HttpHeaders.WWW_AUTHENTICATE)
                .expectBody()
                .jsonPath("$.error").isEqualTo("service_unavailable")
                .jsonPath("$.status").isEqualTo(503)
                .jsonPath("$.path").isEqualTo("/api/ledger/entries")
                .jsonPath("$.detail").isEqualTo("KEYS_UNAVAILABLE");

        assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(3));
    }
}
```

`src/test/java/com/gatekeeper/config/JwksFetchLoggingTest.java`:

```java
package com.gatekeeper.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import reactor.core.publisher.Mono;

import java.net.ConnectException;
import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;

/** One WARN when the key set stops answering, one INFO when it answers again. The M7 design, section 14. */
@ExtendWith(OutputCaptureExtension.class)
class JwksFetchLoggingTest {

    static final ClientRequest REQUEST = ClientRequest.create(HttpMethod.GET, URI.create("http://authcore/oauth2/jwks")).build();

    @Test
    void warnsOnceThenInformsOnRecovery(CapturedOutput output) {
        JwksFetchLogging logging = new JwksFetchLogging();
        ExchangeFunction refused = request -> Mono.error(new ConnectException("Connection refused"));
        ExchangeFunction ok = request -> Mono.just(ClientResponse.create(HttpStatus.OK).build());

        for (int i = 0; i < 3; i++) {
            logging.filter(REQUEST, refused).onErrorResume(e -> Mono.empty()).block();
        }
        logging.filter(REQUEST, ok).block();
        logging.filter(REQUEST, ok).block();

        assertThat(count(output.getOut(), "AuthCore's key set could not be fetched")).isEqualTo(1);
        assertThat(count(output.getOut(), "AuthCore's key set answered again")).isEqualTo(1);
    }

    @Test
    void aNonSuccessStatusIsAFailure(CapturedOutput output) {
        JwksFetchLogging logging = new JwksFetchLogging();

        logging.filter(REQUEST, request -> Mono.just(ClientResponse.create(HttpStatus.BAD_GATEWAY).build())).block();

        assertThat(output.getOut()).contains("AuthCore's key set could not be fetched");
    }

    private static int count(String text, String needle) {
        int count = 0;
        for (int i = text.indexOf(needle); i >= 0; i = text.indexOf(needle, i + 1)) {
            count++;
        }
        return count;
    }
}
```

Change `src/test/java/com/gatekeeper/error/UnreachableJwksErrorShapeTest.java`: rename the test method to `rendersAnUnreachableJwksAsServiceUnavailable`, replace its Javadoc with:

```java
    /**
     * The token is well-formed and would verify if the key set were reachable, but it never gets
     * that far: the fetch is refused, and {@code NimbusReactiveJwtDecoder} wraps that as {@code
     * IllegalStateException("Could not obtain the keys", ...)}. Since M7 that is a 503 with {@code
     * KEYS_UNAVAILABLE}, not a 401: the token is very likely valid, and a 401 would send the caller
     * to refresh it against the AuthCore that is unreachable (the M7 design, section 4).
     */
```

and replace its assertion chain with:

```java
                .expectStatus().isEqualTo(503)
                .expectHeader().valueEquals(HttpHeaders.RETRY_AFTER, "5")
                .expectHeader().doesNotExist(HttpHeaders.WWW_AUTHENTICATE)
                .expectBody()
                .jsonPath("$.error").isEqualTo("service_unavailable")
                .jsonPath("$.status").isEqualTo(503)
                .jsonPath("$.path").isEqualTo("/api/ledger/entries")
                .jsonPath("$.detail").isEqualTo("KEYS_UNAVAILABLE");
```

Leave its `localhost:9` JWKS: it goes through `WebClient`, which parses the port correctly (verified); the single-digit-port problem is the gateway's routing call only.

- [ ] **Step 3: Run to see them fail**

Run: `.\mvnw.cmd -o -q test "-Dtest=JwksTimeoutTest,JwksFetchLoggingTest,UnreachableJwksErrorShapeTest"`
Expected: COMPILATION ERROR (`JwksFetchLogging`). Once you add an empty `JwksFetchLogging` stub to compile, `JwksTimeoutTest` should hang until WebTestClient's 5 s timeout and `UnreachableJwksErrorShapeTest` get 401 — note both, then continue.

- [ ] **Step 4: Implement `JwksFetchLogging`**

`src/main/java/com/gatekeeper/config/JwksFetchLogging.java`:

```java
package com.gatekeeper.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import reactor.core.publisher.Mono;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Logs AuthCore's key set going away and coming back, once each — not once per request. The M7
 * design, section 14. There is no breaker for the key set, so this flag is what keeps an outage to a
 * few lines: WARN on the first failed fetch after a success (or at startup), DEBUG for further
 * failures, INFO when a fetch succeeds again. A non-2xx answer is a failure too.
 */
final class JwksFetchLogging implements ExchangeFilterFunction {

    private static final Logger log = LoggerFactory.getLogger(JwksFetchLogging.class);

    private final AtomicBoolean failing = new AtomicBoolean();

    @Override
    public Mono<ClientResponse> filter(ClientRequest request, ExchangeFunction next) {
        return next.exchange(request)
                .doOnNext(response -> {
                    if (response.statusCode().is2xxSuccessful()) {
                        answered();
                    } else {
                        failed("HTTP " + response.statusCode().value());
                    }
                })
                .doOnError(error -> failed(error.toString()));
    }

    private void failed(String cause) {
        if (failing.compareAndSet(false, true)) {
            log.warn("AuthCore's key set could not be fetched; bearer tokens that need a key fetch are refused"
                    + " 503 until it answers: {}", cause);
        } else {
            log.debug("AuthCore's key set still not answering: {}", cause);
        }
    }

    private void answered() {
        if (failing.compareAndSet(true, false)) {
            log.info("AuthCore's key set answered again");
        }
    }
}
```

- [ ] **Step 5: Give the decoder its `WebClient`**

In `JwtDecoderConfig.java`, add parameter `ResilienceProperties resilience` to `jwtDecoder(...)`, replace the decoder line with:

```java
        NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder.withJwkSetUri(jwkSetUri)
                .webClient(jwksWebClient(resilience.jwksTimeout()))
                .build();
```

and add:

```java
    /**
     * The key-set fetch with a connect and a response timeout. The M7 design, section 4. Without them
     * an AuthCore that accepts the connection and never answers hung the request; a connect timeout is
     * needed as well, or a host that never accepts would wait for the operating system's own, which can
     * exceed 20 s. Any failure — refused, silent, non-2xx — reaches {@code GlobalErrorWebExceptionHandler}
     * as the decoder's "Could not obtain the keys" (verified in Spring Security 7.0.6), answered 503.
     */
    static WebClient jwksWebClient(Duration timeout) {
        HttpClient http = HttpClient.create()
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, Math.toIntExact(timeout.toMillis()))
                .responseTimeout(timeout);
        return WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(http))
                .filter(new JwksFetchLogging())
                .build();
    }
```

Imports: `com.gatekeeper.resilience.ResilienceProperties`, `io.netty.channel.ChannelOption`, `org.springframework.http.client.reactive.ReactorClientHttpConnector`, `org.springframework.web.reactive.function.client.WebClient`, `reactor.netty.http.client.HttpClient`, `java.time.Duration`. Append to the class Javadoc: `<p>Since M7 the key-set fetch has its own timeouts — see {@link #jwksWebClient}.`

- [ ] **Step 6: Reshape the handler and answer 503 for the key set**

Replace `GlobalErrorWebExceptionHandler.java` with the version below. It reshapes the handler into one mapping per failure (`Answer`) so Tasks 4, 5 and 7 each add one case; behaviour for every existing case is unchanged except the key set, which becomes 503.

```java
package com.gatekeeper.error;

import com.gatekeeper.apikey.IntrospectionUnavailableException;
import com.gatekeeper.revocation.RevocationUnavailableException;
import org.jspecify.annotations.Nullable;
import org.springframework.boot.autoconfigure.web.WebProperties;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.webflux.autoconfigure.error.AbstractErrorWebExceptionHandler;
import org.springframework.boot.webflux.error.ErrorAttributes;
import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.RequestPredicates;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

/**
 * One JSON error shape across the platform. Without it a client gets an empty body from
 * the gateway and a JSON body from the services behind it for what is, to them, the same
 * failure.
 *
 * <p>Ordered ahead of Boot's own handler so this one wins. In practice Boot's own handler is
 * never even created: its {@code @Bean} method carries {@code @ConditionalOnMissingBean} on
 * its return type {@code ErrorWebExceptionHandler}, and this component — a bean of that same
 * type — is registered before autoconfiguration is evaluated, the way every
 * {@code @ConditionalOnMissingBean} back-off in Boot works. The explicit {@code @Order(-2)}
 * (one ahead of the {@code @Order(-1)} Boot would have used) is defence in depth for that,
 * not the thing actually doing the work — confirmed by reading both classes' bytecode with
 * {@code javap} rather than assumed.
 *
 * <p>This handler does not, by itself, catch the no-token case. Spring Security's own {@code
 * ServerAuthenticationEntryPoint} commits a 401 directly and never throws, so that request
 * never reaches this class at all — see {@link JsonServerAuthenticationEntryPoint}, wired in
 * {@code GatewaySecurityConfig}, which renders the identical {@link ErrorBody} shape for
 * that path instead.
 *
 * <p>Each failure it recognises maps to one {@link Answer}: a status, a fixed {@code detail} and a
 * {@code Retry-After}. The M7 design, section 8, has the table.
 */
@Component
@Order(-2)
public class GlobalErrorWebExceptionHandler extends AbstractErrorWebExceptionHandler {

    /** AuthCore's key set could not be fetched. The M7 design, section 4. */
    public static final String KEYS_UNAVAILABLE = "KEYS_UNAVAILABLE";

    public GlobalErrorWebExceptionHandler(ErrorAttributes errorAttributes,
                                          WebProperties webProperties,
                                          ApplicationContext applicationContext,
                                          ServerCodecConfigurer codecConfigurer) {
        super(errorAttributes, webProperties.getResources(), applicationContext);
        setMessageWriters(codecConfigurer.getWriters());
        setMessageReaders(codecConfigurer.getReaders());
    }

    /** What the caller is told: status, the fixed {@code detail} if any, and {@code Retry-After} if any. */
    record Answer(HttpStatus status, @Nullable String detail, @Nullable String retryAfter) {
    }

    @Override
    protected RouterFunction<ServerResponse> getRoutingFunction(ErrorAttributes errorAttributes) {
        return RouterFunctions.route(RequestPredicates.all(), this::render);
    }

    private Mono<ServerResponse> render(ServerRequest request) {
        Throwable error = getError(request);
        Answer answer = answerFor(request, error);

        ServerResponse.BodyBuilder builder = ServerResponse.status(answer.status())
                .contentType(MediaType.APPLICATION_JSON);

        if (answer.status() == HttpStatus.UNAUTHORIZED) {
            // RFC 6750 requires it on a 401 from a bearer-token resource. Not unconditional: a 503
            // or 404 carrying WWW-Authenticate would be wrong and confusing.
            builder = builder.header(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
        }
        if (answer.retryAfter() != null) {
            builder = builder.header(HttpHeaders.RETRY_AFTER, answer.retryAfter());
        }
        return builder.bodyValue(ErrorBody.of(answer.status(), request.path(), answer.detail()));
    }

    /**
     * Several failures reach here as raw exceptions rather than anything Spring Security or Boot
     * recognises, and each would otherwise read as a server fault.
     *
     * <p>A claim carrying a control character arrives as {@code IllegalArgumentException("Validation
     * failed for header '...'", ...)} from Netty's header validation, thrown inside the gateway's own
     * routing filter when it copies the stamped header onto the outbound request. The gateway cannot
     * establish who the caller is, so it refuses the credential: 401. The match is on type and the
     * fixed part of the message, deliberately narrower than any {@code IllegalArgumentException}: a
     * blanket catch would relabel an unrelated bug as an authentication failure, and a 401 is not
     * paged on the way a 500 is.
     *
     * <p>An unreachable key set arrives as {@code IllegalStateException("Could not obtain the keys",
     * ...)} from the remote key source, matched the same narrow way. Until M7 it was a 401, so as not to
     * advertise that the identity provider was down. Since M7 it is 503 {@link #KEYS_UNAVAILABLE}, like
     * the two other "a dependency could not answer" cases: the token is very likely valid, and a 401
     * would send the caller to discard it and refresh it against the very AuthCore that is unreachable
     * (the M7 design, section 4).
     *
     * <p>{@link IntrospectionUnavailableException} and {@link RevocationUnavailableException} get bare
     * type matches, with no message narrowing: each is a type this gateway declares for itself and
     * throws from exactly one place for exactly one reason, so there is no ambient use of it an
     * unrelated bug could collide with. Both are 503 — see their own Javadoc for why.
     */
    private Answer answerFor(ServerRequest request, Throwable error) {
        if (isRejectedOutboundHeader(error)) {
            return new Answer(HttpStatus.UNAUTHORIZED, null, null);
        }
        if (isUnreachableJwks(error)) {
            return new Answer(HttpStatus.SERVICE_UNAVAILABLE, KEYS_UNAVAILABLE, "5");
        }
        if (error instanceof IntrospectionUnavailableException) {
            return new Answer(HttpStatus.SERVICE_UNAVAILABLE, null, "5");
        }
        if (error instanceof RevocationUnavailableException) {
            return new Answer(HttpStatus.SERVICE_UNAVAILABLE, RevocationUnavailableException.DETAIL, "5");
        }

        int code = (int) getErrorAttributes(request, ErrorAttributeOptions.defaults())
                .getOrDefault("status", 500);
        HttpStatus resolved = HttpStatus.resolve(code);
        HttpStatus status = resolved != null ? resolved : HttpStatus.INTERNAL_SERVER_ERROR;
        // Any other 503 still tells the caller it is worth retrying.
        return new Answer(status, null, status == HttpStatus.SERVICE_UNAVAILABLE ? "5" : null);
    }

    /**
     * {@code NimbusReactiveJwtDecoder}'s fixed message when the key-set fetch fails for any reason —
     * refused, timed out, a non-2xx response, or malformed JSON. All of these surface through the same
     * unconditional {@code onErrorMap} wrapping the fetch (verified in Spring Security 7.0.6, including
     * for M7's connect and response timeouts), so the message carries no variable text and an exact
     * match is safe.
     */
    private static boolean isUnreachableJwks(Throwable error) {
        return error instanceof IllegalStateException
                && "Could not obtain the keys".equals(error.getMessage());
    }

    /**
     * Netty's {@code DefaultHeaders.validateValue} message when a header value fails
     * validation, prefix-matched because the message interpolates the header name.
     */
    private static boolean isRejectedOutboundHeader(Throwable error) {
        return error instanceof IllegalArgumentException
                && error.getMessage() != null
                && error.getMessage().startsWith("Validation failed for header");
    }
}
```

Verify `org.jspecify.annotations.Nullable` is on the classpath (`javap -cp` the jspecify jar, or grep the repo for an existing use); if not, drop the annotation rather than add a dependency.

- [ ] **Step 7: Update two comments in `application.yml`**

Under `api-key:`, replace the two lines starting `# The JWKS fetch has no timeout and that is filed as an M7 defect.` with:

```yaml
    # Do not leave a remote call without a timeout: a host that accepts the connection and never
    # answers must fail, not hang. (The JWKS fetch has one since M7: gatekeeper.resilience.jwks-timeout.)
```

Under `rate-limit:`, in the `redis-timeout` comment, replace `(the JWKS fetch's missing timeout is an open M7 item; this call does not repeat it)` with `(as every remote call here has)`.

- [ ] **Step 8: Run, make them fail on purpose, then the suite**

Run: `.\mvnw.cmd -o -q test "-Dtest=JwksTimeoutTest,JwksFetchLoggingTest,UnreachableJwksErrorShapeTest,ErrorShapeTest"` — expected all pass.

Mutations, with `clean`, each restored:
- `jwksWebClient` without `.responseTimeout(timeout)` → `JwksTimeoutTest` fails (hangs to WebTestClient's 5 s timeout).
- `isUnreachableJwks` answering `new Answer(HttpStatus.UNAUTHORIZED, null, null)` → both 503 tests fail.

Run: `.\mvnw.cmd -o test` — expected 292 (289 + 3: one in `JwksTimeoutTest`, two in `JwksFetchLoggingTest`), 0 failures.

- [ ] **Step 9: Commit**

```
feat(M7): time out the JWKS fetch and answer an unreachable key set 503

The key-set fetch gets a 2 s connect and response timeout; before, an
AuthCore that accepted and never answered hung the request. A failed
fetch is now 503 KEYS_UNAVAILABLE with Retry-After: 5, like the
introspection and revocation outages, not a 401 that would send a client
to refresh against the unreachable issuer. The handler is reshaped into
one mapping per failure; JWKS outages log once, not per request.
```

---

### Task 4: Timeouts toward the downstreams (spec §5, §8)

**Files:**
- Modify: `src/main/resources/application.yml`
- Modify: `src/main/java/com/gatekeeper/error/GlobalErrorWebExceptionHandler.java`
- Test: `src/test/java/com/gatekeeper/resilience/DownstreamTimeoutTest.java`, `src/test/java/com/gatekeeper/resilience/DownstreamUnreachableTest.java`

- [ ] **Step 1: Branch**

`git checkout master; git checkout -b feature/m7-task-4`

- [ ] **Step 2: Write the failing tests**

`src/test/java/com/gatekeeper/resilience/DownstreamTimeoutTest.java`:

```java
package com.gatekeeper.resilience;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.gatekeeper.support.TestKey;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * A downstream that answers too slowly is answered 504 DOWNSTREAM_TIMEOUT within the route's own
 * timeout. The global timeout is set long here and the ledger route's short, so a pass proves the
 * per-route value is the one in force. The M7 design, section 5.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class DownstreamTimeoutTest {

    static final String ISSUER = "http://localhost:8080";
    static WireMockServer downstream;
    static TestKey signingKey;

    @Autowired
    WebTestClient client;

    @BeforeAll
    static void start() {
        signingKey = TestKey.generate("k1");
        downstream = new WireMockServer(options().dynamicPort());
        downstream.start();
        downstream.stubFor(get(urlEqualTo("/oauth2/jwks")).willReturn(okJson(TestKey.jwksDocument(signingKey))));
        downstream.stubFor(get(urlEqualTo("/ledger/slow")).willReturn(aResponse().withFixedDelay(1500).withStatus(200)));
        downstream.stubFor(post(urlEqualTo("/ledger/slow")).willReturn(aResponse().withFixedDelay(1500).withStatus(200)));
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
        registry.add("spring.cloud.gateway.server.webflux.httpclient.response-timeout", () -> "10s");
        registry.add("gatekeeper.resilience.response-timeout-millis.ledger", () -> "300");
    }

    @Test
    void aSlowGetIsAnsweredGatewayTimeoutWithinTheRouteTimeout() {
        long started = System.nanoTime();

        client.get().uri("/api/ledger/slow")
                .header(HttpHeaders.AUTHORIZATION, token())
                .exchange()
                .expectStatus().isEqualTo(504)
                .expectHeader().doesNotExist(HttpHeaders.RETRY_AFTER)
                .expectHeader().doesNotExist(HttpHeaders.WWW_AUTHENTICATE)
                .expectBody()
                .jsonPath("$.error").isEqualTo("gateway_timeout")
                .jsonPath("$.status").isEqualTo(504)
                .jsonPath("$.path").isEqualTo("/api/ledger/slow")
                .jsonPath("$.detail").isEqualTo("DOWNSTREAM_TIMEOUT");

        assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofMillis(1200));
    }

    /** For a POST the outcome is unknown — the downstream may have processed it — and 504 says so. */
    @Test
    void aSlowPostIsAnsweredGatewayTimeout() {
        client.post().uri("/api/ledger/slow")
                .header(HttpHeaders.AUTHORIZATION, token())
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{}")
                .exchange()
                .expectStatus().isEqualTo(504)
                .expectBody().jsonPath("$.detail").isEqualTo("DOWNSTREAM_TIMEOUT");
    }

    private static String token() {
        return "Bearer " + signingKey.mint(ISSUER, "ezzat", Instant.now().plus(5, ChronoUnit.MINUTES),
                Map.of("tenant", "acme", "scope", List.of("payments:read", "payments:write")));
    }
}
```

`src/test/java/com/gatekeeper/resilience/DownstreamUnreachableTest.java`:

```java
package com.gatekeeper.resilience;

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

import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;

/**
 * Nothing listens on the ledger's port: a connect error, answered 502 DOWNSTREAM_UNREACHABLE rather
 * than an unmapped 500. The M7 design, section 8. The port is multi-digit on purpose: Reactor Netty
 * mis-parses a single-digit port in the gateway's routing call as a host name.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class DownstreamUnreachableTest {

    static final String ISSUER = "http://localhost:8080";
    static WireMockServer authCore;
    static TestKey signingKey;
    static int closedPort;

    @Autowired
    WebTestClient client;

    @BeforeAll
    static void start() throws IOException {
        signingKey = TestKey.generate("k1");
        authCore = new WireMockServer(options().dynamicPort());
        authCore.start();
        authCore.stubFor(get(urlEqualTo("/oauth2/jwks")).willReturn(okJson(TestKey.jwksDocument(signingKey))));
        try (ServerSocket probe = new ServerSocket(0)) {
            closedPort = probe.getLocalPort();
        }
    }

    @AfterAll
    static void stop() {
        authCore.stop();
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("gatekeeper.auth.jwk-set-uri", () -> authCore.baseUrl() + "/oauth2/jwks");
        registry.add("gatekeeper.auth.issuer", () -> ISSUER);
        registry.add("gatekeeper.downstream.ledger", () -> "http://localhost:" + closedPort);
        registry.add("gatekeeper.downstream.authcore", () -> authCore.baseUrl());
    }

    @Test
    void aRefusedConnectionIsAnsweredBadGateway() {
        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, token())
                .exchange()
                .expectStatus().isEqualTo(502)
                .expectHeader().doesNotExist(HttpHeaders.RETRY_AFTER)
                .expectBody()
                .jsonPath("$.error").isEqualTo("bad_gateway")
                .jsonPath("$.status").isEqualTo(502)
                .jsonPath("$.path").isEqualTo("/api/ledger/entries")
                .jsonPath("$.detail").isEqualTo("DOWNSTREAM_UNREACHABLE");
    }

    static String token() {
        return "Bearer " + signingKey.mint(ISSUER, "ezzat", Instant.now().plus(5, ChronoUnit.MINUTES),
                Map.of("tenant", "acme", "scope", List.of("payments:read", "payments:write")));
    }
}
```

- [ ] **Step 3: Run to see them fail**

Run: `.\mvnw.cmd -o -q test "-Dtest=DownstreamTimeoutTest,DownstreamUnreachableTest"`
Expected: the timeout tests get 200 after 1.5 s (no timeout exists); the unreachable test gets 500.

- [ ] **Step 4: Global and per-route timeouts in `application.yml`**

Under `spring.cloud.gateway.server.webflux`, before `routes:`, add:

```yaml
          # The safety net for every route, present and future: a connect timeout in milliseconds and
          # a response timeout. Each route below also states its own response timeout, which wins.
          # The M7 design, section 5.
          httpclient:
            connect-timeout: 2000
            response-timeout: 5s
```

Give each route a `metadata` block (after `uri:`), with its own key:

```yaml
              metadata:
                # Plain milliseconds; see gatekeeper.resilience.response-timeout-millis.
                response-timeout: ${gatekeeper.resilience.response-timeout-millis.authcore-accounts}
```

(`authcore-machine` and `ledger` likewise, each referring to its own route id.)

- [ ] **Step 5: Map the timeout and the connect error**

In `GlobalErrorWebExceptionHandler`:

1. Add constants:

```java
    /** A downstream did not answer within its route's response timeout. The M7 design, section 5. */
    public static final String DOWNSTREAM_TIMEOUT = "DOWNSTREAM_TIMEOUT";
    /** A downstream could not be connected to. The M7 design, section 8. */
    public static final String DOWNSTREAM_UNREACHABLE = "DOWNSTREAM_UNREACHABLE";
```

2. In `answerFor`, before the fallback to the error attributes, add:

```java
        if (isDownstreamTimeout(error)) {
            return new Answer(HttpStatus.GATEWAY_TIMEOUT, DOWNSTREAM_TIMEOUT, null);
        }
        if (error instanceof ConnectException) {
            return new Answer(HttpStatus.BAD_GATEWAY, DOWNSTREAM_UNREACHABLE, null);
        }
```

3. Add:

```java
    /**
     * Spring Cloud Gateway's routing filter, when a downstream exceeds the route's response timeout:
     * a 504 {@code ResponseStatusException} caused by the gateway's own {@code TimeoutException}
     * (verified in 5.0.2). Matched on both, so a 504 raised for another reason is not relabelled.
     */
    private static boolean isDownstreamTimeout(Throwable error) {
        return error instanceof ResponseStatusException status
                && status.getStatusCode().value() == HttpStatus.GATEWAY_TIMEOUT.value()
                && status.getCause() instanceof org.springframework.cloud.gateway.support.TimeoutException;
    }
```

Imports: `java.net.ConnectException`, `org.springframework.web.server.ResponseStatusException`. A bare `ConnectException` match is safe: it covers a refused connection (Netty's `AnnotatedConnectException`) and the connect timeout (Netty's `ConnectTimeoutException`), both subclasses (verified); every other remote call in the gateway — introspection, the key set, Redis — wraps its connect errors in its own exception before they could reach here. Extend `answerFor`'s Javadoc with one paragraph saying exactly that.

- [ ] **Step 6: Run, make them fail, the suite**

Run the two classes — expected 3 pass. Mutations with `clean`, each restored:
- remove the `ledger` route's `metadata` → `aSlowGetIsAnsweredGatewayTimeoutWithinTheRouteTimeout` fails (the 10 s global applies: 200 after 1.5 s).
- write the ledger metadata as `response-timeout: 300ms` (a duration, not milliseconds) with the test property also `300ms` → the same test fails (Spring Cloud Gateway ignores it silently). Record this: it is why the values are plain milliseconds.

Run: `.\mvnw.cmd -o test` — expected 295 (292 + 3), 0 failures.

- [ ] **Step 7: Commit**

```
feat(M7): time out calls to the downstreams

A 2 s connect and 5 s response timeout for every route, and each route
stating its own response timeout from gatekeeper.resilience in plain
milliseconds. A timeout is 504 DOWNSTREAM_TIMEOUT; a refused or timed-out
connect is 502 DOWNSTREAM_UNREACHABLE instead of an unmapped 500.
```

---

### Task 5: One circuit breaker per downstream (spec §6, §7, §8, §14)

**Files:**
- Create: `src/main/java/com/gatekeeper/resilience/ResilienceConfig.java`
- Modify: `src/main/resources/application.yml`
- Modify: `src/main/java/com/gatekeeper/error/GlobalErrorWebExceptionHandler.java`
- Test: `src/test/java/com/gatekeeper/resilience/DownstreamCircuitBreakerTest.java`; one test added to `DownstreamUnreachableTest`

- [ ] **Step 1: Branch**

`git checkout master; git checkout -b feature/m7-task-5`

- [ ] **Step 2: Write the failing test**

`src/test/java/com/gatekeeper/resilience/DownstreamCircuitBreakerTest.java`:

```java
package com.gatekeeper.resilience;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.gatekeeper.support.TestKey;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.cloud.circuitbreaker.resilience4j.ReactiveResilience4JCircuitBreakerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * One breaker per downstream: what opens it, what it answers while open, how it recovers, and what it
 * never counts. The M7 design, sections 6 to 8. Small values (a window of 4, open for 1 s) keep it fast;
 * {@code ProductionValuesTest} pins the real ones.
 *
 * <p>POST throughout, so the GET-only retry (Task 6) never changes how many calls the downstream sees.
 * Breakers are reset before each test: they live for the whole context.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@ExtendWith(OutputCaptureExtension.class)
class DownstreamCircuitBreakerTest {

    static final String ISSUER = "http://localhost:8080";
    static WireMockServer downstream;
    static TestKey signingKey;

    @Autowired
    WebTestClient client;

    @Autowired
    ReactiveResilience4JCircuitBreakerFactory breakers;

    @BeforeAll
    static void start() {
        signingKey = TestKey.generate("k1");
        downstream = new WireMockServer(options().dynamicPort());
        downstream.start();
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
        registry.add("gatekeeper.resilience.breaker.sliding-window-size", () -> "4");
        registry.add("gatekeeper.resilience.breaker.minimum-calls", () -> "4");
        registry.add("gatekeeper.resilience.breaker.open-for", () -> "1s");
        registry.add("gatekeeper.resilience.breaker.trial-calls", () -> "1");
        registry.add("gatekeeper.resilience.response-timeout-millis.ledger", () -> "300");
    }

    @BeforeEach
    void reset() {
        downstream.resetAll();
        downstream.stubFor(get(urlEqualTo("/oauth2/jwks")).willReturn(okJson(TestKey.jwksDocument(signingKey))));
        downstream.stubFor(get(urlEqualTo("/api/machine/payments")).willReturn(okJson("[]")));
        // find, never circuitBreaker(name): creating one here would bypass the gateway's configuration.
        breakers.getCircuitBreakerRegistry().getAllCircuitBreakers().forEach(CircuitBreaker::reset);
    }

    @Test
    void repeatedServiceUnavailableOpensItAndThenNothingReachesTheDownstream(CapturedOutput output) {
        downstream.stubFor(post(urlEqualTo("/ledger/entries")).willReturn(aResponse().withStatus(503)));
        for (int i = 0; i < 4; i++) {
            postEntry().expectStatus().isEqualTo(503).expectBody().jsonPath("$.detail").isEqualTo("DOWNSTREAM_ERROR");
        }

        for (int i = 0; i < 3; i++) {
            postEntry()
                    .expectStatus().isEqualTo(503)
                    .expectHeader().valueEquals(HttpHeaders.RETRY_AFTER, "1")
                    .expectHeader().doesNotExist(HttpHeaders.WWW_AUTHENTICATE)
                    .expectBody()
                    .jsonPath("$.error").isEqualTo("service_unavailable")
                    .jsonPath("$.detail").isEqualTo("DOWNSTREAM_UNAVAILABLE");
        }

        downstream.verify(4, postRequestedFor(urlEqualTo("/ledger/entries")));
        assertThat(state("ledger")).isEqualTo(CircuitBreaker.State.OPEN);
        assertThat(output.getOut()).contains("Downstream ledger: circuit breaker opened");
    }

    /**
     * 502, 503 and 504 are availability signals: they count, and their bodies and headers are replaced
     * by the gateway's shape, keeping the status. The M7 design, section 7.
     */
    @Test
    void countedStatusesAreReplacedByTheGatewaysShapeHeadersIncluded() {
        for (int status : new int[] {502, 503, 504}) {
            downstream.stubFor(post(urlEqualTo("/ledger/entries")).willReturn(aResponse().withStatus(status)
                    .withHeader("X-Upstream", "yes")
                    .withHeader("Set-Cookie", "session=downstream")
                    .withHeader("Content-Type", "text/html")
                    .withBody("<html>downstream page</html>")));

            postEntry()
                    .expectStatus().isEqualTo(status)
                    .expectHeader().contentType(MediaType.APPLICATION_JSON)
                    .expectHeader().doesNotExist("X-Upstream")
                    .expectHeader().doesNotExist(HttpHeaders.SET_COOKIE)
                    .expectBody()
                    .jsonPath("$.status").isEqualTo(status)
                    .jsonPath("$.path").isEqualTo("/api/ledger/entries")
                    .jsonPath("$.detail").isEqualTo("DOWNSTREAM_ERROR");
            breakers.getCircuitBreakerRegistry().getAllCircuitBreakers().forEach(CircuitBreaker::reset);
        }
    }

    /**
     * A 500 is the downstream's own answer: it passes through untouched — status, headers and body,
     * byte for byte — and never counts, however many there are. The M7 design, section 7.
     */
    @Test
    void fiveHundredsPassThroughUntouchedAndNeverOpenIt() {
        String body = "{\"error\":\"internal_server_error\",\"downstream\":\"own diagnostics\"}";
        downstream.stubFor(post(urlEqualTo("/ledger/entries")).willReturn(aResponse().withStatus(500)
                .withHeader("Content-Type", "application/json")
                .withHeader("X-Upstream", "yes")
                .withBody(body)));

        for (int i = 0; i < 10; i++) {
            byte[] received = postEntry()
                    .expectStatus().isEqualTo(500)
                    .expectHeader().valueEquals("X-Upstream", "yes")
                    .expectBody().returnResult().getResponseBody();
            assertThat(new String(received)).isEqualTo(body);
        }

        downstream.verify(10, postRequestedFor(urlEqualTo("/ledger/entries")));
        assertThat(state("ledger")).isEqualTo(CircuitBreaker.State.CLOSED);
        assertThat(breakers.getCircuitBreakerRegistry().find("ledger").orElseThrow().getMetrics().getNumberOfFailedCalls())
                .isZero();
    }

    @Test
    void timeoutsCountAsFailures() {
        downstream.stubFor(post(urlEqualTo("/ledger/entries")).willReturn(aResponse().withFixedDelay(800).withStatus(200)));
        for (int i = 0; i < 4; i++) {
            postEntry().expectStatus().isEqualTo(504);
        }

        postEntry().expectStatus().isEqualTo(503).expectBody().jsonPath("$.detail").isEqualTo("DOWNSTREAM_UNAVAILABLE");
    }

    @Test
    void oneSuccessfulTrialAfterTheOpenWindowClosesIt() throws InterruptedException {
        downstream.stubFor(post(urlEqualTo("/ledger/entries")).willReturn(aResponse().withStatus(503)));
        for (int i = 0; i < 4; i++) {
            postEntry().expectStatus().isEqualTo(503);
        }
        assertThat(state("ledger")).isEqualTo(CircuitBreaker.State.OPEN);
        downstream.stubFor(post(urlEqualTo("/ledger/entries")).willReturn(okJson("{}")));

        Thread.sleep(1200);

        postEntry().expectStatus().isOk();
        assertThat(state("ledger")).isEqualTo(CircuitBreaker.State.CLOSED);
    }

    /** Each downstream has its own breaker: ledger's being open does not cut AuthCore off. */
    @Test
    void onlyTheSickDownstreamIsCutOff() {
        downstream.stubFor(post(urlEqualTo("/ledger/entries")).willReturn(aResponse().withStatus(503)));
        for (int i = 0; i < 4; i++) {
            postEntry().expectStatus().isEqualTo(503);
        }

        client.get().uri("/api/machine/payments")
                .header(HttpHeaders.AUTHORIZATION, token())
                .exchange()
                .expectStatus().isOk();
        assertThat(state("ledger")).isEqualTo(CircuitBreaker.State.OPEN);
        assertThat(state("authcore")).isEqualTo(CircuitBreaker.State.CLOSED);
    }

    private WebTestClient.ResponseSpec postEntry() {
        return client.post().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, token())
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{}")
                .exchange();
    }

    private CircuitBreaker.State state(String name) {
        return breakers.getCircuitBreakerRegistry().find(name).orElseThrow().getState();
    }

    private static String token() {
        return "Bearer " + signingKey.mint(ISSUER, "ezzat", Instant.now().plus(5, ChronoUnit.MINUTES),
                Map.of("tenant", "acme", "scope", List.of("payments:read", "payments:write")));
    }
}
```

Add to `DownstreamUnreachableTest` (with the same four `gatekeeper.resilience.breaker.*` properties as above added to its `@DynamicPropertySource`):

```java
    /** Connect errors count: after enough of them the breaker answers at once. The M7 design, section 6. */
    @Test
    void connectErrorsOpenTheBreaker() {
        for (int i = 0; i < 4; i++) {
            client.get().uri("/api/ledger/entries").header(HttpHeaders.AUTHORIZATION, token()).exchange();
        }

        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, token())
                .exchange()
                .expectStatus().isEqualTo(503)
                .expectBody().jsonPath("$.detail").isEqualTo("DOWNSTREAM_UNAVAILABLE");
    }
```

Because test order is not fixed and the breaker lives for the context, give `aRefusedConnectionIsAnsweredBadGateway` a fresh breaker: autowire `ReactiveResilience4JCircuitBreakerFactory breakers` and add a `@BeforeEach` that resets all breakers, as above.

- [ ] **Step 3: Run to see it fail**

Run: `.\mvnw.cmd -o -q test "-Dtest=DownstreamCircuitBreakerTest,DownstreamUnreachableTest"` — expected failures: no breaker exists (`find("ledger")` empty), counted statuses pass through untouched.

- [ ] **Step 4: `ResilienceConfig`**

`src/main/java/com/gatekeeper/resilience/ResilienceConfig.java`:

```java
package com.gatekeeper.resilience;

import io.github.resilience4j.bulkhead.BulkheadFullException;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import io.github.resilience4j.circuitbreaker.event.CircuitBreakerOnStateTransitionEvent;
import io.github.resilience4j.timelimiter.TimeLimiterConfig;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.circuitbreaker.resilience4j.ReactiveResilience4JCircuitBreakerFactory;
import org.springframework.cloud.client.circuitbreaker.Customizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * The downstreams' breakers, from {@link ResilienceProperties}. The M7 design, sections 6, 7 and 14.
 *
 * <p>One per downstream service — {@link #AUTHCORE}, shared by both AuthCore routes, and {@link #LEDGER}
 * — named by each route's {@code CircuitBreaker} filter in {@code application.yml}. What counts as a
 * failure is decided there ({@code statusCodes}: 502, 503, 504) and by the errors that reach the breaker
 * (connect errors, timeouts); a downstream 500 is neither, so it never counts. A full bulkhead's
 * refusal is ignored: the downstream did not fail, the gateway chose not to call it.
 *
 * <p>The TimeLimiter is disabled by {@code spring.cloud.circuitbreaker.resilience4j.disable-time-limiter};
 * the {@code timeLimiterConfig} given here is required by the builder and never applied.
 */
@Configuration
public class ResilienceConfig {

    public static final String AUTHCORE = "authcore";
    public static final String LEDGER = "ledger";

    private static final Logger log = LoggerFactory.getLogger(ResilienceConfig.class);

    @Bean
    public Customizer<ReactiveResilience4JCircuitBreakerFactory> downstreamBreakers(ResilienceProperties properties) {
        ResilienceProperties.Breaker breaker = properties.breaker();
        CircuitBreakerConfig config = CircuitBreakerConfig.custom()
                .slidingWindowType(CircuitBreakerConfig.SlidingWindowType.COUNT_BASED)
                .slidingWindowSize(breaker.slidingWindowSize())
                .minimumNumberOfCalls(breaker.minimumCalls())
                .failureRateThreshold(breaker.failureRateThreshold())
                .waitDurationInOpenState(breaker.openFor())
                .permittedNumberOfCallsInHalfOpenState(breaker.trialCalls())
                .ignoreExceptions(BulkheadFullException.class)
                .build();
        return factory -> {
            factory.configure(builder -> builder
                    .circuitBreakerConfig(config)
                    .timeLimiterConfig(TimeLimiterConfig.ofDefaults()), AUTHCORE, LEDGER);
            // Once per breaker: the factory runs its customizers on every call (verified in 5.0.2), so
            // without once(...) each request would add another listener.
            factory.addCircuitBreakerCustomizer(Customizer.once(
                    circuitBreaker -> circuitBreaker.getEventPublisher()
                            .onStateTransition(event -> logTransition(event, circuitBreaker)),
                    CircuitBreaker::getName), AUTHCORE, LEDGER);
        };
    }

    /** WARN when one opens, INFO otherwise; never per request. The M7 design, section 14. */
    private static void logTransition(CircuitBreakerOnStateTransitionEvent event, CircuitBreaker circuitBreaker) {
        CircuitBreaker.StateTransition transition = event.getStateTransition();
        if (transition.getToState() == CircuitBreaker.State.OPEN) {
            log.warn("Downstream {}: circuit breaker opened ({} -> OPEN) at a {}% failure rate; its requests are"
                            + " refused 503 until a trial call succeeds",
                    event.getCircuitBreakerName(), transition.getFromState(),
                    circuitBreaker.getMetrics().getFailureRate());
        } else {
            log.info("Downstream {}: circuit breaker {} -> {}",
                    event.getCircuitBreakerName(), transition.getFromState(), transition.getToState());
        }
    }
}
```

Verify before compiling: `Customizer.once(Customizer<T>, Function<? super T, ?>)` in `spring-cloud-commons` 5.0.2 (`javap -cp` its jar, class `org.springframework.cloud.client.circuitbreaker.Customizer`); `factory.configure(Consumer<Resilience4JConfigBuilder>, String...)`; `CircuitBreakerConfig.Builder.failureRateThreshold(float)`. Adjust only types, never behaviour, and say what you adjusted.

- [ ] **Step 5: The routes' `CircuitBreaker` filters, and no TimeLimiter**

In `application.yml`, give each route a `filters:` list **beginning** with the breaker (the `ledger` route keeps `StripPrefix` and `RemoveRequestHeader` after it):

```yaml
              filters:
                # First, so it wraps everything after it, Retry included (Task 6). Counts connect
                # errors, timeouts and these statuses; a downstream 500 is the downstream's own
                # answer and passes through uncounted. The M7 design, sections 6 and 7.
                - name: CircuitBreaker
                  args:
                    name: authcore
                    statusCodes: BAD_GATEWAY,SERVICE_UNAVAILABLE,GATEWAY_TIMEOUT
```

(`name: authcore` for both AuthCore routes, `name: ledger` for the ledger route.)

Add, under `spring:` (a sibling of `cloud.gateway`, inside `spring.cloud`):

```yaml
    circuitbreaker:
      resilience4j:
        # Spring Cloud CircuitBreaker's default wraps each call in a 1 s TimeLimiter, which would cut
        # requests before the routes' own 5 s timeout. The gateway's response timeout governs instead.
        # The M7 design, section 6.
        disable-time-limiter: true
```

- [ ] **Step 6: Map the open breaker and the counted statuses; strip downstream headers**

In `GlobalErrorWebExceptionHandler`:

1. Constants:

```java
    /** The downstream's breaker is open. The M7 design, section 6. */
    public static final String DOWNSTREAM_UNAVAILABLE = "DOWNSTREAM_UNAVAILABLE";
    /** The downstream answered 502, 503 or 504 — an availability signal. The M7 design, section 7. */
    public static final String DOWNSTREAM_ERROR = "DOWNSTREAM_ERROR";
```

2. Constructor: add a `ResilienceProperties resilience` parameter and a field:

```java
    private final String breakerRetryAfter;
    ...
        // The open window, in whole seconds: an upper bound, since the window may be partly over.
        this.breakerRetryAfter = Long.toString(Math.max(1, (resilience.breaker().openFor().toMillis() + 999) / 1000));
```

3. In `answerFor`, before the timeout case:

```java
        if (error instanceof ServiceUnavailableException) {
            return new Answer(HttpStatus.SERVICE_UNAVAILABLE, DOWNSTREAM_UNAVAILABLE, breakerRetryAfter);
        }
        if (error instanceof CircuitBreakerStatusCodeException counted) {
            return new Answer(HttpStatus.valueOf(counted.getStatusCode().value()), DOWNSTREAM_ERROR, null);
        }
```

`ServiceUnavailableException` is `org.springframework.cloud.gateway.support.ServiceUnavailableException`, raised by the gateway's breaker filter when the breaker refuses (verified). `CircuitBreakerStatusCodeException` is the non-static inner class `org.springframework.cloud.gateway.filter.factory.SpringCloudCircuitBreakerFilterFactory.CircuitBreakerStatusCodeException` (import it as a nested type); Boot would render it as 500, which is why it is mapped explicitly (verified).

4. In `render`, first thing after computing the answer:

```java
        removeDownstreamHeaders(request.exchange());
```

and add:

```java
    /**
     * A counted downstream status reaches here after the downstream's headers were copied onto the
     * response, and Boot's handler does not clear them (verified in 5.0.2 and Boot 4.0.7): without this,
     * a downstream's {@code Set-Cookie} or {@code Content-Encoding} would ride on the gateway's error. The
     * gateway records which headers came from the downstream; they are removed from every error it
     * renders. Headers the gateway set itself, such as the rate limiter's, stay.
     */
    private static void removeDownstreamHeaders(ServerWebExchange exchange) {
        Set<String> fromDownstream = exchange.getAttribute(ServerWebExchangeUtils.CLIENT_RESPONSE_HEADER_NAMES);
        if (fromDownstream != null) {
            fromDownstream.forEach(exchange.getResponse().getHeaders()::remove);
        }
    }
```

Verify `ServerWebExchangeUtils.CLIENT_RESPONSE_HEADER_NAMES` exists in 5.0.2 and is a `Set<String>` attribute set by `NettyRoutingFilter` (`javap -c`); if its type differs, adapt and say so. Imports: `org.springframework.cloud.gateway.support.ServerWebExchangeUtils`, `org.springframework.web.server.ServerWebExchange`, `java.util.Set`.

5. Extend `answerFor`'s Javadoc with a paragraph stating section 7's assumption: a downstream 502/503/504 is an availability signal, counted and replaced; a 500 is the downstream's own answer and never reaches this handler — it passes through untouched.

- [ ] **Step 7: Run, make it fail, the suite**

Run the two classes — expected all pass. Mutations with `clean`, each restored:
- add `INTERNAL_SERVER_ERROR` to the ledger route's `statusCodes` → `fiveHundredsPassThroughUntouchedAndNeverOpenIt` fails.
- remove `SERVICE_UNAVAILABLE` from `statusCodes` → `repeatedServiceUnavailableOpensIt…` fails.
- give the ledger route `name: authcore` → `onlyTheSickDownstreamIsCutOff` fails.
- delete `removeDownstreamHeaders(...)` from `render` → `countedStatusesAreReplaced…` fails on `X-Upstream`/`Set-Cookie`.
- set `disable-time-limiter: false` with the ledger route timeout at 3000 ms and a 1500 ms stub in a scratch test → 504 at about 1 s. (Optional to automate; `ProductionValuesTest` pins the property.)

Run: `.\mvnw.cmd -o test` — expected 302 (295 + 6 + 1), 0 failures. Every existing integration test now runs through a breaker; if any changes behaviour, report it.

- [ ] **Step 8: Commit**

```
feat(M7): a circuit breaker per downstream

The authcore and ledger breakers count connect errors, timeouts and
downstream 502/503/504; a downstream 500 is the downstream's own answer
and passes through untouched, uncounted. Open, a breaker answers 503
DOWNSTREAM_UNAVAILABLE at once with Retry-After. Counted statuses become
the gateway's shape with DOWNSTREAM_ERROR, downstream headers removed.
The 1 s TimeLimiter is off; the routes' timeouts govern.
```

---

### Task 6: One retry, for GET only, inside the breaker (spec §9)

**Files:**
- Modify: `src/main/resources/application.yml`
- Test: `src/test/java/com/gatekeeper/resilience/DownstreamRetryTest.java`

- [ ] **Step 1: Branch**

`git checkout master; git checkout -b feature/m7-task-6`

- [ ] **Step 2: Write the failing test**

`src/test/java/com/gatekeeper/resilience/DownstreamRetryTest.java`:

```java
package com.gatekeeper.resilience;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.stubbing.Scenario;
import com.gatekeeper.support.TestKey;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.cloud.circuitbreaker.resilience4j.ReactiveResilience4JCircuitBreakerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * One retry, for GET only, after 100 ms, on 502, 503 and connect errors; never a POST, a timeout or a
 * 500. Inside the breaker: it sees one outcome per client request. And a retry spends no extra
 * rate-limit token. The M7 design, section 9.
 *
 * <p>Each test calls as a fresh tenant on a small plan, so its rate-limit count starts full.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class DownstreamRetryTest {

    static final String ISSUER = "http://localhost:8080";
    static WireMockServer downstream;
    static TestKey signingKey;

    @Autowired
    WebTestClient client;

    @Autowired
    ReactiveResilience4JCircuitBreakerFactory breakers;

    String tenant;

    @BeforeAll
    static void start() {
        signingKey = TestKey.generate("k1");
        downstream = new WireMockServer(options().dynamicPort());
        downstream.start();
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
        registry.add("gatekeeper.resilience.response-timeout-millis.ledger", () -> "300");
        registry.add("gatekeeper.rate-limit.default-plan", () -> "retry10");
        registry.add("gatekeeper.rate-limit.plans.retry10.requests-per-second", () -> "1");
        registry.add("gatekeeper.rate-limit.plans.retry10.burst", () -> "10");
        registry.add("gatekeeper.rate-limit.plans.retry10.daily-quota", () -> "1000");
    }

    @BeforeEach
    void reset() {
        tenant = "retry-" + UUID.randomUUID();
        downstream.resetAll();
        downstream.stubFor(get(urlEqualTo("/oauth2/jwks")).willReturn(okJson(TestKey.jwksDocument(signingKey))));
        breakers.getCircuitBreakerRegistry().getAllCircuitBreakers().forEach(CircuitBreaker::reset);
    }

    @Test
    void aGetIsRetriedOnceOnServiceUnavailableAndSucceeds() {
        flakyOnce(503);

        getEntries().expectStatus().isOk();

        downstream.verify(2, getRequestedFor(urlEqualTo("/ledger/entries")));
    }

    @Test
    void aGetIsRetriedOnceOnBadGatewayAndSucceeds() {
        flakyOnce(502);

        getEntries().expectStatus().isOk();

        downstream.verify(2, getRequestedFor(urlEqualTo("/ledger/entries")));
    }

    @Test
    void onlyOnce() {
        downstream.stubFor(get(urlEqualTo("/ledger/entries")).willReturn(aResponse().withStatus(503)));

        getEntries().expectStatus().isEqualTo(503).expectBody().jsonPath("$.detail").isEqualTo("DOWNSTREAM_ERROR");

        downstream.verify(2, getRequestedFor(urlEqualTo("/ledger/entries")));
    }

    @Test
    void aPostIsNeverRetried() {
        downstream.stubFor(post(urlEqualTo("/ledger/entries")).willReturn(aResponse().withStatus(503)));

        client.post().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, token())
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{}")
                .exchange()
                .expectStatus().isEqualTo(503);

        downstream.verify(1, postRequestedFor(urlEqualTo("/ledger/entries")));
    }

    @Test
    void aTimeoutIsNotRetried() {
        downstream.stubFor(get(urlEqualTo("/ledger/entries")).willReturn(aResponse().withFixedDelay(800).withStatus(200)));

        getEntries().expectStatus().isEqualTo(504);

        downstream.verify(1, getRequestedFor(urlEqualTo("/ledger/entries")));
    }

    @Test
    void aFiveHundredIsNotRetried() {
        downstream.stubFor(get(urlEqualTo("/ledger/entries")).willReturn(aResponse().withStatus(500).withBody("own")));

        getEntries().expectStatus().isEqualTo(500).expectBody(String.class).isEqualTo("own");

        downstream.verify(1, getRequestedFor(urlEqualTo("/ledger/entries")));
    }

    /** Inside the breaker: a request that succeeds on its retry is one success, not a failure and a success. */
    @Test
    void theBreakerSeesOneOutcomePerRequest() {
        flakyOnce(503);

        getEntries().expectStatus().isOk();

        CircuitBreaker.Metrics metrics = breakers.getCircuitBreakerRegistry().find("ledger").orElseThrow().getMetrics();
        assertThat(metrics.getNumberOfFailedCalls()).isZero();
        assertThat(metrics.getNumberOfSuccessfulCalls()).isEqualTo(1);
    }

    /** The rate limiter runs before the route's filters, so a retried request costs one token. */
    @Test
    void aRetriedRequestCostsOneRateLimitToken() {
        flakyOnce(503);

        getEntries().expectStatus().isOk().expectHeader().valueEquals("X-RateLimit-Remaining", "9");
    }

    private void flakyOnce(int status) {
        downstream.stubFor(get(urlEqualTo("/ledger/entries")).inScenario("flaky")
                .whenScenarioStateIs(Scenario.STARTED)
                .willReturn(aResponse().withStatus(status))
                .willSetStateTo("recovered"));
        downstream.stubFor(get(urlEqualTo("/ledger/entries")).inScenario("flaky")
                .whenScenarioStateIs("recovered")
                .willReturn(okJson("[]")));
    }

    private WebTestClient.ResponseSpec getEntries() {
        return client.get().uri("/api/ledger/entries").header(HttpHeaders.AUTHORIZATION, token()).exchange();
    }

    private String token() {
        return "Bearer " + signingKey.mint(ISSUER, "ezzat", Instant.now().plus(5, ChronoUnit.MINUTES),
                Map.of("tenant", tenant, "scope", List.of("payments:read", "payments:write")));
    }
}
```

- [ ] **Step 3: Run to see it fail**

Run: `.\mvnw.cmd -o -q test "-Dtest=DownstreamRetryTest"` — expected: the two "retried … succeeds" tests and the two that count requests get one request where two are expected.

- [ ] **Step 4: The routes' `Retry` filters**

In `application.yml`, add to each route's `filters:`, **directly after** `CircuitBreaker` (the configuration below was run and verified against Spring Cloud Gateway 5.0.2 while planning):

```yaml
                # After the breaker, so the breaker sees one outcome per client request, and nothing
                # is retried while it is open. GET only, once, after 100 ms, on 502, 503 and connect
                # errors. series is empty so only the listed statuses count, and exceptions is set
                # explicitly because the default list includes the gateway's TimeoutException — every
                # response timeout would be retried. Never a POST, a timeout or a 500.
                # The M7 design, section 9.
                - name: Retry
                  args:
                    retries: 1
                    methods: GET
                    statuses: BAD_GATEWAY,SERVICE_UNAVAILABLE
                    series:
                    exceptions: java.net.ConnectException
                    backoff:
                      firstBackoff: 100ms
                      maxBackoff: 100ms
                      factor: 1
                      basedOnPreviousValue: false
```

- [ ] **Step 5: Run, make it fail, the suite**

Run the class — expected 8 pass. Mutations with `clean`, each restored:
- `methods: GET,POST` → `aPostIsNeverRetried` fails.
- delete the `exceptions:` line (back to the defaults) → `aTimeoutIsNotRetried` fails.
- move the `Retry` filter **before** `CircuitBreaker` → `theBreakerSeesOneOutcomePerRequest` fails.

Run: `.\mvnw.cmd -o test` — expected 310 (302 + 8), 0 failures. `DownstreamCircuitBreakerTest` uses POST and must be unaffected.

- [ ] **Step 6: Commit**

```
feat(M7): retry a GET once, inside the breaker

One retry after 100 ms on 502, 503 and connect errors, for GET only;
never a POST, a timeout or a 500. After the breaker in each route, so
the breaker sees one outcome per client request and nothing is retried
while it is open. The rate limiter runs first, so a retry costs no extra
token. The exception list is explicit: the default retries timeouts.
```

---

### Task 7: A semaphore bulkhead per downstream (spec §10)

**Files:**
- Modify: `src/main/java/com/gatekeeper/resilience/ResilienceConfig.java`
- Modify: `src/main/java/com/gatekeeper/error/GlobalErrorWebExceptionHandler.java`
- Test: `src/test/java/com/gatekeeper/resilience/DownstreamBulkheadTest.java`

- [ ] **Step 1: Branch**

`git checkout master; git checkout -b feature/m7-task-7`

- [ ] **Step 2: Write the failing test**

`src/test/java/com/gatekeeper/resilience/DownstreamBulkheadTest.java`:

```java
package com.gatekeeper.resilience;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.gatekeeper.support.TestKey;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.cloud.circuitbreaker.resilience4j.ReactiveResilience4JCircuitBreakerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * With a limit of 2: two slow requests in flight to ledger, and the next is refused at once 503
 * DOWNSTREAM_BUSY. Refusals never count as breaker failures, and AuthCore is unaffected. The M7 design,
 * section 10. The breaker's window is small here so that, were refusals counted, it would open.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class DownstreamBulkheadTest {

    static final String ISSUER = "http://localhost:8080";
    static WireMockServer downstream;
    static TestKey signingKey;

    @Autowired
    WebTestClient client;

    @Autowired
    ReactiveResilience4JCircuitBreakerFactory breakers;

    @LocalServerPort
    int port;

    @BeforeAll
    static void start() {
        signingKey = TestKey.generate("k1");
        downstream = new WireMockServer(options().dynamicPort().containerThreads(20));
        downstream.start();
        downstream.stubFor(get(urlEqualTo("/oauth2/jwks")).willReturn(okJson(TestKey.jwksDocument(signingKey))));
        downstream.stubFor(get(urlEqualTo("/ledger/slow")).willReturn(aResponse().withFixedDelay(1500).withStatus(200)));
        downstream.stubFor(get(urlEqualTo("/api/machine/payments")).willReturn(okJson("[]")));
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
        registry.add("gatekeeper.resilience.bulkhead.max-concurrent-calls", () -> "2");
        registry.add("gatekeeper.resilience.breaker.sliding-window-size", () -> "4");
        registry.add("gatekeeper.resilience.breaker.minimum-calls", () -> "4");
    }

    @Test
    void aFullBulkheadRefusesAtOnceWithoutCountingAgainstTheBreaker() throws Exception {
        WebClient direct = WebClient.create("http://localhost:" + port);
        List<CompletableFuture<Integer>> held = new ArrayList<>();
        for (int i = 0; i < 2; i++) {
            held.add(direct.get().uri("/api/ledger/slow").header(HttpHeaders.AUTHORIZATION, token())
                    .exchangeToMono(response -> Mono.just(response.statusCode().value()))
                    .toFuture());
        }
        Thread.sleep(400); // both are now in flight, waiting on the slow downstream

        for (int i = 0; i < 6; i++) {
            long started = System.nanoTime();
            client.get().uri("/api/ledger/slow")
                    .header(HttpHeaders.AUTHORIZATION, token())
                    .exchange()
                    .expectStatus().isEqualTo(503)
                    .expectHeader().valueEquals(HttpHeaders.RETRY_AFTER, "1")
                    .expectBody()
                    .jsonPath("$.error").isEqualTo("service_unavailable")
                    .jsonPath("$.detail").isEqualTo("DOWNSTREAM_BUSY");
            assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofMillis(500));
        }

        // AuthCore has its own bulkhead: unaffected while ledger's is full.
        client.get().uri("/api/machine/payments").header(HttpHeaders.AUTHORIZATION, token())
                .exchange().expectStatus().isOk();

        for (CompletableFuture<Integer> request : held) {
            assertThat(request.get(5, TimeUnit.SECONDS)).isEqualTo(200);
        }
        downstream.verify(2, getRequestedFor(urlEqualTo("/ledger/slow")));
        CircuitBreaker ledger = breakers.getCircuitBreakerRegistry().find("ledger").orElseThrow();
        assertThat(ledger.getState()).isEqualTo(CircuitBreaker.State.CLOSED);
        assertThat(ledger.getMetrics().getNumberOfFailedCalls()).isZero();
    }

    private static String token() {
        return "Bearer " + signingKey.mint(ISSUER, "ezzat", Instant.now().plus(5, ChronoUnit.MINUTES),
                Map.of("tenant", "acme", "scope", List.of("payments:read")));
    }
}
```

- [ ] **Step 3: Run to see it fail**

Run: `.\mvnw.cmd -o -q test "-Dtest=DownstreamBulkheadTest"` — expected: the third request is not refused (the default bulkhead allows 25), or is refused as an unmapped 500.

- [ ] **Step 4: Configure the bulkheads**

In `ResilienceConfig`, add:

```java
    /**
     * A semaphore bulkhead per downstream, inside its breaker (Spring Cloud CircuitBreaker applies it
     * there, keyed by the breaker's name — verified in 5.0.2). Beyond the limit a request is refused at
     * once, without waiting: 503 DOWNSTREAM_BUSY. The breaker ignores the refusal. The M7 design,
     * section 10.
     */
    @Bean
    public Customizer<ReactiveResilience4jBulkheadProvider> downstreamBulkheads(ResilienceProperties properties) {
        BulkheadConfig config = BulkheadConfig.custom()
                .maxConcurrentCalls(properties.bulkhead().maxConcurrentCalls())
                .maxWaitDuration(Duration.ZERO)
                .build();
        return provider -> provider.configure(builder -> builder.bulkheadConfig(config), AUTHCORE, LEDGER);
    }
```

Imports: `io.github.resilience4j.bulkhead.BulkheadConfig`, `org.springframework.cloud.circuitbreaker.resilience4j.ReactiveResilience4jBulkheadProvider`, `java.time.Duration`.

- [ ] **Step 5: Map the refusal**

In `GlobalErrorWebExceptionHandler`, add the constant and, in `answerFor` before the timeout case:

```java
    /** The downstream's bulkhead is full. The M7 design, section 10. */
    public static final String DOWNSTREAM_BUSY = "DOWNSTREAM_BUSY";
```

```java
        if (error instanceof BulkheadFullException) {
            return new Answer(HttpStatus.SERVICE_UNAVAILABLE, DOWNSTREAM_BUSY, "1");
        }
```

Import `io.github.resilience4j.bulkhead.BulkheadFullException`; it reaches the handler raw (verified).

- [ ] **Step 6: Run, make it fail, the suite**

Run the class — expected pass. Mutation with `clean`: remove `.ignoreExceptions(BulkheadFullException.class)` from the breaker config → the breaker opens on the refusals (state OPEN, failed calls > 0) — the test fails. Restore.

Run: `.\mvnw.cmd -o test` — expected 311 (310 + 1), 0 failures.

- [ ] **Step 7: Commit**

```
feat(M7): a semaphore bulkhead per downstream

At most gatekeeper.resilience.bulkhead.max-concurrent-calls requests in
flight to each downstream; beyond that, refused at once 503
DOWNSTREAM_BUSY with Retry-After: 1. A refusal is not a breaker failure,
and one downstream's full bulkhead does not touch the other's.
```

---

### Task 8: The production values are the agreed ones (spec §11)

**Files:**
- Test: `src/test/java/com/gatekeeper/resilience/ProductionValuesTest.java`

- [ ] **Step 1: Branch**

`git checkout master; git checkout -b feature/m7-task-8`

- [ ] **Step 2: Verify the classes the test reads**

`javap` in the gateway server-webflux 5.0.2 jar: `org.springframework.cloud.gateway.config.GatewayProperties` (`getRoutes()` → `List<RouteDefinition>`), `org.springframework.cloud.gateway.config.HttpClientProperties` (`getConnectTimeout()` → `Integer`, `getResponseTimeout()` → `Duration`), `RouteDefinition.getMetadata()`, `getFilters()` → `List<FilterDefinition>` (`getName()`, `getArgs()` → `Map<String,String>`). In the CircuitBreaker jar: `Resilience4JConfigurationProperties.isDisableTimeLimiter()`. Adjust names if they differ and say so.

- [ ] **Step 3: Write the test**

`src/test/java/com/gatekeeper/resilience/ProductionValuesTest.java`:

```java
package com.gatekeeper.resilience;

import io.github.resilience4j.bulkhead.BulkheadConfig;
import io.github.resilience4j.circuitbreaker.CircuitBreakerConfig;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.circuitbreaker.resilience4j.ReactiveResilience4JCircuitBreakerFactory;
import org.springframework.cloud.circuitbreaker.resilience4j.ReactiveResilience4jBulkheadProvider;
import org.springframework.cloud.circuitbreaker.resilience4j.Resilience4JConfigurationProperties;
import org.springframework.cloud.gateway.config.GatewayProperties;
import org.springframework.cloud.gateway.config.HttpClientProperties;
import org.springframework.cloud.gateway.filter.FilterDefinition;
import org.springframework.cloud.gateway.route.RouteDefinition;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The values the repo owner agreed, read from the real application.yml with no test overrides, so the
 * small values the other tests use can never hide a production change. The M7 design, section 11.
 */
@SpringBootTest
class ProductionValuesTest {

    @Autowired
    GatewayProperties gateway;

    @Autowired
    HttpClientProperties httpClient;

    @Autowired
    ResilienceProperties resilience;

    @Autowired
    Resilience4JConfigurationProperties resilience4j;

    @Autowired
    ReactiveResilience4JCircuitBreakerFactory breakers;

    @Autowired
    ReactiveResilience4jBulkheadProvider bulkheads;

    @Test
    void timeouts() {
        assertThat(httpClient.getConnectTimeout()).isEqualTo(2000);
        assertThat(httpClient.getResponseTimeout()).isEqualTo(Duration.ofSeconds(5));
        assertThat(resilience.jwksTimeout()).isEqualTo(Duration.ofSeconds(2));
        for (RouteDefinition route : gateway.getRoutes()) {
            Object timeout = route.getMetadata().get("response-timeout");
            // Plain milliseconds, or Spring Cloud Gateway silently ignores it.
            assertThat(Long.parseLong(String.valueOf(timeout))).as(route.getId()).isEqualTo(5000L);
        }
    }

    @Test
    void everyRouteHasItsBreakerBeforeItsRetry() {
        Map<String, String> breakerNames = Map.of(
                "authcore-accounts", "authcore", "authcore-machine", "authcore", "ledger", "ledger");
        assertThat(gateway.getRoutes()).extracting(RouteDefinition::getId)
                .containsExactlyInAnyOrderElementsOf(breakerNames.keySet());

        for (RouteDefinition route : gateway.getRoutes()) {
            List<String> names = route.getFilters().stream().map(FilterDefinition::getName).toList();
            assertThat(names.indexOf("CircuitBreaker")).as(route.getId()).isZero();
            assertThat(names.indexOf("Retry")).as(route.getId()).isEqualTo(1);

            Map<String, String> breaker = args(route, "CircuitBreaker");
            assertThat(breaker.get("name")).isEqualTo(breakerNames.get(route.getId()));
            assertThat(breaker.get("statusCodes")).isEqualTo("BAD_GATEWAY,SERVICE_UNAVAILABLE,GATEWAY_TIMEOUT");

            Map<String, String> retry = args(route, "Retry");
            assertThat(retry.get("retries")).isEqualTo("1");
            assertThat(retry.get("methods")).isEqualTo("GET");
            assertThat(retry.get("statuses")).isEqualTo("BAD_GATEWAY,SERVICE_UNAVAILABLE");
            assertThat(retry.get("exceptions")).isEqualTo("java.net.ConnectException");
        }
    }

    @Test
    void theBreakersAndBulkheads() {
        assertThat(resilience4j.isDisableTimeLimiter()).isTrue();
        for (String name : List.of(ResilienceConfig.AUTHCORE, ResilienceConfig.LEDGER)) {
            // Run one call through, so the factory creates the breaker and bulkhead from its configuration.
            breakers.create(name).run(Mono.just("ok"), null).block();

            CircuitBreakerConfig breaker = breakers.getCircuitBreakerRegistry().find(name).orElseThrow()
                    .getCircuitBreakerConfig();
            assertThat(breaker.getSlidingWindowSize()).isEqualTo(20);
            assertThat(breaker.getMinimumNumberOfCalls()).isEqualTo(10);
            assertThat(breaker.getFailureRateThreshold()).isEqualTo(50f);
            assertThat(breaker.getPermittedNumberOfCallsInHalfOpenState()).isEqualTo(3);

            BulkheadConfig bulkhead = bulkheads.getBulkheadRegistry().find(name).orElseThrow().getBulkheadConfig();
            assertThat(bulkhead.getMaxConcurrentCalls()).isEqualTo(50);
            assertThat(bulkhead.getMaxWaitDuration()).isEqualTo(Duration.ZERO);
        }
        assertThat(resilience.breaker().openFor()).isEqualTo(Duration.ofSeconds(10));
    }

    private static Map<String, String> args(RouteDefinition route, String filter) {
        return route.getFilters().stream()
                .filter(definition -> definition.getName().equals(filter))
                .findFirst().orElseThrow()
                .getArgs().entrySet().stream()
                .collect(Collectors.toMap(Map.Entry::getKey, Map.Entry::getValue));
    }
}
```

If the bound `args` keys or comma-list values differ from these (for example list values bound as indexed keys `statuses.0`), print the map once, adjust **only how the test reads it**, never the expected values, and say what you saw. The open window is asserted from the properties because Resilience4j 2.3.0 stores it as an interval function; if `CircuitBreakerConfig` exposes it as a `Duration`, assert that instead.

- [ ] **Step 4: Run, make it fail, the suite**

Run the class — expected 3 pass. Mutations with `clean`, each restored: `failure-rate-threshold: 60` in `application.yml` → fails; ledger `response-timeout` metadata as `5s` → fails; `Retry` before `CircuitBreaker` on one route → fails.

Run: `.\mvnw.cmd -o test` — expected 314 (311 + 3), 0 failures.

- [ ] **Step 5: Commit**

```
test(M7): pin the production resilience values

Reads the real application.yml with no overrides: the timeouts, every
route's breaker before its retry and their arguments, the breakers' and
bulkheads' limits, and the TimeLimiter off. Small test values can no
longer hide a production change.
```

---

### Task 9: Mutation sweep (spec §11)

No production change unless a mutation survives. Branch `feature/m7-task-9`. Each mutation in the working copy, run with `clean`, restored with `git checkout -- src/main` before the next.

| # | Mutation | Run | Must fail |
|---|---|---|---|
| 1 | Add `INTERNAL_SERVER_ERROR` to a route's breaker `statusCodes` | `DownstreamCircuitBreakerTest,ProductionValuesTest` | yes |
| 2 | Remove `BAD_GATEWAY,SERVICE_UNAVAILABLE` from `statusCodes` | `DownstreamCircuitBreakerTest,ProductionValuesTest` | yes |
| 3 | Retry `methods: GET,POST` | `DownstreamRetryTest,ProductionValuesTest` | yes |
| 4 | Retry without the `exceptions:` line (defaults retry timeouts) | `DownstreamRetryTest,ProductionValuesTest` | yes |
| 5 | `Retry` before `CircuitBreaker` on the ledger route | `DownstreamRetryTest,ProductionValuesTest` | yes |
| 6 | Breaker without `ignoreExceptions(BulkheadFullException.class)` | `DownstreamBulkheadTest` | yes |
| 7 | `disable-time-limiter: false` | `ProductionValuesTest` | yes |
| 8 | `jwksWebClient` without its timeouts | `JwksTimeoutTest` | yes |
| 9 | Unreachable key set answered 401 again | `JwksTimeoutTest,UnreachableJwksErrorShapeTest` | yes |
| 10 | Remove the `reconnectQuickly` bean | `ReconnectDelayTest` | yes |
| 11 | Ledger route's breaker `name: authcore` | `DownstreamCircuitBreakerTest,ProductionValuesTest` | yes |
| 12 | Delete `removeDownstreamHeaders(...)` from `render` | `DownstreamCircuitBreakerTest` | yes |
| 13 | Map `CircuitBreakerStatusCodeException` to 503 regardless of status | `DownstreamCircuitBreakerTest` | yes |

If one survives: write the test that kills it, show it fail on the mutation and pass without it, commit `test(M7): <what it pins>`. Otherwise commit nothing. Report the table with results.

---

### Task 10: Live run (spec §11)

Branch: none (no repo change). Logs outside the repo, processes started with `run_in_background` and waited for by polling their logs.

1. From the authcore directory, `docker compose up -d postgres redis`. Start AuthCore (`.\mvnw.cmd -o spring-boot:run`, port 8080) and ledger-service (`.\mvnw.cmd -o spring-boot:run` from its directory, port 8082). Build GateKeeper (`.\mvnw.cmd -o -q package -DskipTests`) and start it: `java -jar target/gatekeeper-0.0.1-SNAPSHOT.jar` (port 8081).
2. **Ledger stopped.** A machine token is enough: `curl.exe -s -u authcore-machine:machine-secret -d "grant_type=client_credentials&scope=payments:read" http://localhost:8080/oauth2/token`. The gateway's ledger rule asks for a JWT with `payments:read`, which it carries; ledger-service itself then answers 403, since a machine token has no permissions — a 403 is the downstream's own answer, passed through and counted as a success, which is all the breaker needs. First confirm `GET http://localhost:8081/api/ledger/entries` reaches ledger (its 403) and `GET /api/machine/payments` answers. Stop ledger-service; send twelve GETs to the ledger route, recording `status time_total`: expect 502 `DOWNSTREAM_UNREACHABLE` for the first ten (each after one retry), then 503 `DOWNSTREAM_UNAVAILABLE` in milliseconds; the WARN "circuit breaker opened" once; AuthCore's route still answering. Start ledger-service; call once a second and record the time to the first non-503 (ledger's 403) and the breaker's INFO lines.
3. **A downstream that never answers.** A silent socket on port 18099 (a PowerShell `TcpListener` that accepts and never reads). A second gateway: `java -jar … --server.port=8091 --gatekeeper.downstream.authcore=http://localhost:18099`. `GET /api/machine/payments` with a machine token: expect 504 `DOWNSTREAM_TIMEOUT` at about 5 s, and after ten such calls 503 at once.
4. **A key set that never answers.** A third gateway: `--server.port=8092 --gatekeeper.auth.jwk-set-uri=http://localhost:18099/oauth2/jwks`. A bearer request: expect 503 `KEYS_UNAVAILABLE` in about 2 s; the WARN once.
5. **Redis down and up.** On the main gateway: get a fresh machine token, `docker stop authcore-redis-1`, wait 30 s or more (so Lettuce's old backoff would have grown), `docker start authcore-redis-1`, then call once a second and record the time from start to the first non-503. Expect about 7 s or less (M6: 17.8 s).
6. Shut everything you started down; keep Redis up. Run `.\mvnw.cmd -o test` (expected 314 plus any Task 9 additions) and `.\mvnw.cmd -o test "-Dspring.data.redis.port=1"`, recording both lines.

Report every observed line and number; Task 11 writes them up.

---

### Task 11: Documentation (spec §15)

Branch `feature/m7-task-11`. Read the README's M5 and M6 sections first and match their voice.

- **README:** an M7 section — the timeouts (global and per route, plain milliseconds and why), the breakers (per downstream, what counts, **section 7's assumption stated plainly**: 502/503/504 are availability signals and are replaced, headers included; a 500 is the downstream's own answer and passes through untouched), the retry (GET only, once, inside the breaker, one token), the bulkhead, the JWKS 503, the reconnect delay, the response table of spec §8, the live run with its numbers; the test tables and counts; known limitations, including the all-500 downstream; the roadmap.
- **Handoff:** §1 to "Next: M8 — audit and observability"; the repo table; M7 Built in §4; in §5 the JWKS-timeout and Lettuce-backoff items closed, the all-500 item added, the constants item updated; §6 `feature/m8-task-N`.
- **Design:** append "As built" and "Live run" paragraphs to §11.
- Commit `docs(M7): resilience in the README, handoff and design`. No attribution anywhere.

---

## Self-review notes (for the controller)

- **Spec coverage:** §3 → T1; §4 → T3; §5 → T4; §6 → T5; §7 → T5 (tests + handler Javadoc), T11; §8 → T3–T7; §9 → T6; §10 → T7; §11 → T1–T10; §12 → T2–T7; §14 → T3, T5; §15 → T11.
- **Expected counts**, each task branching from `master` after the previous merged: 278 → 282 (T1) → 289 (T2) → 292 (T3) → 295 (T4) → 302 (T5) → 310 (T6) → 311 (T7) → 314 (T8). If a number is off, the implementer reports the actual count and which tests account for it.
- **The behaviours the repo owner fixed**, and where each is enforced: 500 untouched and uncounted (T5 test + mutation 1); 502/503/504 counted and replaced with headers (T5 tests + mutations 2, 12); breaker before retry (T6, T8, mutation 5); POST never retried (T6, mutation 3); one token per retry (T6); bulkhead refusals uncounted (T7, mutation 6); JWKS 503 (T3, mutation 9).
