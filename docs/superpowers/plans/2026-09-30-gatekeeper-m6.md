# GateKeeper M6 — Token Revocation Check — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Refuse a revoked JWT with 401 on the next request at every gateway instance, and refuse fast with 503 when Redis cannot say whether a token is revoked.

**Architecture:** A `ReactiveJwtDecoder` wraps the existing Nimbus decoder: after signature, `exp`, `nbf` and `iss` pass, it requires a non-blank `jti` and asks Redis `EXISTS authcore:revoked:jti:<jti>` (AuthCore's deny-list). The call goes through M5's single-flight connection step, extracted into `com.gatekeeper.redis`, within a 200 ms timeout and behind a circuit breaker of its own whose open state **refuses**. A revoked token is a `BadJwtException` (ordinary 401); an unanswerable check is a `RevocationUnavailableException`, which the global error handler answers 503.

**Tech Stack:** Spring Boot 4.0.7, Spring Security 7.0.6, Spring Cloud Gateway 5.0.2 (webflux), spring-data-redis 4.0.6 (Lettuce), Reactor 3.8 with reactor-test, JUnit 6, AssertJ, WireMock 3.13.2.

**Spec:** `docs/superpowers/specs/2026-09-30-gatekeeper-m6-design.md`. Read it before any task; section numbers below refer to it.

---

## Conventions for every task

- **Branch:** `feature/m6-task-N` off `master`; merged back by the controller with `git merge --no-ff`. Do not merge or push yourself.
- **Build:** `.\mvnw.cmd -o ...` from the repo root, in PowerShell. Never `mvn`. `&&` does not work in Windows PowerShell 5.1; use `;`.
- **Redis must be running** for the suite: `docker ps` must show `authcore-redis-1` up. If it is not, `docker start authcore-redis-1`. Without it about 45 tests fail on connection errors; that is not a regression.
- **Commits:** write the message to a file and `git commit -F <file>`. Never `-m` with quotes. **No `Co-Authored-By` line and no mention of Claude or any AI tool** in any commit message.
- **Files:** UTF-8 without BOM. Move files with `git mv` so history follows them.
- **Verify facts against the jars, not memory:** `jar tf <jar> | Select-String <Name>` and `javap -cp <jar> <FQCN>`. Boot 4 moved many classes.
- **A test that passes the moment you write it has proven nothing.** Each task says how to see it fail first.

## File map

| File | Task | Responsibility |
|---|---|---|
| `src/main/java/com/gatekeeper/redis/RedisConnectionStep.java` | 1 | Single-flight, uncancellable connect; shared by every Redis consumer |
| `src/main/java/com/gatekeeper/redis/RedisConfig.java` | 1 | The connection-step bean |
| `src/main/java/com/gatekeeper/redis/RedisWarmUp.java` | 1 (moved), 6 | Bounded connect before the port binds |
| `src/main/java/com/gatekeeper/redis/RedisCircuitBreaker.java` | 2 (moved) | Named breaker; permits CLOSED / PROBE / DENIED |
| `src/main/java/com/gatekeeper/ratelimit/RedisRateLimitStore.java` | 1 | Uses the shared connection step |
| `src/main/java/com/gatekeeper/ratelimit/RateLimitConfig.java` | 1, 2 | `rateLimitBreaker` bean |
| `src/main/java/com/gatekeeper/ratelimit/RateLimitFilter.java` | 2 | Injects `rateLimitBreaker` by qualifier |
| `src/main/java/com/gatekeeper/revocation/RevocationStore.java` | 3 | `Mono<Boolean> isRevoked(String jti)` |
| `src/main/java/com/gatekeeper/revocation/RedisRevocationStore.java` | 3 | `EXISTS authcore:revoked:jti:<jti>` after the connection step |
| `src/main/java/com/gatekeeper/revocation/RevocationUnavailableException.java` | 4 | The 503 signal; neither `JwtException` nor `AuthenticationException` |
| `src/main/java/com/gatekeeper/revocation/RevocationCheckingJwtDecoder.java` | 4 | The check itself |
| `src/main/java/com/gatekeeper/revocation/RevocationProperties.java` | 5 | `gatekeeper.revocation.redis-timeout` |
| `src/main/java/com/gatekeeper/revocation/RevocationConfig.java` | 6 | `revocationStore` and `revocationBreaker` beans |
| `src/main/java/com/gatekeeper/config/JwtDecoderConfig.java` | 6 | Returns the wrapping decoder |
| `src/main/java/com/gatekeeper/error/GlobalErrorWebExceptionHandler.java` | 6 | 503 + `detail` for `RevocationUnavailableException` |
| `src/main/java/com/gatekeeper/error/ErrorBody.java` | 6 | Javadoc: a fifth call site with a `detail` |
| `src/main/resources/application.yml` | 5 | The `gatekeeper.revocation` block |
| `src/test/java/com/gatekeeper/support/TestKey.java` | 6 | Mint with a chosen or absent `jti`; read a token's `jti` |

---

### Task 1: Extract the connection step into `com.gatekeeper.redis`

A pure refactor: no behaviour changes. `RedisRateLimitStore`'s connect step becomes `RedisConnectionStep`, one bean; the store and the warm-up use it; `RedisWarmUp` moves to the new package.

**Files:**
- Create: `src/main/java/com/gatekeeper/redis/RedisConnectionStep.java`
- Create: `src/main/java/com/gatekeeper/redis/RedisConfig.java`
- Move: `src/main/java/com/gatekeeper/ratelimit/RedisWarmUp.java` → `src/main/java/com/gatekeeper/redis/RedisWarmUp.java`
- Modify: `src/main/java/com/gatekeeper/ratelimit/RedisRateLimitStore.java`
- Modify: `src/main/java/com/gatekeeper/ratelimit/RateLimitConfig.java`
- Move: `src/test/java/com/gatekeeper/ratelimit/RedisRateLimitStoreConnectTest.java` → `src/test/java/com/gatekeeper/redis/RedisConnectionStepTest.java`
- Move: `src/test/java/com/gatekeeper/ratelimit/RedisWarmUpTest.java` → `src/test/java/com/gatekeeper/redis/RedisWarmUpTest.java`
- Modify: `src/test/java/com/gatekeeper/ratelimit/RedisRateLimitStoreTest.java` (two constructor calls)

- [ ] **Step 1: Create the branch and move the two test files**

```powershell
git checkout master; git checkout -b feature/m6-task-1
New-Item -ItemType Directory -Force src/test/java/com/gatekeeper/redis, src/main/java/com/gatekeeper/redis | Out-Null
git mv src/test/java/com/gatekeeper/ratelimit/RedisRateLimitStoreConnectTest.java src/test/java/com/gatekeeper/redis/RedisConnectionStepTest.java
git mv src/test/java/com/gatekeeper/ratelimit/RedisWarmUpTest.java src/test/java/com/gatekeeper/redis/RedisWarmUpTest.java
git mv src/main/java/com/gatekeeper/ratelimit/RedisWarmUp.java src/main/java/com/gatekeeper/redis/RedisWarmUp.java
```

- [ ] **Step 2: Rewrite `RedisConnectionStepTest` against the new class**

Replace the whole file `src/test/java/com/gatekeeper/redis/RedisConnectionStepTest.java` with:

```java
package com.gatekeeper.redis;

import org.junit.jupiter.api.Test;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.NoSuchElementException;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertTimeoutPreemptively;

/**
 * The shared connection step: one attempt at a time, which no caller can cancel; a success kept
 * for good, a failure not kept at all. The M5 design, section 7; shared since M6 (its section 7).
 */
class RedisConnectionStepTest {

    final AtomicInteger pings = new AtomicInteger();

    @Test
    void callersWhoGiveUpNeitherCancelNorRepeatTheAttempt() throws InterruptedException {
        CountDownLatch answer = new CountDownLatch(1);
        AtomicInteger interrupted = new AtomicInteger();
        RedisConnectionStep step = new RedisConnectionStep(() -> Mono.fromCallable(() -> {
            pings.incrementAndGet();
            try {
                // blocks inside subscribe, as Lettuce's connect does
                answer.await();
            } catch (InterruptedException ex) {
                interrupted.incrementAndGet();
                throw ex;
            }
            return "PONG";
        }));

        // Preemptive, so a step that blocked its caller inside subscribe fails rather than hangs.
        assertTimeoutPreemptively(Duration.ofSeconds(3), () -> {
            for (int i = 0; i < 3; i++) {
                assertThatThrownBy(() -> step.ready().timeout(Duration.ofMillis(50)).block())
                        .hasCauseInstanceOf(TimeoutException.class);
            }
        });
        CountDownLatch connected = new CountDownLatch(1);
        step.ready().subscribe(null, error -> { }, connected::countDown);
        answer.countDown();

        assertThat(connected.await(2, TimeUnit.SECONDS)).isTrue();
        assertThat(pings).hasValue(1);
        assertThat(interrupted).hasValue(0);
    }

    @Test
    void keepsASuccess() {
        RedisConnectionStep step = new RedisConnectionStep(() -> Mono.fromCallable(() -> {
            pings.incrementAndGet();
            return "PONG";
        }));

        step.ready().block(Duration.ofSeconds(2));
        step.ready().block(Duration.ofSeconds(2));

        assertThat(pings).hasValue(1);
    }

    /** An empty ping is not a success: it must not be cached, so the next caller pings again. */
    @Test
    void anEmptyPingIsRetried() {
        RedisConnectionStep step = new RedisConnectionStep(() -> {
            int attempt = pings.incrementAndGet();
            return attempt == 1 ? Mono.empty() : Mono.just("PONG");
        });

        assertThatThrownBy(() -> step.ready().block(Duration.ofSeconds(2)))
                .isInstanceOf(NoSuchElementException.class);
        step.ready().block(Duration.ofSeconds(2));

        assertThat(pings).hasValue(2);
    }

    @Test
    void triesAgainAfterAFailure() {
        RedisConnectionStep step = new RedisConnectionStep(() -> Mono.fromCallable(() -> {
            if (pings.incrementAndGet() == 1) {
                throw new IllegalStateException("connection refused");
            }
            return "PONG";
        }));

        assertThatThrownBy(() -> step.ready().block(Duration.ofSeconds(2)))
                .hasMessageContaining("connection refused");
        step.ready().block(Duration.ofSeconds(2));

        assertThat(pings).hasValue(2);
    }
}
```

- [ ] **Step 3: Point `RedisWarmUpTest` at the new class**

In `src/test/java/com/gatekeeper/redis/RedisWarmUpTest.java`: change the package line to `package com.gatekeeper.redis;`, change the Javadoc's "on the store's connection step" to "on the shared connection step", and replace the helper at the bottom with:

```java
    /** The real composition: the warm-up on a connection step whose ping stands in for Redis. */
    private static RedisWarmUp warmUp(Supplier<Mono<?>> ping) {
        return new RedisWarmUp(new RedisConnectionStep(ping));
    }
```

- [ ] **Step 4: Run the two moved tests to see them fail to compile**

Run: `.\mvnw.cmd -o -q test "-Dtest=RedisConnectionStepTest,RedisWarmUpTest"`
Expected: COMPILATION ERROR — `RedisConnectionStep` does not exist.

- [ ] **Step 5: Create `RedisConnectionStep`**

`src/main/java/com/gatekeeper/redis/RedisConnectionStep.java`:

```java
package com.gatekeeper.redis;

import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import reactor.core.publisher.Mono;
import reactor.core.scheduler.Schedulers;

import java.time.Duration;
import java.util.function.Supplier;

/**
 * Connects to Redis once, by one attempt no caller can cancel. The M5 design, section 7; shared by
 * the rate limiter and the revocation check since M6 (its section 7).
 *
 * <p>Lettuce opens its shared connection with a blocking wait inside {@code subscribe()}, before any
 * timeout downstream has started. So every consumer connects through this single cached step: a
 * ping, subscribed on a worker thread so the wait never holds an event loop, whose success is kept
 * for good and whose failure is not kept at all, so the next caller tries again. A caller waits on
 * the step within its own timeout, and timing out stops the caller waiting, never the attempt. That
 * matters: cancelling the worker interrupts it, and Lettuce then abandons its connection attempt
 * rather than cancelling it — each timed-out request against a silent Redis used to leave one
 * connection behind, all of them going live when Redis answered again.
 *
 * <p>Once connected, a consumer makes no thread hop: Lettuce's commands are non-blocking on an
 * established connection, and it reconnects in the background.
 */
public class RedisConnectionStep {

    /** Keep a successful connection for good: exactly the value Reactor treats as "never expire". */
    private static final Duration FOREVER = Duration.ofMillis(Long.MAX_VALUE);

    private final Mono<Boolean> connected;

    public RedisConnectionStep(ReactiveStringRedisTemplate redis) {
        this(() -> redis.execute(connection -> connection.ping()).next());
    }

    /** For tests: any ping, to stand in for a Redis that answers, fails or never answers. */
    public RedisConnectionStep(Supplier<Mono<?>> ping) {
        // cache(value, error, empty): a success is kept forever, an error or an empty answer not at
        // all; and unlike cacheInvalidateIf, subscribers cancelling never cancel the attempt.
        //
        // "Forever" is the factory's lifetime. That holds because LettuceConnectionFactory drops its
        // shared connection only in resetConnection() — called by stop() and initConnection(), or by
        // validateConnection() when setValidateConnection(true), which Spring Boot does not set —
        // and normal operation calls none of them; Lettuce itself reconnects in the background.
        // After a lifecycle stop and restart, the first check would connect on the calling thread.
        //
        // .single() turns an empty ping into an error too, so it is not cached as success either —
        // cache's own "empty" branch only covers a Mono that completes with no error and no value
        // reaching thenReturn, which never happens once thenReturn always supplies one.
        this.connected = Mono.defer(ping)
                .subscribeOn(Schedulers.boundedElastic())
                .single()
                .thenReturn(Boolean.TRUE)
                .cache(ok -> FOREVER, error -> Duration.ZERO, () -> Duration.ZERO);
    }

    /** Completes once Redis has answered a ping; fails, uncached, if this attempt did not. */
    public Mono<Void> ready() {
        return connected.then();
    }
}
```

- [ ] **Step 6: Create `RedisConfig`**

`src/main/java/com/gatekeeper/redis/RedisConfig.java`:

```java
package com.gatekeeper.redis;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;

@Configuration
public class RedisConfig {

    /** One step for every consumer, so one Redis costs one connection attempt at a time. */
    @Bean
    public RedisConnectionStep redisConnectionStep(ReactiveStringRedisTemplate redis) {
        return new RedisConnectionStep(redis);
    }
}
```

- [ ] **Step 7: Move `RedisWarmUp` onto the step**

Replace `src/main/java/com/gatekeeper/redis/RedisWarmUp.java` with:

```java
package com.gatekeeper.redis;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.SmartInitializingSingleton;
import org.springframework.stereotype.Component;
import reactor.core.publisher.Mono;

import java.time.Duration;

/**
 * Connects to Redis once at startup, before the web server accepts traffic. The M5 design,
 * section 7.
 *
 * <p>Lettuce opens its shared connection on first use. Without this, the first request after boot
 * would pay for opening that connection and exceed its consumer's timeout. This only opens the
 * connection, not the rate limiter's script: the first request still pays one extra round trip,
 * {@code EVALSHA} answered {@code NOSCRIPT} then {@code EVAL}, which is small.
 * {@code afterSingletonsInstantiated} runs while the context refreshes, before the web server binds
 * its port.
 *
 * <p><strong>Bounded, and never fails the boot.</strong> It waits on the shared connection step —
 * which already runs on a worker thread — for at most {@link #WARM_UP_TIMEOUT}. Giving up stops the
 * waiting, not the attempt, which the first requests then share. A Redis that is down or silent
 * only logs a warning.
 */
@Component
public class RedisWarmUp implements SmartInitializingSingleton {

    static final Duration WARM_UP_TIMEOUT = Duration.ofSeconds(2);

    private static final Logger log = LoggerFactory.getLogger(RedisWarmUp.class);

    private final RedisConnectionStep connection;

    public RedisWarmUp(RedisConnectionStep connection) {
        this.connection = connection;
    }

    @Override
    public void afterSingletonsInstantiated() {
        connection.ready()
                .timeout(WARM_UP_TIMEOUT)
                .onErrorResume(error -> {
                    log.warn("Redis did not answer the startup warm-up; the rate limiter will fail open until it does",
                            error);
                    return Mono.empty();
                })
                .block();
    }
}
```

- [ ] **Step 8: Make `RedisRateLimitStore` use the step**

In `src/main/java/com/gatekeeper/ratelimit/RedisRateLimitStore.java`:

1. Delete the imports `reactor.core.scheduler.Schedulers`, `java.time.Duration` and `java.util.function.Supplier`; add `import com.gatekeeper.redis.RedisConnectionStep;`.
2. Replace the third Javadoc paragraph (starting `<p><strong>Connected once, by one attempt no caller can cancel.</strong>`) and the fourth (starting `<p>Once connected`) with this single paragraph:

```java
 * <p><strong>Connects through the shared {@link RedisConnectionStep}</strong>, which never lets a
 * blocking connect hold an event loop or leak a connection per timed-out request. The M5 design,
 * section 7.
```

3. Delete the `FOREVER` constant, the `connected` field, both constructors and the `connect()` method, and put in their place:

```java
    private final ReactiveStringRedisTemplate redis;
    private final RedisConnectionStep connection;

    public RedisRateLimitStore(ReactiveStringRedisTemplate redis, RedisConnectionStep connection) {
        this.redis = redis;
        this.connection = connection;
    }
```

4. In `run(...)`, change the first line of the chain from `return connected` to `return connection.ready()`.

- [ ] **Step 9: Update `RateLimitConfig`**

Replace the `rateLimitStore` bean method and its Javadoc line in `src/main/java/com/gatekeeper/ratelimit/RateLimitConfig.java` with:

```java
    @Bean
    public RedisRateLimitStore rateLimitStore(ReactiveStringRedisTemplate redis, RedisConnectionStep connection) {
        return new RedisRateLimitStore(redis, connection);
    }
```

and add `import com.gatekeeper.redis.RedisConnectionStep;`.

- [ ] **Step 10: Update `RedisRateLimitStoreTest`'s two constructor calls**

In `src/test/java/com/gatekeeper/ratelimit/RedisRateLimitStoreTest.java`, add a field and an import:

```java
import com.gatekeeper.redis.RedisConnectionStep;
...
    @Autowired
    RedisConnectionStep connection;
```

and change both `new RedisRateLimitStore(redis)` to `new RedisRateLimitStore(redis, connection)`.

- [ ] **Step 11: Run the moved tests, then the whole suite**

Run: `.\mvnw.cmd -o -q test "-Dtest=RedisConnectionStepTest,RedisWarmUpTest,RedisRateLimitStoreTest"`
Expected: all pass.

Run: `.\mvnw.cmd -o test`
Expected: `Tests run: 242, Failures: 0, Errors: 0` — the same count as before; this task only moves code.

- [ ] **Step 12: Check nothing still refers to the old names**

Run: `git grep -n "RedisRateLimitStoreConnectTest\|store.connect()\|ratelimit.RedisWarmUp"`
Expected: no output. (`README.md` or the handoff may mention them; if so, leave the docs for Task 10 and say so in your report.)

- [ ] **Step 13: Commit**

Message file:

```
refactor(M6): share Redis's connection step between its consumers

The rate limiter's single-flight, uncancellable connect moves into
com.gatekeeper.redis as RedisConnectionStep, one bean. The store and the
startup warm-up wait on it; the revocation check will too, so one Redis
still costs one connection attempt at a time. No behaviour changes.
```

```powershell
git add -A; git commit -F <message-file>
```

---

### Task 2: Move the breaker to `com.gatekeeper.redis` and give it a name

The same class serves two consumers from Task 6 on. Each log line must say which one, and what that consumer does while it is open. `rateLimitBreaker` is injected by qualifier so a second breaker bean cannot make injection ambiguous.

**Files:**
- Move: `src/main/java/com/gatekeeper/ratelimit/RedisCircuitBreaker.java` → `src/main/java/com/gatekeeper/redis/RedisCircuitBreaker.java`
- Move: `src/test/java/com/gatekeeper/ratelimit/RedisCircuitBreakerTest.java` → `src/test/java/com/gatekeeper/redis/RedisCircuitBreakerTest.java`
- Modify: `src/main/java/com/gatekeeper/ratelimit/RateLimitConfig.java`
- Modify: `src/main/java/com/gatekeeper/ratelimit/RateLimitFilter.java`
- Modify: `src/test/java/com/gatekeeper/ratelimit/RateLimitFilterTest.java`

- [ ] **Step 1: Branch and move**

```powershell
git checkout master; git checkout -b feature/m6-task-2
git mv src/main/java/com/gatekeeper/ratelimit/RedisCircuitBreaker.java src/main/java/com/gatekeeper/redis/RedisCircuitBreaker.java
git mv src/test/java/com/gatekeeper/ratelimit/RedisCircuitBreakerTest.java src/test/java/com/gatekeeper/redis/RedisCircuitBreakerTest.java
```

- [ ] **Step 2: Update the moved test and add the log test**

In `src/test/java/com/gatekeeper/redis/RedisCircuitBreakerTest.java`:

1. Package `com.gatekeeper.redis`; import `com.gatekeeper.redis.RedisCircuitBreaker.Permit`.
2. Add imports:

```java
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
```

   First confirm the package is still right in Boot 4:
   `jar tf "$env:USERPROFILE\.m2\repository\org\springframework\boot\spring-boot-test\4.0.7\spring-boot-test-4.0.7.jar" | Select-String OutputCaptureExtension`.
   If it has moved, use the path the jar shows.
3. Annotate the class `@ExtendWith(OutputCaptureExtension.class)`, change its Javadoc to `/** The breaker, on a fake clock. The M5 design, section 7; the M6 design, section 7. */`.
4. Replace the `breaker` field with:

```java
    final RedisCircuitBreaker breaker = new RedisCircuitBreaker("Test consumer", "doing the test thing",
            WINDOW, RedisCircuitBreaker.FAILURES_TO_OPEN, now::get);
```

5. Add these two tests before the `open()` helper:

```java
    /** Two consumers share this class: each line must say whose Redis, and what happens meanwhile. */
    @Test
    void itsOpeningNamesItsConsumerAndWhatHappensWhileOpen(CapturedOutput output) {
        open();

        assertThat(output).contains(
                "Test consumer: Redis failed 3 times in a row; doing the test thing for 5 s at a time until it answers");
    }

    @Test
    void itsClosingNamesItsConsumer(CapturedOutput output) {
        open();
        advance(WINDOW);

        assertThat(breaker.recordSuccess(breaker.allowCall())).isTrue();

        assertThat(output).contains("Test consumer: Redis answered again; breaker closed");
    }
```

- [ ] **Step 3: Update `RateLimitFilterTest`**

In `src/test/java/com/gatekeeper/ratelimit/RateLimitFilterTest.java`: change the import to `com.gatekeeper.redis.RedisCircuitBreaker.Permit` and add `import com.gatekeeper.redis.RedisCircuitBreaker;`. Change the two constructions:

```java
        RedisCircuitBreaker breaker = new RedisCircuitBreaker("Rate limiter", "forwarding requests unlimited",
                RedisCircuitBreaker.OPEN_FOR, 1, System::nanoTime);
```

```java
    private static RedisCircuitBreaker freshBreaker() {
        return new RedisCircuitBreaker("Rate limiter", "forwarding requests unlimited",
                RedisCircuitBreaker.OPEN_FOR, RedisCircuitBreaker.FAILURES_TO_OPEN, System::nanoTime);
    }
```

In `aLateAnswerDoesNotCloseTheBreaker`, change `for (int i = 0; i < 3; i++)` to `for (int i = 0; i < RedisCircuitBreaker.FAILURES_TO_OPEN; i++)`.

- [ ] **Step 4: Run to see the failure**

Run: `.\mvnw.cmd -o -q test "-Dtest=RedisCircuitBreakerTest,RateLimitFilterTest"`
Expected: COMPILATION ERROR — no constructor `RedisCircuitBreaker(String, String, Duration, int, LongSupplier)`.

- [ ] **Step 5: Rewrite the breaker**

Replace `src/main/java/com/gatekeeper/redis/RedisCircuitBreaker.java` with:

```java
package com.gatekeeper.redis;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.time.Duration;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.function.LongSupplier;

/**
 * Stops one consumer asking a Redis that is not answering. The M5 design, section 7; used by the
 * rate limiter and, since M6, by the revocation check (its section 7), one instance each.
 *
 * <p>After {@link #FAILURES_TO_OPEN} consecutive failures or timeouts the breaker opens: for
 * {@link #OPEN_FOR} its consumer does not call Redis at all. What the consumer does instead is its
 * own decision — the rate limiter forwards unlimited, the revocation check refuses — and the breaker
 * only reports it, in its log lines. Then exactly one call probes; its success closes the breaker,
 * its failure opens it for another window at once. This bounds what the consumer adds to Lettuce's
 * unbounded reconnect buffer to about one command per window, and turns an outage into one warning
 * when the breaker opens and one line when it closes, instead of a stack trace per request.
 *
 * <p><strong>Why three, not one.</strong> The timeout is measured in the gateway, so a single one may
 * be the gateway's own slowness — a GC pause, or CPU starved by a flood — rather than Redis's.
 * Opening on one would switch the consumer's Redis off for everyone under overload. So an isolated
 * failure affects only its own request, any success while closed resets the count, and it takes
 * three in a row to open. A hard outage still reaches three within the first few requests; a failed
 * probe needs no such count, because the evidence is already in.
 *
 * <p><strong>Only the probe closes it.</strong> Each call takes a {@link Permit} before it asks
 * Redis and reports its outcome with that permit. A request already in flight when the breaker
 * opened holds a {@link Permit#CLOSED} permit; its late success says nothing about Redis now, so
 * it does not close the breaker. Otherwise a Redis answering around the timeout would open and
 * close it hundreds of times a second.
 *
 * <p>The cost: once the breaker opens, its consumer stays without Redis for up to one window even if
 * Redis recovers sooner.
 */
public class RedisCircuitBreaker {

    public static final Duration OPEN_FOR = Duration.ofSeconds(5);
    /** Consecutive failures, while closed, that open the breaker. */
    public static final int FAILURES_TO_OPEN = 3;

    private static final Logger log = LoggerFactory.getLogger(RedisCircuitBreaker.class);

    /** What a caller may do, decided once per call, and reported back with its outcome. */
    public enum Permit {
        /** The breaker was closed: call Redis. */
        CLOSED,
        /** The breaker was open and its window had passed: call Redis as the one probe. */
        PROBE,
        /** The breaker is open: do not call Redis. */
        DENIED
    }

    private final String name;
    private final String whileOpen;
    private final Duration openFor;
    private final long openForNanos;
    private final int failuresToOpen;
    private final LongSupplier nanoTime;
    private final AtomicBoolean open = new AtomicBoolean();
    private final AtomicLong openUntil = new AtomicLong();
    private final AtomicInteger consecutiveFailures = new AtomicInteger();

    /**
     * @param name      the consumer, as its log lines name it: "Rate limiter", "Revocation check"
     * @param whileOpen what the consumer does while the breaker is open, as the opening warning says
     *                  it: "forwarding requests unlimited"
     */
    public RedisCircuitBreaker(String name, String whileOpen, Duration openFor, int failuresToOpen,
                               LongSupplier nanoTime) {
        this.name = name;
        this.whileOpen = whileOpen;
        this.openFor = openFor;
        this.openForNanos = openFor.toNanos();
        this.failuresToOpen = failuresToOpen;
        this.nanoTime = nanoTime;
    }

    /**
     * {@link Permit#CLOSED} while closed. While open, {@link Permit#DENIED} until the window has
     * passed; then {@link Permit#PROBE} for exactly one caller — the one that claims the next window
     * — and {@link Permit#DENIED} for the rest.
     */
    public Permit allowCall() {
        if (!open.get()) {
            return Permit.CLOSED;
        }
        long until = openUntil.get();
        long now = nanoTime.getAsLong();
        if (now - until < 0) {
            return Permit.DENIED;
        }
        return openUntil.compareAndSet(until, now + openForNanos) ? Permit.PROBE : Permit.DENIED;
    }

    /**
     * While closed, resets the count of consecutive failures. While open, closes the breaker, but
     * only for the probe's success; a late success from before the opening does nothing. True only
     * when this call closed it.
     */
    public boolean recordSuccess(Permit permit) {
        if (permit == Permit.PROBE) {
            // Reset again before closing, in case a failure was counted just as the breaker opened:
            // the first failure after the closing counts from zero, and none after it is lost.
            consecutiveFailures.set(0);
            if (open.compareAndSet(true, false)) {
                log.info("{}: Redis answered again; breaker closed", name);
                return true;
            }
        } else if (permit == Permit.CLOSED && !open.get()) {
            consecutiveFailures.set(0);
        }
        return false;
    }

    /**
     * While closed, counts the failure, and opens the breaker for a window from now when it is the
     * {@link #FAILURES_TO_OPEN}th in a row, warning with the cause. While open — a failed probe, or
     * a late failure from before the opening — re-opens it for a window from now, at once. True only
     * when this call opened it.
     */
    public boolean recordFailure(Permit permit, Throwable error) {
        if (permit == Permit.CLOSED && !open.get()) {
            int failures = consecutiveFailures.incrementAndGet();
            if (failures < failuresToOpen) {
                log.debug("{}: Redis failed, {} of {} consecutive failures: {}",
                        name, failures, failuresToOpen, error.toString());
                return false;
            }
        }
        openUntil.set(nanoTime.getAsLong() + openForNanos);
        if (open.compareAndSet(false, true)) {
            // The count describes only the stretch while closed.
            consecutiveFailures.set(0);
            log.warn("{}: Redis failed {} times in a row; {} for {} s at a time until it answers",
                    name, failuresToOpen, whileOpen, openFor.toSeconds(), error);
            return true;
        }
        log.debug("{}: Redis still failing ({} call): {}", name, permit, error.toString());
        return false;
    }
}
```

- [ ] **Step 6: Name the limiter's breaker bean and inject it by qualifier**

In `RateLimitConfig.java`, replace the `redisCircuitBreaker` bean with:

```java
    /** The limiter's own breaker; the revocation check has another. Injected by this name. */
    @Bean
    public RedisCircuitBreaker rateLimitBreaker() {
        return new RedisCircuitBreaker("Rate limiter", "forwarding requests unlimited",
                RedisCircuitBreaker.OPEN_FOR, RedisCircuitBreaker.FAILURES_TO_OPEN, System::nanoTime);
    }
```

and add `import com.gatekeeper.redis.RedisCircuitBreaker;`.

In `RateLimitFilter.java`: change the import `com.gatekeeper.ratelimit.RedisCircuitBreaker.Permit` to `com.gatekeeper.redis.RedisCircuitBreaker.Permit`; add `import com.gatekeeper.redis.RedisCircuitBreaker;` and `import org.springframework.beans.factory.annotation.Qualifier;`; and change the constructor's last parameter to `@Qualifier("rateLimitBreaker") RedisCircuitBreaker breaker`.

- [ ] **Step 7: Run the tests, then the suite**

Run: `.\mvnw.cmd -o -q test "-Dtest=RedisCircuitBreakerTest,RateLimitFilterTest"`
Expected: pass. Then prove the two log tests can fail: temporarily change `"{}: Redis failed {} times"` to `"Redis failed {} times"` (dropping `name`), rerun, see `itsOpeningNamesItsConsumerAndWhatHappensWhileOpen` fail, and restore it.

Run: `.\mvnw.cmd -o test`
Expected: `Tests run: 244, Failures: 0, Errors: 0` (242 + 2).

- [ ] **Step 8: Check nothing still refers to the old package**

Run: `git grep -n "ratelimit.RedisCircuitBreaker\|redisCircuitBreaker"`
Expected: no output in `src/`. List any hits in docs in your report; Task 10 handles them.

- [ ] **Step 9: Commit**

```
refactor(M6): move the breaker to com.gatekeeper.redis and name it

Each consumer will have its own breaker: the log lines now say whose
Redis failed and what that consumer does while the breaker is open. The
limiter's bean is rateLimitBreaker, injected by qualifier, so a second
breaker cannot make injection ambiguous.
```

---

### Task 3: The revocation store

**Files:**
- Create: `src/main/java/com/gatekeeper/revocation/RevocationStore.java`
- Create: `src/main/java/com/gatekeeper/revocation/RedisRevocationStore.java`
- Test: `src/test/java/com/gatekeeper/revocation/RedisRevocationStoreTest.java`

- [ ] **Step 1: Branch**

`git checkout master; git checkout -b feature/m6-task-3`

- [ ] **Step 2: Write the failing test**

`src/test/java/com/gatekeeper/revocation/RedisRevocationStoreTest.java`:

```java
package com.gatekeeper.revocation;

import com.gatekeeper.redis.RedisConnectionStep;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

/**
 * The store against the real Redis, reading exactly the key AuthCore's {@code RevocationService}
 * writes. The M6 design, sections 2 and 9.
 *
 * <p>This Redis is shared with AuthCore and every other test: each test uses a fresh {@code jti} and
 * deletes its key afterwards.
 */
@SpringBootTest
class RedisRevocationStoreTest {

    @Autowired
    ReactiveStringRedisTemplate redis;

    @Autowired
    RedisConnectionStep connection;

    private final List<String> written = new ArrayList<>();

    @AfterEach
    void deleteKeys() {
        written.forEach(key -> redis.delete(key).block());
    }

    @Test
    void readsAuthCoresKey() {
        assertThat(RedisRevocationStore.key("abc")).isEqualTo("authcore:revoked:jti:abc");
    }

    @Test
    void aDenyListedJtiIsRevoked() {
        String jti = revoke(Duration.ofMinutes(1));

        assertThat(store().isRevoked(jti).block()).isTrue();
    }

    @Test
    void anUnknownJtiIsNotRevoked() {
        assertThat(store().isRevoked(UUID.randomUUID().toString()).block()).isFalse();
    }

    /** AuthCore's entries expire with the token: an expired entry is no longer a revocation. */
    @Test
    void anExpiredEntryIsNotRevoked() throws InterruptedException {
        String jti = revoke(Duration.ofMillis(100));
        Thread.sleep(300);

        assertThat(store().isRevoked(jti).block()).isFalse();
    }

    @Test
    void waitsOnTheConnectionStep() {
        RedisConnectionStep refused = new RedisConnectionStep(
                () -> Mono.error(new IllegalStateException("connection refused")));

        assertThatThrownBy(() -> new RedisRevocationStore(redis, refused).isRevoked("any").block())
                .hasMessageContaining("connection refused");
    }

    private RedisRevocationStore store() {
        return new RedisRevocationStore(redis, connection);
    }

    /** Writes the entry the way AuthCore's RevocationService does: value "revoked", with a TTL. */
    private String revoke(Duration ttl) {
        String jti = UUID.randomUUID().toString();
        String key = RedisRevocationStore.key(jti);
        written.add(key);
        redis.opsForValue().set(key, "revoked", ttl).block();
        return jti;
    }
}
```

- [ ] **Step 3: Run it to see it fail**

Run: `.\mvnw.cmd -o -q test "-Dtest=RedisRevocationStoreTest"`
Expected: COMPILATION ERROR — `RedisRevocationStore` does not exist.

- [ ] **Step 4: Write the interface and the store**

`src/main/java/com/gatekeeper/revocation/RevocationStore.java`:

```java
package com.gatekeeper.revocation;

import reactor.core.publisher.Mono;

/** Whether a token has been revoked, by its {@code jti}. The M6 design, section 9. */
public interface RevocationStore {

    /** True if revoked, false if not; an error or an empty answer means the store could not say. */
    Mono<Boolean> isRevoked(String jti);
}
```

`src/main/java/com/gatekeeper/revocation/RedisRevocationStore.java`:

```java
package com.gatekeeper.revocation;

import com.gatekeeper.redis.RedisConnectionStep;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import reactor.core.publisher.Mono;

/**
 * Reads AuthCore's deny-list. The contract is AuthCore's {@code RevocationService}: it writes
 * {@code authcore:revoked:jti:<jti>}, value {@code "revoked"}, with a TTL equal to the token's
 * remaining lifetime, so an entry disappears exactly when the token would have expired anyway. One
 * {@code EXISTS} answers the question; the value is never read. The M6 design, section 2.
 *
 * <p>Connects through the shared {@link RedisConnectionStep}, so a silent Redis cannot block an event
 * loop or leak a connection per timed-out request (the M5 design, section 7). The timeout and the
 * breaker are the caller's: {@code RevocationCheckingJwtDecoder}.
 */
public class RedisRevocationStore implements RevocationStore {

    private static final String KEY_PREFIX = "authcore:revoked:jti:";

    private final ReactiveStringRedisTemplate redis;
    private final RedisConnectionStep connection;

    public RedisRevocationStore(ReactiveStringRedisTemplate redis, RedisConnectionStep connection) {
        this.redis = redis;
        this.connection = connection;
    }

    static String key(String jti) {
        return KEY_PREFIX + jti;
    }

    @Override
    public Mono<Boolean> isRevoked(String jti) {
        return connection.ready().then(Mono.defer(() -> redis.hasKey(key(jti))));
    }
}
```

The Javadoc names `RevocationCheckingJwtDecoder` with `{@code}`, not `{@link}`: that class does not exist until Task 4.

- [ ] **Step 5: Run it to see it pass**

Run: `.\mvnw.cmd -o -q test "-Dtest=RedisRevocationStoreTest"`
Expected: 5 tests pass.

Then prove `aDenyListedJtiIsRevoked` can fail: temporarily change `KEY_PREFIX` to `"authcore:revoked:"`, rerun, see `readsAuthCoresKey` and `aDenyListedJtiIsRevoked` fail, restore.

Run: `.\mvnw.cmd -o test`
Expected: `Tests run: 249, Failures: 0, Errors: 0` (244 + 5).

- [ ] **Step 6: Commit**

```
feat(M6): read AuthCore's revocation deny-list

RedisRevocationStore answers whether a jti is revoked with one EXISTS on
authcore:revoked:jti:<jti>, the key AuthCore's RevocationService writes,
after the shared connection step.
```

---

### Task 4: The decoder that checks revocation

**Files:**
- Create: `src/main/java/com/gatekeeper/revocation/RevocationUnavailableException.java`
- Create: `src/main/java/com/gatekeeper/revocation/RevocationCheckingJwtDecoder.java`
- Test: `src/test/java/com/gatekeeper/revocation/RevocationCheckingJwtDecoderTest.java`

- [ ] **Step 1: Branch**

`git checkout master; git checkout -b feature/m6-task-4`

- [ ] **Step 2: Write the failing tests**

`src/test/java/com/gatekeeper/revocation/RevocationCheckingJwtDecoderTest.java`:

```java
package com.gatekeeper.revocation;

import com.gatekeeper.redis.RedisCircuitBreaker;
import com.gatekeeper.redis.RedisCircuitBreaker.Permit;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The check, with a fake inner decoder, a fake store and a breaker on a fake clock. The M6 design,
 * sections 3, 4, 6 and 7.
 */
class RevocationCheckingJwtDecoderTest {

    static final Duration TIMEOUT = Duration.ofMillis(100);
    static final IllegalStateException DOWN = new IllegalStateException("redis down");

    final AtomicInteger storeCalls = new AtomicInteger();
    final AtomicReference<String> askedAbout = new AtomicReference<>();
    final AtomicReference<Mono<Boolean>> answer = new AtomicReference<>(Mono.just(false));
    final AtomicLong now = new AtomicLong(1_000_000_000L);
    final RedisCircuitBreaker breaker = new RedisCircuitBreaker("Revocation check", "refusing",
            RedisCircuitBreaker.OPEN_FOR, RedisCircuitBreaker.FAILURES_TO_OPEN, now::get);

    final RevocationStore store = jti -> {
        storeCalls.incrementAndGet();
        askedAbout.set(jti);
        return answer.get();
    };

    @Test
    void passesATokenThatIsNotRevoked() {
        Jwt jwt = jwt("j-1");

        StepVerifier.create(decoder(jwt).decode("t")).expectNext(jwt).verifyComplete();

        assertThat(storeCalls).hasValue(1);
    }

    @Test
    void asksAboutTheTokensOwnJti() {
        decoder(jwt("j-42")).decode("t").block();

        assertThat(askedAbout).hasValue("j-42");
    }

    @Test
    void refusesARevokedTokenAsABadToken() {
        answer.set(Mono.just(true));

        StepVerifier.create(decoder(jwt("j-1")).decode("t"))
                .expectErrorSatisfies(error -> assertThat(error)
                        .isInstanceOf(BadJwtException.class)
                        .hasMessageContaining("revoked"))
                .verify();
    }

    /** A token that cannot be revoked does not pass a gateway that enforces revocation (section 6). */
    @Test
    void refusesATokenWithNoJtiWithoutAskingTheStore() {
        StepVerifier.create(decoder(jwt(null)).decode("t"))
                .expectError(BadJwtException.class)
                .verify();

        assertThat(storeCalls).hasValue(0);
    }

    /** Blank would check the key "authcore:revoked:jti:", which nobody writes. */
    @Test
    void refusesABlankJtiWithoutAskingTheStore() {
        StepVerifier.create(decoder(jwt(" ")).decode("t"))
                .expectError(BadJwtException.class)
                .verify();

        assertThat(storeCalls).hasValue(0);
    }

    /** Forged or expired tokens must not reach Redis: an outsider picks their jti freely (section 3). */
    @Test
    void aTokenTheInnerDecoderRejectsNeverReachesTheStore() {
        ReactiveJwtDecoder rejecting = token -> Mono.error(new BadJwtException("bad signature"));

        StepVerifier.create(decoder(rejecting).decode("t"))
                .expectErrorMessage("bad signature")
                .verify();

        assertThat(storeCalls).hasValue(0);
    }

    @Test
    void refusesWhenTheStoreFails() {
        answer.set(Mono.error(DOWN));

        StepVerifier.create(decoder(jwt("j-1")).decode("t"))
                .expectErrorSatisfies(error -> assertThat(error)
                        .isInstanceOf(RevocationUnavailableException.class)
                        .hasCause(DOWN))
                .verify();
    }

    @Test
    void refusesWhenTheStoreAnswersNothing() {
        answer.set(Mono.empty());

        StepVerifier.create(decoder(jwt("j-1")).decode("t"))
                .expectError(RevocationUnavailableException.class)
                .verify();
    }

    @Test
    void refusesWhenTheStoreDoesNotAnswerInTime() {
        answer.set(Mono.never());

        StepVerifier.create(decoder(jwt("j-1")).decode("t"))
                .expectErrorSatisfies(error -> assertThat(error)
                        .isInstanceOf(RevocationUnavailableException.class)
                        .hasCauseInstanceOf(TimeoutException.class))
                .verify(Duration.ofSeconds(2));
    }

    /**
     * The handoff's warning: copying the limiter's handling of an open breaker would skip the check,
     * failing open. Here an open breaker refuses, and does not ask Redis.
     */
    @Test
    void anOpenBreakerRefusesWithoutAskingTheStore() {
        answer.set(Mono.error(DOWN));
        RevocationCheckingJwtDecoder decoder = decoder(jwt("j-1"));
        for (int i = 0; i < RedisCircuitBreaker.FAILURES_TO_OPEN; i++) {
            StepVerifier.create(decoder.decode("t")).expectError(RevocationUnavailableException.class).verify();
        }
        assertThat(breaker.allowCall()).isEqualTo(Permit.DENIED);
        answer.set(Mono.just(false));

        StepVerifier.create(decoder.decode("t")).expectError(RevocationUnavailableException.class).verify();

        assertThat(storeCalls).hasValue(RedisCircuitBreaker.FAILURES_TO_OPEN);
    }

    /** A revoked token is Redis answering, not failing: it must not count towards opening. */
    @Test
    void aRevokedTokenIsNotARedisFailure() {
        RedisCircuitBreaker opensOnOne = new RedisCircuitBreaker("Revocation check", "refusing",
                RedisCircuitBreaker.OPEN_FOR, 1, now::get);
        answer.set(Mono.just(true));

        StepVerifier.create(new RevocationCheckingJwtDecoder(token -> Mono.just(jwt("j-1")), store, opensOnOne, TIMEOUT)
                        .decode("t"))
                .expectError(BadJwtException.class)
                .verify();

        assertThat(opensOnOne.allowCall()).isEqualTo(Permit.CLOSED);
    }

    @Test
    void theProbesSuccessClosesTheBreaker() {
        answer.set(Mono.error(DOWN));
        RevocationCheckingJwtDecoder decoder = decoder(jwt("j-1"));
        for (int i = 0; i < RedisCircuitBreaker.FAILURES_TO_OPEN; i++) {
            decoder.decode("t").onErrorResume(error -> Mono.empty()).block();
        }
        now.addAndGet(RedisCircuitBreaker.OPEN_FOR.toNanos());
        answer.set(Mono.just(false));

        StepVerifier.create(decoder.decode("t")).expectNextCount(1).verifyComplete();

        assertThat(breaker.allowCall()).isEqualTo(Permit.CLOSED);
    }

    /**
     * The permit is taken when the check runs, not when the decode is assembled: a decode assembled
     * while the breaker was closed, and run after it opened, is refused without asking Redis.
     */
    @Test
    void thePermitIsTakenWhenTheCheckRuns() {
        RevocationCheckingJwtDecoder decoder = decoder(jwt("j-1"));
        Mono<Jwt> assembledWhileClosed = decoder.decode("t");
        answer.set(Mono.error(DOWN));
        for (int i = 0; i < RedisCircuitBreaker.FAILURES_TO_OPEN; i++) {
            decoder.decode("t").onErrorResume(error -> Mono.empty()).block();
        }

        StepVerifier.create(assembledWhileClosed).expectError(RevocationUnavailableException.class).verify();

        assertThat(storeCalls).hasValue(RedisCircuitBreaker.FAILURES_TO_OPEN);
    }

    private RevocationCheckingJwtDecoder decoder(Jwt decoded) {
        return decoder(token -> Mono.just(decoded));
    }

    private RevocationCheckingJwtDecoder decoder(ReactiveJwtDecoder inner) {
        return new RevocationCheckingJwtDecoder(inner, store, breaker, TIMEOUT);
    }

    private static Jwt jwt(String jti) {
        Jwt.Builder builder = Jwt.withTokenValue("t")
                .header("alg", "RS256")
                .subject("ezzat")
                .issuer("http://localhost:8080");
        if (jti != null) {
            builder.jti(jti);
        }
        return builder.build();
    }
}
```

- [ ] **Step 3: Run to see it fail**

Run: `.\mvnw.cmd -o -q test "-Dtest=RevocationCheckingJwtDecoderTest"`
Expected: COMPILATION ERROR — `RevocationCheckingJwtDecoder` and `RevocationUnavailableException` do not exist.

- [ ] **Step 4: Write the exception**

`src/main/java/com/gatekeeper/revocation/RevocationUnavailableException.java`:

```java
package com.gatekeeper.revocation;

/**
 * Whether the token is revoked could not be established — Redis erroring, silent, answering
 * nothing, or its breaker open. Answered 503 with {@code Retry-After: 5}. The M6 design, section 4.
 *
 * <p>Deliberately neither a {@code JwtException} nor an {@code AuthenticationException}. {@code
 * JwtReactiveAuthenticationManager} maps only {@code JwtException}, and {@code
 * AuthenticationWebFilter} catches only {@code AuthenticationException} (both verified in the 7.0.6
 * bytecode), so this passes both untouched to {@code GlobalErrorWebExceptionHandler} — the route
 * M3's {@code IntrospectionUnavailableException} takes to its own 503. As either of those types it
 * would become a 401, telling the caller to discard a token that is very likely valid.
 */
public class RevocationUnavailableException extends RuntimeException {

    /** The fixed {@code detail} of the 503, so it can be told from M3's introspection 503. */
    public static final String DETAIL = "REVOCATION_UNAVAILABLE";

    public RevocationUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
```

- [ ] **Step 5: Write the decoder**

`src/main/java/com/gatekeeper/revocation/RevocationCheckingJwtDecoder.java`:

```java
package com.gatekeeper.revocation;

import com.gatekeeper.redis.RedisCircuitBreaker;
import com.gatekeeper.redis.RedisCircuitBreaker.Permit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtException;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.util.StringUtils;
import reactor.core.publisher.Mono;

import java.time.Duration;

/**
 * Refuses a revoked token, however valid its signature. The M6 design, sections 3 to 8.
 *
 * <p><strong>After every other check.</strong> The inner decoder verifies the signature against the
 * JWKS and validates {@code exp}, {@code nbf} and the pinned {@code iss} first. Only a token that
 * passes all of it reaches Redis, so a forged or expired token — whose {@code jti} an outsider picks
 * freely — cannot generate Redis load.
 *
 * <p><strong>A revoked token is an invalid token:</strong> a {@link BadJwtException}, which
 * Spring Security answers with the same 401 as an expired or forged one. So is a token with no
 * {@code jti}, or a blank one: it could never be revoked, so it does not pass a gateway that enforces
 * revocation (section 6).
 *
 * <p><strong>Fails closed, fast.</strong> A Redis error, a timeout, an empty answer, or an open
 * breaker is a {@link RevocationUnavailableException}: 503, never an admitted request. An open
 * breaker means <em>refuse</em> — the rate limiter's breaker means "skip Redis and forward", and
 * copying that here would fail open. Only the store call is mapped to a failure: a revoked token is
 * Redis answering, and must not count towards opening the breaker.
 */
public class RevocationCheckingJwtDecoder implements ReactiveJwtDecoder {

    private static final Logger log = LoggerFactory.getLogger(RevocationCheckingJwtDecoder.class);

    private final ReactiveJwtDecoder delegate;
    private final RevocationStore store;
    private final RedisCircuitBreaker breaker;
    private final Duration timeout;

    public RevocationCheckingJwtDecoder(ReactiveJwtDecoder delegate, RevocationStore store,
                                        RedisCircuitBreaker breaker, Duration timeout) {
        this.delegate = delegate;
        this.store = store;
        this.breaker = breaker;
        this.timeout = timeout;
    }

    @Override
    public Mono<Jwt> decode(String token) throws JwtException {
        return delegate.decode(token).flatMap(this::check);
    }

    private Mono<Jwt> check(Jwt jwt) {
        String jti = jwt.getId();
        if (!StringUtils.hasText(jti)) {
            // Only the issuer can sign a token without one, so this is an issuer bug, and an
            // outsider cannot flood this line.
            log.warn("Refused a validly signed token with no jti, which could never be revoked: sub={}, iss={}",
                    jwt.getSubject(), jwt.getIssuer());
            return Mono.error(new BadJwtException("The token has no jti, so it cannot be revoked"));
        }
        return Mono.defer(() -> isRevoked(jti))
                .flatMap(revoked -> {
                    if (revoked) {
                        // DEBUG: a holder can replay a revoked token as fast as they like, and the
                        // limiter never sees it. Counting these is M8's audit event.
                        log.debug("Refused revoked token {}", jti);
                        return Mono.error(new BadJwtException("The token has been revoked"));
                    }
                    return Mono.just(jwt);
                });
    }

    /** The store call alone, behind the breaker and the timeout; its failures, and only its, map to 503. */
    private Mono<Boolean> isRevoked(String jti) {
        // Taken when the check runs, not when the decode was assembled (section 7).
        Permit permit = breaker.allowCall();
        if (permit == Permit.DENIED) {
            log.debug("Revocation check's breaker is open; refusing token {}", jti);
            return Mono.error(new RevocationUnavailableException("the revocation check's breaker is open", null));
        }
        return store.isRevoked(jti)
                .timeout(timeout)
                .switchIfEmpty(Mono.error(() -> new IllegalStateException("the revocation store answered nothing")))
                // The permit taken before the call, not the breaker's state now: only a probe's
                // success may close it.
                .doOnNext(answer -> breaker.recordSuccess(permit))
                .onErrorMap(error -> {
                    breaker.recordFailure(permit, error);
                    log.debug("Revocation check could not be completed for token {}: {}", jti, error.toString());
                    return new RevocationUnavailableException("the revocation check could not be completed", error);
                });
    }
}
```

- [ ] **Step 6: Run to see the tests pass**

Run: `.\mvnw.cmd -o -q test "-Dtest=RevocationCheckingJwtDecoderTest"`
Expected: 13 tests pass.

- [ ] **Step 7: Prove the key tests can fail**

One at a time, in the working copy, rerun the test class after each and restore it afterwards:

| Change | Must fail |
|---|---|
| `if (permit == Permit.DENIED)` returns `Mono.just(false)` instead of the error | `anOpenBreakerRefusesWithoutAskingTheStore` |
| Delete the `if (!StringUtils.hasText(jti))` block | `refusesATokenWithNoJtiWithoutAskingTheStore`, `refusesABlankJtiWithoutAskingTheStore` |
| Move `.onErrorMap(...)` to after `.flatMap(revoked -> ...)` in `check` (so it also maps the `BadJwtException`) | `refusesARevokedTokenAsABadToken`, `aRevokedTokenIsNotARedisFailure` |
| Replace `Mono.defer(() -> isRevoked(jti))` with `isRevoked(jti)` computed eagerly in `decode` before `delegate.decode(token)` — e.g. `Mono<Boolean> early = isRevoked("j-1"); return delegate.decode(token).flatMap(jwt -> early.map(...))` | `thePermitIsTakenWhenTheCheckRuns` |

Record each result in your report.

Then run: `.\mvnw.cmd -o test`
Expected: `Tests run: 262, Failures: 0, Errors: 0` (249 + 13).

- [ ] **Step 8: Commit**

```
feat(M6): refuse a revoked token inside JWT decoding

RevocationCheckingJwtDecoder wraps the Nimbus decoder: after signature
and claims pass, a missing, blank or deny-listed jti is a BadJwtException
(the ordinary 401). A Redis error, timeout, empty answer or open breaker
is a RevocationUnavailableException, bound for 503; an open breaker
refuses rather than skipping the check.
```

---

### Task 5: `gatekeeper.revocation.redis-timeout`

**Files:**
- Create: `src/main/java/com/gatekeeper/revocation/RevocationProperties.java`
- Modify: `src/main/resources/application.yml`
- Test: `src/test/java/com/gatekeeper/revocation/RevocationPropertiesTest.java`

- [ ] **Step 1: Branch**

`git checkout master; git checkout -b feature/m6-task-5`

- [ ] **Step 2: Write the failing test**

`src/test/java/com/gatekeeper/revocation/RevocationPropertiesTest.java`:

```java
package com.gatekeeper.revocation;

import org.junit.jupiter.api.Test;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.test.context.runner.ApplicationContextRunner;
import org.springframework.context.annotation.Configuration;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/** Bound strictly and validated at startup, as the limiter's are. The M6 design, section 10. */
class RevocationPropertiesTest {

    private final ApplicationContextRunner runner = new ApplicationContextRunner()
            .withUserConfiguration(TestConfig.class);

    @Test
    void bindsTheTimeout() {
        runner.withPropertyValues("gatekeeper.revocation.redis-timeout=200ms")
                .run(context -> {
                    assertThat(context).hasNotFailed();
                    assertThat(context.getBean(RevocationProperties.class).redisTimeout())
                            .isEqualTo(Duration.ofMillis(200));
                });
    }

    @Test
    void refusesAMissingTimeout() {
        runner.run(context -> assertThat(messageChain(context.getStartupFailure()))
                .contains("gatekeeper.revocation.redis-timeout must be a positive duration"));
    }

    @Test
    void refusesAZeroTimeout() {
        runner.withPropertyValues("gatekeeper.revocation.redis-timeout=0ms")
                .run(context -> assertThat(messageChain(context.getStartupFailure()))
                        .contains("gatekeeper.revocation.redis-timeout must be a positive duration"));
    }

    @Test
    void refusesANegativeTimeout() {
        runner.withPropertyValues("gatekeeper.revocation.redis-timeout=-1s")
                .run(context -> assertThat(messageChain(context.getStartupFailure()))
                        .contains("gatekeeper.revocation.redis-timeout must be a positive duration"));
    }

    /** A typo must fail the boot, not silently leave the real key unset. */
    @Test
    void refusesAnUnknownKey() {
        runner.withPropertyValues(
                        "gatekeeper.revocation.redis-timeout=200ms",
                        "gatekeeper.revocation.redis-timout=5s")
                .run(context -> assertThat(messageChain(context.getStartupFailure()))
                        .contains("redis-timout"));
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
    @EnableConfigurationProperties(RevocationProperties.class)
    static class TestConfig {
    }
}
```

- [ ] **Step 3: Run to see it fail**

Run: `.\mvnw.cmd -o -q test "-Dtest=RevocationPropertiesTest"`
Expected: COMPILATION ERROR — `RevocationProperties` does not exist.

- [ ] **Step 4: Write the properties and the configuration**

`src/main/java/com/gatekeeper/revocation/RevocationProperties.java`:

```java
package com.gatekeeper.revocation;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

/**
 * {@code gatekeeper.revocation}. The M6 design, section 10.
 *
 * <p>Strictly bound: an unknown key under the prefix fails the boot rather than silently leaving the
 * real one unset. There is no default in code, as for the rate limiter: {@code application.yml}
 * supplies it, and a missing value fails the boot.
 *
 * @param redisTimeout how long the revocation check waits for Redis before refusing with 503
 */
@ConfigurationProperties(prefix = "gatekeeper.revocation", ignoreUnknownFields = false)
public record RevocationProperties(Duration redisTimeout) {

    public RevocationProperties {
        if (redisTimeout == null || redisTimeout.isZero() || redisTimeout.isNegative()) {
            throw new IllegalArgumentException("gatekeeper.revocation.redis-timeout must be a positive duration");
        }
    }
}
```

In `src/main/resources/application.yml`, insert after the `rate-limit:` block's last line (`demo-reporting-job: free`) and before the blank line preceding `management:`:

```yaml
  revocation:
    # How long the revocation check waits for Redis. A revoked token getting through is a security
    # failure, so an unanswered check refuses (503 with Retry-After) rather than admitting — the
    # opposite of rate-limit.redis-timeout above — and it must refuse fast, not hang. See the M6
    # design, sections 4 and 7.
    redis-timeout: 200ms
```

(Indented two spaces, as a sibling of `rate-limit:` under `gatekeeper:`.)

- [ ] **Step 5: Run the test and the suite**

Run: `.\mvnw.cmd -o -q test "-Dtest=RevocationPropertiesTest"`
Expected: 5 pass. (If `refusesAMissingTimeout` fails because Boot does not construct the record when no property is present, check with `javap` how `ConfigurationPropertiesBean` binds value objects in Boot 4.0.7, and report it rather than weakening the test: the design requires a missing value to fail the boot.)

Run: `.\mvnw.cmd -o test`
Expected: `Tests run: 267, Failures: 0, Errors: 0` (262 + 5): `@ConfigurationPropertiesScan` now binds the class in every context, and `application.yml` supplies the value.

- [ ] **Step 6: Commit**

```
feat(M6): configure how long the revocation check waits for Redis

gatekeeper.revocation.redis-timeout, 200 ms, strictly bound and
validated at startup like the rate limiter's.
```

---

### Task 6: Wire the check in, answer 503, and test it end to end

After this task every bearer token is checked. The two M5 fail-open tests would then see 503s, correctly; they keep testing the limiter by replacing the revocation store with one that always answers "not revoked".

**Files:**
- Create: `src/main/java/com/gatekeeper/revocation/RevocationConfig.java`
- Modify: `src/main/java/com/gatekeeper/config/JwtDecoderConfig.java`
- Modify: `src/main/java/com/gatekeeper/error/GlobalErrorWebExceptionHandler.java`
- Modify: `src/main/java/com/gatekeeper/error/ErrorBody.java` (Javadoc only)
- Modify: `src/main/java/com/gatekeeper/redis/RedisWarmUp.java` (warning text)
- Modify: `src/test/java/com/gatekeeper/support/TestKey.java`
- Modify: `src/test/java/com/gatekeeper/ratelimit/DeadRedisFailOpenTest.java`
- Modify: `src/test/java/com/gatekeeper/ratelimit/SilentRedisFailOpenTest.java`
- Test: `src/test/java/com/gatekeeper/revocation/RevocationTest.java`

- [ ] **Step 1: Branch**

`git checkout master; git checkout -b feature/m6-task-6`

- [ ] **Step 2: Let tests choose a token's `jti`**

In `src/test/java/com/gatekeeper/support/TestKey.java`, add `import java.text.ParseException;`, and replace `mintAdvertisingKeyId` with the three methods below (`mint` is unchanged and still calls `mintAdvertisingKeyId`):

```java
    /**
     * Signs with this key but writes a different {@code kid} into the header. Task 10 needs
     * this to separate a bad signature over a known key from an entirely unknown key id —
     * they fail on different code paths.
     */
    public String mintAdvertisingKeyId(String keyId, String issuer, String subject,
                                       Instant expiresAt, Map<String, Object> claims) {
        return sign(keyId, UUID.randomUUID().toString(), issuer, subject, expiresAt, claims);
    }

    /** A token whose {@code jti} the test chooses; {@code null} leaves the claim out altogether. */
    public String mintWithJwtId(String jwtId, String issuer, String subject,
                                Instant expiresAt, Map<String, Object> claims) {
        return sign(this.key.getKeyID(), jwtId, issuer, subject, expiresAt, claims);
    }

    /** The {@code jti} of a token this class minted, read without verifying it. */
    public static String jwtIdOf(String token) {
        try {
            return SignedJWT.parse(token).getJWTClaimsSet().getJWTID();
        } catch (ParseException ex) {
            throw new IllegalArgumentException("not a signed JWT", ex);
        }
    }

    private String sign(String keyId, String jwtId, String issuer, String subject,
                        Instant expiresAt, Map<String, Object> claims) {
        try {
            JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                    .issuer(issuer)
                    .subject(subject)
                    .issueTime(Date.from(Instant.now().minusSeconds(30)))
                    .expirationTime(Date.from(expiresAt));
            if (jwtId != null) {
                builder.jwtID(jwtId);
            }
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
```

- [ ] **Step 3: Write the failing integration test**

`src/test/java/com/gatekeeper/revocation/RevocationTest.java`:

```java
package com.gatekeeper.revocation;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.gatekeeper.support.TestKey;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * A revoked token, end to end, against the real Redis: refused with the ordinary 401 before
 * authorization, rate limiting or routing. The M6 design, sections 3, 6, 8 and 11.
 *
 * <p>The real store is wrapped in one that counts its calls, so "never asked" is an assertion,
 * not an assumption: an API-key caller and a token the inner decoder rejects must not reach it.
 *
 * <p>Every test uses a fresh tenant and a fresh {@code jti}, and deletes the deny-list entries it
 * writes: this Redis is shared with AuthCore and every other test.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class RevocationTest {

    static final String ISSUER = "http://localhost:8080";
    static final String INTROSPECT_PATH = "/api/internal/api-keys/introspect";
    static final AtomicInteger storeCalls = new AtomicInteger();

    static WireMockServer downstream;
    static TestKey signingKey;

    @Autowired
    WebTestClient client;

    @Autowired
    ReactiveStringRedisTemplate redis;

    private final List<String> written = new ArrayList<>();

    @TestConfiguration
    static class CountingStore {

        @Bean
        @Primary
        RevocationStore countingRevocationStore(@Qualifier("revocationStore") RevocationStore real) {
            return jti -> {
                storeCalls.incrementAndGet();
                return real.isRevoked(jti);
            };
        }
    }

    @BeforeAll
    static void start() {
        signingKey = TestKey.generate("k1");
        downstream = new WireMockServer(options().dynamicPort());
        downstream.start();
        downstream.stubFor(get(urlEqualTo("/oauth2/jwks")).willReturn(okJson(TestKey.jwksDocument(signingKey))));
        downstream.stubFor(get(urlEqualTo("/ledger/entries")).willReturn(okJson("[]")));
        downstream.stubFor(get(urlEqualTo("/api/machine/payments")).willReturn(aResponse().withStatus(200).withBody("[]")));
        downstream.stubFor(post(urlEqualTo(INTROSPECT_PATH)).atPriority(10).willReturn(okJson("""
                {"active":false}""")));
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
        registry.add("gatekeeper.api-key.introspection-uri", () -> downstream.baseUrl() + INTROSPECT_PATH);
    }

    @BeforeEach
    void reset() {
        storeCalls.set(0);
        downstream.resetRequests();
    }

    @AfterEach
    void deleteKeys() {
        written.forEach(key -> redis.delete(key).block());
    }

    @Test
    void refusesARevokedTokenWithTheOrdinary401() {
        String tenant = freshTenant();
        String token = userToken(tenant);
        revoke(token);

        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().valueEquals(HttpHeaders.WWW_AUTHENTICATE, "Bearer")
                .expectBody()
                .jsonPath("$.error").isEqualTo("unauthorized")
                .jsonPath("$.status").isEqualTo(401)
                .jsonPath("$.path").isEqualTo("/api/ledger/entries")
                .jsonPath("$.detail").doesNotExist();

        assertThat(storeCalls).hasValue(1);
        downstream.verify(0, getRequestedFor(urlEqualTo("/ledger/entries")));
        // Refused before the limiter: nothing was counted against the tenant.
        assertThat(redis.keys("gatekeeper:*" + tenant + "*").collectList().block()).isEmpty();
    }

    @Test
    void servesATokenThatIsNotRevoked() {
        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + userToken(freshTenant()))
                .exchange()
                .expectStatus().isOk();

        assertThat(storeCalls).hasValue(1);
    }

    @Test
    void refusesATokenWithNoJti() {
        String token = signingKey.mintWithJwtId(null, ISSUER, "ezzat", Instant.now().plus(5, ChronoUnit.MINUTES),
                Map.of("tenant", freshTenant(), "scope", List.of("payments:read")));

        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().valueEquals(HttpHeaders.WWW_AUTHENTICATE, "Bearer");

        assertThat(storeCalls).hasValue(0);
    }

    @Test
    void refusesATokenWithABlankJti() {
        String token = signingKey.mintWithJwtId("", ISSUER, "ezzat", Instant.now().plus(5, ChronoUnit.MINUTES),
                Map.of("tenant", freshTenant(), "scope", List.of("payments:read")));

        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isUnauthorized();

        assertThat(storeCalls).hasValue(0);
    }

    /** An expired token fails in the inner decoder and never reaches Redis (section 3). */
    @Test
    void anExpiredTokenNeverReachesTheStore() {
        String token = signingKey.mint(ISSUER, "ezzat", Instant.now().minus(5, ChronoUnit.MINUTES),
                Map.of("tenant", freshTenant(), "scope", List.of("payments:read")));

        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isUnauthorized();

        assertThat(storeCalls).hasValue(0);
    }

    /** API keys are not deny-listed; they revoke through AuthCore's enabled flag (section 12). */
    @Test
    void anApiKeyCallerIsNotChecked() {
        String rawKey = "ak_test_" + UUID.randomUUID();
        downstream.stubFor(post(urlEqualTo(INTROSPECT_PATH))
                .atPriority(1)
                .withRequestBody(equalToJson("{\"key\":\"" + rawKey + "\"}"))
                .willReturn(okJson("""
                        {"active":true,"name":"reporting","scopes":["payments:read"],"expiresAt":"%s"}"""
                        .formatted(Instant.now().plus(1, ChronoUnit.HOURS)))));

        client.get().uri("/api/machine/payments")
                .header("X-API-Key", rawKey)
                .exchange()
                .expectStatus().isOk();

        assertThat(storeCalls).hasValue(0);
    }

    private void revoke(String token) {
        String key = "authcore:revoked:jti:" + TestKey.jwtIdOf(token);
        written.add(key);
        redis.opsForValue().set(key, "revoked", Duration.ofMinutes(5)).block();
    }

    private static String freshTenant() {
        return "rv-" + UUID.randomUUID();
    }

    private static String userToken(String tenant) {
        return signingKey.mint(ISSUER, "ezzat", Instant.now().plus(5, ChronoUnit.MINUTES),
                Map.of("tenant", tenant, "scope", List.of("payments:read")));
    }
}
```

The literal key in `revoke(...)` is deliberate: this test pins AuthCore's contract independently of `RedisRevocationStore.key`.

- [ ] **Step 4: Run to see it fail**

Run: `.\mvnw.cmd -o -q test "-Dtest=RevocationTest"`
Expected: the context fails to start — no bean named `revocationStore` for the `@Qualifier`. That is the missing wiring.

- [ ] **Step 5: Add `RevocationConfig`**

`src/main/java/com/gatekeeper/revocation/RevocationConfig.java`:

```java
package com.gatekeeper.revocation;

import com.gatekeeper.redis.RedisCircuitBreaker;
import com.gatekeeper.redis.RedisConnectionStep;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;

@Configuration
public class RevocationConfig {

    @Bean
    public RevocationStore revocationStore(ReactiveStringRedisTemplate redis, RedisConnectionStep connection) {
        return new RedisRevocationStore(redis, connection);
    }

    /**
     * The revocation check's own breaker; the limiter has another (the M6 design, section 7). Open,
     * it refuses. Injected by this name.
     */
    @Bean
    public RedisCircuitBreaker revocationBreaker() {
        return new RedisCircuitBreaker("Revocation check", "refusing bearer-token requests with 503",
                RedisCircuitBreaker.OPEN_FOR, RedisCircuitBreaker.FAILURES_TO_OPEN, System::nanoTime);
    }
}
```

- [ ] **Step 6: Return the wrapping decoder**

Replace the bean method in `src/main/java/com/gatekeeper/config/JwtDecoderConfig.java`:

```java
    @Bean
    public ReactiveJwtDecoder jwtDecoder(
            @Value("${gatekeeper.auth.jwk-set-uri}") String jwkSetUri,
            @Value("${gatekeeper.auth.issuer}") String issuer,
            RevocationStore revocations,
            @Qualifier("revocationBreaker") RedisCircuitBreaker revocationBreaker,
            RevocationProperties revocation) {

        NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder.withJwkSetUri(jwkSetUri).build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuer));
        return new RevocationCheckingJwtDecoder(decoder, revocations, revocationBreaker, revocation.redisTimeout());
    }
```

Add imports `com.gatekeeper.redis.RedisCircuitBreaker`, `com.gatekeeper.revocation.RevocationCheckingJwtDecoder`, `com.gatekeeper.revocation.RevocationProperties`, `com.gatekeeper.revocation.RevocationStore`, `org.springframework.beans.factory.annotation.Qualifier`. Append to the class Javadoc:

```java
 *
 * <p>Since M6 the Nimbus decoder is wrapped: a token that passes it is then checked against
 * AuthCore's revocation deny-list — see {@link RevocationCheckingJwtDecoder} and the M6 design.
```

- [ ] **Step 7: Answer `RevocationUnavailableException` with 503 and its `detail`**

In `src/main/java/com/gatekeeper/error/GlobalErrorWebExceptionHandler.java`:

1. Add `import com.gatekeeper.revocation.RevocationUnavailableException;`.
2. In `render(...)`, replace the last line `return builder.bodyValue(ErrorBody.of(status, request.path()));` with:

```java
        // Only the revocation 503 carries a detail, so it can be told from M3's introspection 503.
        String detail = error instanceof RevocationUnavailableException ? RevocationUnavailableException.DETAIL : null;
        return builder.bodyValue(ErrorBody.of(status, request.path(), detail));
```

3. In `statusFor(...)`, change `if (error instanceof IntrospectionUnavailableException) {` to:

```java
        if (error instanceof IntrospectionUnavailableException || error instanceof RevocationUnavailableException) {
```

4. Append to `statusFor`'s Javadoc, after the paragraph about `IntrospectionUnavailableException`:

```java
     *
     * <p>{@link RevocationUnavailableException} gets the same bare type match and the same 503, for
     * the same reasons: declared here, thrown from one place ({@code RevocationCheckingJwtDecoder})
     * for one reason — whether the token is revoked could not be established. A 401 would send a
     * caller holding a very likely valid token to refresh it, against an AuthCore that is itself
     * stuck while Redis is down (the M6 design, section 4).
```

In `src/main/java/com/gatekeeper/error/ErrorBody.java`, change the Javadoc sentence `{@code detail} is present only when a caller supplies one — today the 403 and the 429 do.` to `{@code detail} is present only when a caller supplies one — today the 403, the 429 and the revocation 503 do.`

- [ ] **Step 8: Keep the M5 fail-open tests about the limiter**

In both `src/test/java/com/gatekeeper/ratelimit/DeadRedisFailOpenTest.java` and `SilentRedisFailOpenTest.java`, add the imports:

```java
import com.gatekeeper.revocation.RevocationStore;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import reactor.core.publisher.Mono;
```

add inside each class, after the static fields:

```java
    /**
     * This class tests the limiter's fail-open. Since M6 an unreachable Redis also makes the
     * revocation check refuse every bearer token with 503 — correctly, and tested in the
     * {@code revocation} package — so the check is told "not revoked" here, leaving the limiter
     * the only consumer of the dead Redis.
     */
    @TestConfiguration
    static class NothingIsRevoked {

        @Bean
        @Primary
        RevocationStore nothingIsRevoked() {
            return jti -> Mono.just(false);
        }
    }
```

and append to each class Javadoc: `The revocation check is stubbed out; see {@link NothingIsRevoked}.`

- [ ] **Step 9: Say both consequences in the warm-up's warning**

In `src/main/java/com/gatekeeper/redis/RedisWarmUp.java`, change the warning to:

```java
                    log.warn("Redis did not answer the startup warm-up; until it does, the rate limiter fails open"
                            + " and the revocation check refuses bearer tokens with 503", error);
```

and append to the class Javadoc's last paragraph: `Until it answers, the rate limiter fails open and the revocation check refuses (the M6 design, section 8).`

- [ ] **Step 10: Run the new test, then the suite**

Run: `.\mvnw.cmd -o -q test "-Dtest=RevocationTest"`
Expected: 6 pass.

Run: `.\mvnw.cmd -o test`
Expected: `Tests run: 273, Failures: 0, Errors: 0` (267 + 6), with `DeadRedisFailOpenTest` and `SilentRedisFailOpenTest` still green.

Then prove the stub is what keeps the fail-open tests green: temporarily delete the `NothingIsRevoked` class from `DeadRedisFailOpenTest`, run it alone, see it fail with 503, and restore it.

- [ ] **Step 11: Commit**

```
feat(M6): check every bearer token against AuthCore's deny-list

JwtDecoderConfig now returns the revocation-checking decoder, with its
own breaker. A revoked or jti-less token is the ordinary 401; an
unanswerable check is 503 with Retry-After: 5 and the detail
REVOCATION_UNAVAILABLE. The M5 fail-open tests stub the check so they
keep testing only the limiter.
```

---

### Task 7: Fail closed, fast — dead and silent Redis

**Files:**
- Test: `src/test/java/com/gatekeeper/revocation/DeadRedisFailClosedTest.java`
- Test: `src/test/java/com/gatekeeper/revocation/SilentRedisFailClosedTest.java`

These test behaviour Task 6 already built, so they should pass when written. Make each fail first with the mutation in Step 4.

- [ ] **Step 1: Branch**

`git checkout master; git checkout -b feature/m6-task-7`

- [ ] **Step 2: Write `DeadRedisFailClosedTest`**

`src/test/java/com/gatekeeper/revocation/DeadRedisFailClosedTest.java`:

```java
package com.gatekeeper.revocation;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.gatekeeper.redis.RedisCircuitBreaker;
import com.gatekeeper.redis.RedisCircuitBreaker.Permit;
import com.gatekeeper.support.TestKey;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.io.IOException;
import java.net.ServerSocket;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Nothing listens on the Redis port. A bearer token cannot be checked, so it is refused — 503,
 * promptly — and never forwarded, including once the breaker is open. The M6 design, sections 4, 7
 * and 8.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class DeadRedisFailClosedTest {

    static final String ISSUER = "http://localhost:8080";
    static WireMockServer downstream;
    static TestKey signingKey;
    static int deadPort;

    @Autowired
    WebTestClient client;

    @Autowired
    @Qualifier("revocationBreaker")
    RedisCircuitBreaker breaker;

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
    void refusesEveryBearerTokenWith503Promptly() {
        String token = userToken();

        for (int i = 0; i < 5; i++) {
            long started = System.nanoTime();

            client.get().uri("/api/ledger/entries")
                    .header(HttpHeaders.AUTHORIZATION, token)
                    .exchange()
                    .expectStatus().isEqualTo(503)
                    .expectHeader().valueEquals(HttpHeaders.RETRY_AFTER, "5")
                    .expectHeader().doesNotExist(HttpHeaders.WWW_AUTHENTICATE)
                    .expectBody()
                    .jsonPath("$.error").isEqualTo("service_unavailable")
                    .jsonPath("$.status").isEqualTo(503)
                    .jsonPath("$.path").isEqualTo("/api/ledger/entries")
                    .jsonPath("$.detail").isEqualTo(RevocationUnavailableException.DETAIL);

            // The first request also pays for the cold path (the JWKS fetch) on a cold JVM.
            Duration bound = i == 0 ? Duration.ofSeconds(3) : Duration.ofSeconds(1);
            assertThat(Duration.ofNanos(System.nanoTime() - started)).as("request %d", i).isLessThan(bound);
        }

        downstream.verify(0, getRequestedFor(urlEqualTo("/ledger/entries")));
    }

    /** The handoff's warning: an open breaker must refuse, not skip the check and forward. */
    @Test
    void stillRefusesOnceTheBreakerIsOpen() {
        String token = userToken();
        for (int i = 0; i < RedisCircuitBreaker.FAILURES_TO_OPEN; i++) {
            client.get().uri("/api/ledger/entries").header(HttpHeaders.AUTHORIZATION, token).exchange()
                    .expectStatus().isEqualTo(503);
        }
        assertThat(breaker.allowCall()).isEqualTo(Permit.DENIED);

        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, token)
                .exchange()
                .expectStatus().isEqualTo(503)
                .expectBody().jsonPath("$.detail").isEqualTo(RevocationUnavailableException.DETAIL);

        downstream.verify(0, getRequestedFor(urlEqualTo("/ledger/entries")));
    }

    private static String userToken() {
        return "Bearer " + signingKey.mint(ISSUER, "ezzat", Instant.now().plus(5, ChronoUnit.MINUTES),
                Map.of("tenant", "acme", "scope", List.of("payments:read")));
    }
}
```

`breaker.allowCall()` returns `DENIED` without side effects while the window runs; the window is 5 s and the loop takes milliseconds, so it cannot hand out the probe here. If the tests share the breaker across methods in one context, the order does not matter: both only need it open or opening.

- [ ] **Step 3: Write `SilentRedisFailClosedTest`**

`src/test/java/com/gatekeeper/revocation/SilentRedisFailClosedTest.java`:

```java
package com.gatekeeper.revocation;

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
import java.net.Socket;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * A Redis that accepts the connection and never answers. A bearer token is refused 503 within about
 * the revocation timeout — not after Lettuce's own 60-second handshake, which is how AuthCore
 * behaves — and the gateway makes one connection attempt, whoever gives up waiting on it. The M6
 * design, sections 7 and 11.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class SilentRedisFailClosedTest {

    static final String ISSUER = "http://localhost:8080";
    static final List<Socket> held = new CopyOnWriteArrayList<>();
    static final AtomicInteger accepted = new AtomicInteger();
    static WireMockServer downstream;
    static TestKey signingKey;
    static ServerSocket silent;

    @Autowired
    WebTestClient client;

    @BeforeAll
    static void start() throws IOException {
        signingKey = TestKey.generate("k1");
        downstream = new WireMockServer(options().dynamicPort());
        downstream.start();
        downstream.stubFor(get(urlEqualTo("/oauth2/jwks")).willReturn(okJson(TestKey.jwksDocument(signingKey))));
        downstream.stubFor(any(anyUrl()).atPriority(20).willReturn(okJson("{}")));
        silent = new ServerSocket(0);
        Thread acceptor = new Thread(() -> {
            while (!silent.isClosed()) {
                try {
                    held.add(silent.accept());
                    accepted.incrementAndGet();
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
        downstream.stop();
        silent.close();
        for (Socket socket : held) {
            socket.close();
        }
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("gatekeeper.auth.jwk-set-uri", () -> downstream.baseUrl() + "/oauth2/jwks");
        registry.add("gatekeeper.auth.issuer", () -> ISSUER);
        registry.add("gatekeeper.downstream.ledger", () -> downstream.baseUrl());
        registry.add("gatekeeper.downstream.authcore", () -> downstream.baseUrl());
        registry.add("spring.data.redis.port", () -> silent.getLocalPort());
    }

    @Test
    void refusesEveryRequestWithinTheTimeoutAndConnectsOnce() {
        String token = "Bearer " + signingKey.mint(ISSUER, "ezzat", Instant.now().plus(5, ChronoUnit.MINUTES),
                Map.of("tenant", "acme", "scope", List.of("payments:read")));

        for (int i = 0; i < 10; i++) {
            long started = System.nanoTime();

            client.get().uri("/api/ledger/entries")
                    .header(HttpHeaders.AUTHORIZATION, token)
                    .exchange()
                    .expectStatus().isEqualTo(503)
                    .expectHeader().valueEquals(HttpHeaders.RETRY_AFTER, "5")
                    .expectBody().jsonPath("$.detail").isEqualTo(RevocationUnavailableException.DETAIL);

            // The first request also pays for the cold path; the check's own share is its timeout.
            Duration bound = i == 0 ? Duration.ofSeconds(3) : Duration.ofSeconds(1);
            assertThat(Duration.ofNanos(System.nanoTime() - started)).as("request %d", i).isLessThan(bound);
        }

        // The warm-up's single attempt, which every later caller shares rather than repeats.
        assertThat(accepted).as("connections accepted by the silent Redis").hasValueLessThanOrEqualTo(1);
    }
}
```

- [ ] **Step 4: Run them, then make each fail on purpose**

Run: `.\mvnw.cmd -o -q test "-Dtest=DeadRedisFailClosedTest,SilentRedisFailClosedTest"`
Expected: 3 pass.

Then, one at a time, rerun after each and restore:

| Change in `main` | Must fail |
|---|---|
| In `RevocationCheckingJwtDecoder.isRevoked`, the `DENIED` branch returns `Mono.just(false)` | `stillRefusesOnceTheBreakerIsOpen` (200) |
| In `RevocationCheckingJwtDecoder.isRevoked`, delete `.timeout(timeout)` | `refusesEveryRequestWithinTheTimeoutAndConnectsOnce` — the request waits on a connection that never completes, and fails on WebTestClient's own 5 s response timeout or on the duration assertion |
| In `GlobalErrorWebExceptionHandler.statusFor`, remove `|| error instanceof RevocationUnavailableException` | `refusesEveryBearerTokenWith503Promptly` (500) |
| In `RedisRevocationStore.isRevoked`, drop `connection.ready().then(...)` and call `redis.hasKey` directly | `refusesEveryRequestWithinTheTimeoutAndConnectsOnce` — a request blocking inside Lettuce's connect, or more than one connection. If it does not fail, say so in the report: it means the limiter's store, which still uses the step, opened the connection first, and the test cannot tell the two consumers apart |

- [ ] **Step 5: Run the suite**

Run: `.\mvnw.cmd -o test`
Expected: `Tests run: 276, Failures: 0, Errors: 0` (273 + 3).

- [ ] **Step 6: Commit**

```
test(M6): a dead or silent Redis refuses bearer tokens, fast

503 with Retry-After: 5 and the REVOCATION_UNAVAILABLE detail within the
bound, never forwarded, still refused once the breaker is open, and one
connection attempt against a Redis that never answers.
```

---

### Task 8: Both instances refuse a revocation on the next call

**Files:**
- Modify: `src/test/java/com/gatekeeper/ratelimit/TwoGatewaysShareOneLimitTest.java`

- [ ] **Step 1: Branch**

`git checkout master; git checkout -b feature/m6-task-8`

- [ ] **Step 2: Add the test**

Add imports:

```java
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import java.time.Duration;
```

Add, after `shareOneBurst()`:

```java
    /**
     * A revocation reaches every instance on its next call: no instance remembers "not revoked"
     * (the M6 design, section 5). Both are asked once before the revocation, so an in-process cache
     * of that answer — the one the design rejected — would serve the next call a 200 and fail this.
     */
    @Test
    void bothRefuseARevokedTokenOnTheNextCall() {
        String token = userToken("r-" + UUID.randomUUID());
        ledger(toFirst, token).expectStatus().isOk();
        ledger(toSecond, token).expectStatus().isOk();

        ReactiveStringRedisTemplate redis = first.getBean(ReactiveStringRedisTemplate.class);
        String key = "authcore:revoked:jti:" + TestKey.jwtIdOf(token.substring("Bearer ".length()));
        redis.opsForValue().set(key, "revoked", Duration.ofMinutes(5)).block();
        try {
            ledger(toFirst, token).expectStatus().isUnauthorized();
            ledger(toSecond, token).expectStatus().isUnauthorized();
        } finally {
            redis.delete(key).block();
        }
    }
```

Change the first sentence of the class Javadoc to: `The proof that the limit — and, since M6, a revocation — is distributed: two gateway instances, as separate application contexts on their own ports, sharing one Redis and one downstream.`

- [ ] **Step 3: Run it, then make it fail on purpose**

Run: `.\mvnw.cmd -o -q test "-Dtest=TwoGatewaysShareOneLimitTest"`
Expected: 4 pass.

Then add a 5-second in-process cache of "not revoked" to `RevocationCheckingJwtDecoder` — for example a `ConcurrentHashMap<String, Long>` of `jti` → nanoTime when last answered false, consulted before `isRevoked(jti)` and returning `Mono.just(jwt)` within 5 s. Rerun: `bothRefuseARevokedTokenOnTheNextCall` must fail with 200. Restore the decoder (`git checkout -- src/main`).

- [ ] **Step 4: Run the suite**

Run: `.\mvnw.cmd -o test`
Expected: `Tests run: 277, Failures: 0, Errors: 0` (276 + 1).

- [ ] **Step 5: Commit**

```
test(M6): both gateway instances refuse a revocation on the next call

The two-gateway test revokes a token each instance has already served
once: both refuse it next, so no instance may remember "not revoked".
```

---

### Task 9: Mutation sweep

No production change unless a mutation survives. Work on a branch; every mutation is made in the working copy and reverted with `git checkout -- src/main` before the next.

- [ ] **Step 1: Branch**

`git checkout master; git checkout -b feature/m6-task-9`

- [ ] **Step 2: Apply each mutation, run the named tests, record the result, revert**

Run each with `.\mvnw.cmd -o -q test "-Dtest=<classes>"`.

| # | Mutation (in `src/main`) | Run | Must fail |
|---|---|---|---|
| 1 | `RedisRevocationStore.isRevoked` returns `Mono.just(false)` | `RedisRevocationStoreTest,RevocationTest,TwoGatewaysShareOneLimitTest` | yes |
| 2 | Delete the no-`jti` block in `RevocationCheckingJwtDecoder.check` | `RevocationCheckingJwtDecoderTest,RevocationTest` | yes |
| 3 | `DENIED` branch returns `Mono.just(false)` | `RevocationCheckingJwtDecoderTest,DeadRedisFailClosedTest` | yes |
| 4 | `RevocationUnavailableException extends BadJwtException` (constructor `super(message, cause)`) — the failure becomes a 401 | `DeadRedisFailClosedTest,SilentRedisFailClosedTest` | yes |
| 5 | In `isRevoked`, replace `.onErrorMap(...)` with `.onErrorResume(error -> { breaker.recordFailure(permit, error); return Mono.just(false); })` — admit on failure | `RevocationCheckingJwtDecoderTest,DeadRedisFailClosedTest,SilentRedisFailClosedTest` | yes |
| 6 | In `decode`, check before the inner decoder: `return Mono.fromCallable(() -> com.nimbusds.jwt.JWTParser.parse(token).getJWTClaimsSet().getJWTID()).flatMap(store::isRevoked).then(delegate.decode(token)).flatMap(this::check);` | `RevocationCheckingJwtDecoderTest,RevocationTest` | yes (`aTokenTheInnerDecoderRejectsNeverReachesTheStore` or `anExpiredTokenNeverReachesTheStore`) |
| 7 | A 5-second in-process "not revoked" cache (as in Task 8 Step 3) | `TwoGatewaysShareOneLimitTest` | yes |
| 8 | `JwtDecoderConfig` returns the Nimbus decoder unwrapped | `RevocationTest,DeadRedisFailClosedTest` | yes |
| 9 | `GlobalErrorWebExceptionHandler.render` passes `null` as the detail always | `DeadRedisFailClosedTest` | yes |

- [ ] **Step 3: Close any gap**

If a mutation survives, write the test that kills it, in the class where it belongs, see it fail against the mutation, revert the mutation, see it pass, and commit:

```
test(M6): <what the new test pins>
```

If every mutation was caught, commit nothing; report the table with results. Either way, finish on a clean tree.

---

### Task 10: Live run and documentation

**Files:**
- Modify: `README.md`
- Modify: `docs/superpowers/HANDOFF-M3-M6.md`
- Modify: `docs/superpowers/specs/2026-09-30-gatekeeper-m6-design.md` (§11: the live-run results)

- [ ] **Step 1: Branch and start the platform**

```powershell
git checkout master; git checkout -b feature/m6-task-10
```

From the authcore directory: `docker compose up -d postgres redis`, then start AuthCore with `.\mvnw.cmd -o spring-boot:run` (it takes a while; wait for "Started"). From the gatekeeper directory:

```powershell
.\mvnw.cmd -o -q package -DskipTests
java -jar target/gatekeeper-0.0.1-SNAPSHOT.jar
```

Wait for "Started GateKeeperApplication". Use a second PowerShell for the calls below. Use `curl.exe`, never `curl`.

- [ ] **Step 2: A token works, then is revoked**

```powershell
$token = (curl.exe -s -u authcore-machine:machine-secret -d "grant_type=client_credentials&scope=payments:read" http://localhost:8080/oauth2/token | ConvertFrom-Json).access_token
curl.exe -s -o NUL -w "%{http_code}`n" -H "Authorization: Bearer $token" http://localhost:8081/api/machine/payments
curl.exe -s -o NUL -w "%{http_code}`n" -u authcore-machine:machine-secret -d "token=$token&token_type_hint=access_token" http://localhost:8080/oauth2/revoke
curl.exe -s -i -H "Authorization: Bearer $token" http://localhost:8081/api/machine/payments
```

Expected: `200` (or whatever AuthCore's `/api/machine/payments` answers for this client — record it; the point is it is not 401), then `200` from the revoke, then `401` with `WWW-Authenticate: Bearer` and the platform body. Also confirm the key exists: `docker exec authcore-redis-1 redis-cli --scan --pattern "authcore:revoked:jti:*"`.

- [ ] **Step 3: Stop Redis and time the refusals**

```powershell
$fresh = (curl.exe -s -u authcore-machine:machine-secret -d "grant_type=client_credentials&scope=payments:read" http://localhost:8080/oauth2/token | ConvertFrom-Json).access_token
docker stop authcore-redis-1
1..10 | ForEach-Object { curl.exe -s -o NUL -w "%{http_code} %{time_total}`n" -H "Authorization: Bearer $fresh" http://localhost:8081/api/machine/payments }
curl.exe -s -i -H "Authorization: Bearer $fresh" http://localhost:8081/api/ledger/entries
```

Get `$fresh` **before** stopping Redis: AuthCore's own token endpoint may hang without it. Expected: ten `503` lines, each well under a second, the later ones in milliseconds (the breaker is open); the ledger call is `503` with `Retry-After: 5` and `"detail":"REVOCATION_UNAVAILABLE"`. Record the gateway log's single WARN from "Revocation check".

Then, with Redis still down, an API-key caller: `curl.exe -s -o NUL -w "%{http_code} %{time_total}`n" -m 15 -H "X-API-Key: ak_demo_reporting_job_local_only_0000000000" http://localhost:8081/api/machine/payments`. Record what happens; the handoff's open item predicts a hang (M3's cache), and `-m 15` bounds your wait.

- [ ] **Step 4: Start Redis and see it recover**

```powershell
docker start authcore-redis-1
Start-Sleep -Seconds 6
curl.exe -s -o NUL -w "%{http_code}`n" -H "Authorization: Bearer $fresh" http://localhost:8081/api/machine/payments
```

Expected: not 503 (the breaker's probe succeeded; the log shows "Revocation check: Redis answered again; breaker closed"). Stop GateKeeper and AuthCore with Ctrl+C when done. Leave Redis running for the suite.

- [ ] **Step 5: Remeasure the suite without Redis**

Run: `.\mvnw.cmd -o test "-Dspring.data.redis.port=1"`
Record the `Tests run: …, Failures: …, Errors: …` line and work out how many of the full count do not pass (remember `TwoGatewaysShareOneLimitTest` folds its tests into one setup failure). Then run `.\mvnw.cmd -o test` with Redis and record the full count (expected 277, plus any Task 9 additions).

- [ ] **Step 6: Update the README**

Read the README's M5 section first and match its voice and structure. Add an M6 section that says:

- where the check runs (inside JWT decoding, after signature and claims) and why;
- a revoked token and a token with no `jti` are the ordinary 401;
- Redis unavailable is 503 with `Retry-After: 5` and `detail: REVOCATION_UNAVAILABLE`, and why 503 rather than 401;
- it fails closed and fast: the shared connection step, the 200 ms timeout, its own breaker that refuses;
- the consequences in the design's section 8 (boot with Redis down; API-key callers still hang on M3's cache; a bearer token on `/actuator/health`);
- the live-run results from Steps 2–4, with the measured times.

Update the test table (new classes, moved classes' packages, counts), the total, the no-Redis figure from Step 5, and every reference to `RedisWarmUp`, `RedisCircuitBreaker` or the connection step that still names the `ratelimit` package or a single breaker.

- [ ] **Step 7: Update the handoff**

In `docs/superpowers/HANDOFF-M3-M6.md`:

- §1: M6 is complete; the repo table's gatekeeper row (master hash after merge is the controller's to fill — write the test count and "M6's last code merge"); the no-Redis paragraph with Step 5's figure; a paragraph on M6 in the style of the M5 one; "Next: M7" — resilience (the milestone plan's M7), noting the open M7 item that the JWKS fetch has no response timeout.
- §4: M6 **Built**, with its three departures from the milestone plan (design section 12).
- §5: in the constants item, "the breakers' window" (two breakers now); in the API-key-cache item, add that JWT callers now get fast 503s during an outage while API-key callers still hang — observed in Step 3.
- §6: M7 should use `feature/m7-task-N`.

- [ ] **Step 8: Record the live run in the design**

Append to section 11 of `docs/superpowers/specs/2026-09-30-gatekeeper-m6-design.md` a short "Live run, <date>" paragraph with Steps 2–4's results and times.

- [ ] **Step 9: Check the docs for stale names and commit**

Run: `git grep -n "ratelimit.RedisWarmUp\|ratelimit.RedisCircuitBreaker\|RedisRateLimitStoreConnectTest\|redisCircuitBreaker"`
Expected: no output.

```
docs(M6): the revocation check in the README, handoff and design

Where the check runs, the 401 and the 503, why it fails closed and how
it stays fast, the live run against AuthCore, and the remeasured
no-Redis figure. Next is M7.
```

---

## Self-review notes (for the controller)

- **Spec coverage:** §3 → Tasks 4, 6; §4 → Tasks 4, 6, 7; §5 → Task 8; §6 → Tasks 4, 6; §7 → Tasks 1, 2, 4, 6, 7; §8 → Tasks 4, 6, 7, 10; §9 → all; §10 → Task 5; §11 → Tasks 3–9, live run Task 10; §13 → Task 10.
- **One deliberate deviation from spec §11:** the spec lists "`ErrorShapeTest`, one more case" for the 503 shape. The shape is asserted in `DeadRedisFailClosedTest` instead, where the exception really arises: forcing it inside `ErrorShapeTest` would need a stub store for that whole context. Nothing is lost; the assertions are the same.
- **Expected counts** assume Redis running and each task branching from `master` after the previous one merged: 242 (T1) → 244 (T2) → 249 (T3) → 262 (T4) → 267 (T5) → 273 (T6) → 276 (T7) → 277 (T8). If a number is off, the implementer reports the actual count and which tests account for the difference; the controller checks it against `master`'s count plus the task's new tests.
