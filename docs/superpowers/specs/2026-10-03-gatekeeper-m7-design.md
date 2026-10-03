# GateKeeper M7 — Resilience — Design

M6 made the gateway refuse what it cannot verify. M7 makes it survive its dependencies being slow,
sick or gone. A downstream that hangs no longer holds a request indefinitely, a downstream that keeps
failing is cut off for a while instead of being asked again and again, a downstream that is merely slow
cannot use up the gateway's capacity for the other one, and the two dependencies the gateway itself
needs — AuthCore's key set and Redis — fail fast and recover fast.

This is a **single-repo milestone**. AuthCore and ledger-service are unchanged, and nothing below
requires either to change. The open items in the handoff stay where they are, except the two this
milestone owns (§2).

---

## 1. Purpose

Protect callers and downstreams from each other's failures:

- **Bound every wait.** A connect, a response, a key fetch: each has a timeout.
- **Fail fast against a sick downstream.** A circuit breaker per downstream answers at once while
  the downstream is failing, so callers are not made to wait for a failure the gateway already knows
  about, and the downstream is not loaded while it recovers.
- **Isolate the downstreams.** A bulkhead per downstream caps how many requests may wait on it at once,
  so a slow one cannot take capacity from the other.
- **Absorb a momentary blip** on idempotent reads with a single retry.
- **Recover quickly** once a dependency is back.

Every answer the gateway produces for these cases is in the platform's JSON error shape, with a fixed
`detail` (§8).

---

## 2. What this milestone owns from the handoff

- **"M7 — the JWKS fetch has no response timeout."** `NimbusReactiveJwtDecoder` fetches AuthCore's key
  set with a bare `WebClient`, so an AuthCore that accepts the connection and never answers hangs the
  request. Closed by §4.
- **"Lettuce's reconnect backoff lengthens the revocation check's recovery"** (found in M6's live run:
  17.8 s of 503s after Redis returned, up to about 35 s worst case). Assigned to M7 by the repo owner
  on 2026-10-02, as its first task. Closed by §3.

---

## 3. Decision: Lettuce reconnects quickly — exponential from 100 ms to 2 s, with jitter

**Chosen with the repo owner.** A `ClientResourcesBuilderCustomizer` bean in
`com.gatekeeper.redis.RedisConfig` sets the client's reconnect delay: exponential, from 100 ms up to a
2 s cap, with jitter.

- Lettuce's default is exponential up to **30 s**. In M6's live run the gateway reconnected 17 s after
  Redis was back, and every bearer request was refused 503 until then.
- With a 2 s cap, the gateway reconnects within about 2 s of Redis returning and the revocation
  breaker's next probe — at most one 5 s window later — closes it: **about 7 s at worst** instead of 35.
- During an outage each instance attempts about once every 2 s, which is negligible. Jitter keeps
  several instances from reconnecting in lockstep when Redis returns.
- A Redis that accepts and never answers is unchanged: each attempt is still bounded by Lettuce's 60 s
  handshake timeout, and the breakers protect requests meanwhile.
- It is client-wide: the rate limiter, the API-key cache and the revocation check all recover faster.
- A constant, not a property — no caller needs another value; the handoff's constants item covers it.

Rejected: a fixed 1 s delay (lockstep attempts, a constant attempt rate through a long outage), and a
property (YAGNI).

---

## 4. Decision: the JWKS fetch times out at 2 s, and an unreachable key set is 503

**Chosen with the repo owner.** `JwtDecoderConfig` gives the decoder its own `WebClient` with a 2 s
connect timeout and a 2 s response timeout — the same budget as M3's introspection call. A fetch that
fails — refused, silent, or erroring — is answered **503** with `Retry-After: 5`, the platform body
with `"detail": "KEYS_UNAVAILABLE"`, and no `WWW-Authenticate`.

This **changes behaviour that has existed since M2**, where an unreachable key set was answered 401 so
as not to advertise that the identity provider was down. Since then M3 (introspection) and M6
(revocation) chose 503 for the same situation, for a reason that applies here equally: a 401 tells a
client to discard a very likely valid token and refresh it — against AuthCore, the very thing that is
down — which turns an outage into a refresh storm. With this decision all three "a dependency could not
answer" cases answer alike. The cost — the response reveals that the issuer is unreachable — M3 and M6
already accepted.

The key set is cached, so a fetch happens only on a cold start, a token with an unknown `kid`, or a
cache refresh; most requests during an AuthCore outage are unaffected (§11's live run shows it).

A connect timeout is set as well as a response timeout: without it, a host that never accepts the TCP
connection would wait for the operating system's own connect timeout, which can exceed 20 s.

---

## 5. Decision: timeouts toward the downstreams — global defaults, and each route its own

**Chosen with the repo owner.**

- **Global defaults** on the gateway's HTTP client: a **2 s connect timeout** and a **5 s response
  timeout**. They are the safety net: no future route can be added without a bound.
- **Each route states its own** in its `metadata`: `authcore-accounts`, `authcore-machine` and `ledger`,
  5 s each today. The value refers to a property of ours — e.g.
  `response-timeout: ${gatekeeper.resilience.response-timeout-millis.ledger}` — so `application.yml`
  shows every route's budget, and a test overrides it by name rather than by the route's position in a
  list. **It must be a plain number of milliseconds:** verified in 5.0.2, `NettyRoutingFilter` parses a
  route's `response-timeout` with `Long.parseLong` and silently ignores anything else, so `5s` would
  quietly fall back to the global value. `ProductionValuesTest` (§11) checks each is numeric.
- A response timeout is answered **504** with `"detail": "DOWNSTREAM_TIMEOUT"` and no `Retry-After`:
  for a POST the outcome is unknown, since the downstream may have processed it, and 504 says exactly
  that.
- 5 s because both downstreams answer in milliseconds; generous, not unbounded. The connect timeout is
  shorter because a refused or silent connect needs no long wait.

Rejected: global only (per-route in name only, and a slow route would mean raising everyone's), and
different values per route now (nothing needs it; a one-line change later).

---

## 6. Decision: one circuit breaker per downstream

**Chosen with the repo owner.** Spring Cloud Gateway's `CircuitBreaker` filter, backed by Resilience4j
through Spring Cloud CircuitBreaker. Two breakers: **`authcore`**, shared by the `authcore-accounts` and
`authcore-machine` routes, and **`ledger`**. A breaker protects against a sick *service*, and both
AuthCore routes reach the same process: when it is down, both are, and separate breakers would make the
second route rediscover the outage request by request. Breakers live in each gateway instance; each
instance judges a downstream from its own traffic, deliberately.

**What counts as a failure:** a connect error, a response timeout, and a downstream **502, 503 or 504**.
**A downstream 500 does not count** and passes through untouched (§7).

**Values** (properties, §10): a count-based window of the last **20** calls, judged only after at least
**10**; opens at **50 %** failures; stays open **10 s**; then lets **3** trial calls through to decide.

**When open:** answered at once, without calling the downstream: **503** with
`"detail": "DOWNSTREAM_UNAVAILABLE"` and `Retry-After` equal to the configured open window, in whole
seconds (an upper bound — the window may be partly over). Rendered by `GlobalErrorWebExceptionHandler`, like every other error.
**No `FallbackController`:** a fallback endpoint would be a new path, needing its own row in
`RouteScopeAuthorizationManager` and its own tests, to return nothing the handler cannot.

**The TimeLimiter is disabled.** Spring Cloud CircuitBreaker's Resilience4j default wraps each call in a
1 s TimeLimiter, which would cut requests at 1 s, before §5's 5 s; with
`spring.cloud.circuitbreaker.resilience4j.disable-time-limiter: true` the gateway's own response timeout
governs. (Verified in the 5.0.2 source: `ReactiveResilience4JCircuitBreaker` applies the TimeLimiter
unless `disableTimeLimiter`.)

Rejected: a breaker per route (the AuthCore routes would open separately for one outage) and one global
breaker (a sick downstream would cut off the healthy one).

---

## 7. The assumption behind what counts: availability signals versus application responses

Stated explicitly, at the repo owner's request, because the breaker's behaviour rests on it.

**Downstream 502, 503 and 504 are treated as availability and infrastructure signals.** They say "I
cannot serve right now", independent of what was asked: 503 — overloaded, restarting, in maintenance;
502 and 504 — the downstream's own upstream (a proxy, a database, a dependency) failed or was too slow.
The same request a little later is expected to succeed. That is exactly what a breaker exists to detect,
so they **count as failures**, and their bodies — which carry no information the caller can act on —
**are replaced by the gateway's error shape**, keeping the downstream's status, with
`"detail": "DOWNSTREAM_ERROR"`. The replacement covers the downstream's **headers** too: verified in
5.0.2, they are already on the response when the breaker raises its error, and Boot's error handler
does not clear them, so without removing them a `Set-Cookie` or `Content-Encoding` from the downstream
would ride on the gateway's error. The handler removes every header the downstream added.

**A downstream 500 remains an application-level response owned by the downstream.** It says "this
request hit an error" — usually a defect triggered by specific input. So it **passes through untouched**,
the downstream's own status and body, and **does not count** as a breaker failure:

1. **Counting it would let one caller take a service down for everyone.** With §6's values, a single
   client sending ten requests that trigger a 500 — by accident or on purpose — could open the breaker,
   and every caller of that downstream would be refused 503 for 10 s. The gateway would be amplifying
   one client's bad requests into an outage.
2. **The downstream's diagnostics would be lost.** The gateway replaces a counted status's body (above,
   and §8); a 500's body is the downstream's account of what went wrong, and today it reaches the caller
   as is.
3. **It is not transient.** For the same reason §9 does not retry a 500: a defect repeats.

**The cost, stated:** a downstream whose *every* request fails with 500 — a broken deployment, or a
database outage that surfaces as 500 — will not open the breaker. Spring Boot answers an unhandled
database error with 500, so a ledger whose database is down looks like this today. Callers still get
prompt 500s rather than hangs; the timeouts and the bulkhead still bound the damage. The proper fix is
in the downstream: it should answer 503 when a dependency it needs is down. Recorded as an open item
(§13), not built as a "500 rate across all callers" rule here.

---

## 8. The responses

| Situation | Status | `detail` | `Retry-After` |
|---|---|---|---|
| Breaker open | 503 | `DOWNSTREAM_UNAVAILABLE` | 10 (the open window) |
| Bulkhead full | 503 | `DOWNSTREAM_BUSY` | 1 |
| Response timeout | 504 | `DOWNSTREAM_TIMEOUT` | — |
| Connect error (refused, or the 2 s connect timeout), after the one GET retry | 502 | `DOWNSTREAM_UNREACHABLE` | — |
| Downstream answered 502, 503 or 504 (after the GET retry for 502/503) | the same | `DOWNSTREAM_ERROR` | — |
| Downstream answered 500, or any other status | passed through untouched | — | — |
| Key set unreachable or silent | 503 | `KEYS_UNAVAILABLE` | 5 |

Every gateway-generated row is the platform shape, `{"error","status","path","detail"}`, rendered by
`GlobalErrorWebExceptionHandler`; none carries `WWW-Authenticate`, since none is a 401. A connect error
reaches the handler today as an unmapped exception — probably a 500 — and becomes a deliberate 502.

How a counted downstream status becomes the gateway's response: the breaker filter checks the status
when the inner chain completes, before the response body is written, and raises
`CircuitBreakerStatusCodeException`, which the handler renders. (Read in the 5.0.2 source of
`SpringCloudCircuitBreakerFilterFactory`; the plan verifies the filter order that makes "before the body
is written" true, and a test pins it, §11.)

---

## 9. Decision: one retry, for GET only, inside the breaker

**Chosen with the repo owner.** Spring Cloud Gateway's `Retry` filter:

- **GET only.** POST, and every other method, is never retried.
- **Retried:** a connect error (the request never reached the downstream), and a downstream **502 or
  503** (usually momentary: a restart, an overload).
- **Not retried:** a timeout, or a 504 — the downstream may still be working on it, and a retry would
  double the wait; a **500** — a defect repeats (§7).
- **Once, after 100 ms.** A caller waits a few hundred milliseconds more at worst, never twice the
  timeout.
- **The filter's exception list is set explicitly to `java.net.ConnectException`.** Verified in 5.0.2:
  its defaults retry `IOException` *and* the gateway's `TimeoutException`, matching either the error or
  its cause, so left at the defaults it would retry every response timeout. `series` is set empty so
  that only the listed statuses, 502 and 503, are retried, not the whole 5xx range.
- **Inside the breaker:** each route lists `CircuitBreaker` first and `Retry` after it, so the breaker
  sees one outcome per client request — a request that succeeds on its retry is a success — and while
  the breaker is open nothing is retried.
- **One rate-limit token per client request.** `RateLimitFilter` runs before the route filters, so a
  retry does not pass through it again.

Rejected: two retries including timeouts (a 15 s worst case, and triple load on a struggling
downstream), and no retry (the milestone plan asks for it, and a GET that meets a downstream mid-restart
would fail when a retry 100 ms later would succeed).

---

## 10. Decision: a semaphore bulkhead per downstream

**Chosen with the repo owner.** The breaker answers failure; a bulkhead answers *slowness*. A
downstream answering in 4.9 s — inside the timeout — never trips the breaker, yet can fill the gateway's
connections with waiting requests while the other downstream starves.

- A Resilience4j **semaphore** bulkhead per downstream, named like the breakers: `authcore`, `ledger`.
- At most **50** concurrent requests per downstream; beyond that, refused at once without waiting:
  **503** `DOWNSTREAM_BUSY`, `Retry-After: 1`.
- **A refusal does not count as a breaker failure** — the downstream did not fail; the gateway chose not
  to call it. The breaker is configured to ignore `BulkheadFullException`.
- Implemented through Spring Cloud CircuitBreaker's own reactive bulkhead support
  (`ReactiveResilience4jBulkheadProvider`, verified in the 5.0.2 source): enabled by default, keyed by
  the breaker's name, and applied inside the breaker. It requires `resilience4j-bulkhead` on the
  classpath, which the starter does not bring.

Rejected: Reactor Netty's per-address connection-pool limits (tied to host and port, not to a service;
today's `pending-acquire-timeout` is 45 s; a refusal would need its own mapping and would count as a
breaker failure unless excluded; hard to test exactly), and no bulkhead (slow-but-not-failing is the one
case nothing else covers).

---

## 11. Testing

**Every production value is a property, and tests override it with small values** — chosen with the
repo owner. Spring Cloud Gateway's timeouts already are. The breakers and bulkheads are configured from
**our own** `gatekeeper.resilience` properties, applied through Spring Cloud CircuitBreaker's
customizers, rather than from Resilience4j's own `resilience4j.*` properties. Those would also bind —
verified, the starter brings `resilience4j-spring-boot3` 2.3.0 transitively, and it supplies the
registries — but they are loosely bound: a misspelt key is ignored and the breaker silently runs on its
defaults (a 100-call window, 60 s open). Ours are strictly bound and validated, as in M5 and M6, so a
typo fails the boot.

| Class | What it proves |
|---|---|
| `ReconnectDelayTest` | The configured `Delay` never exceeds 2 s for any attempt and varies (jitter); the context's `LettuceConnectionFactory` uses it |
| `JwksTimeoutTest` | A key set that accepts and never answers → 503 `KEYS_UNAVAILABLE` in about 2 s, not a hang; refused → the same; WARN once, DEBUG after, INFO on recovery. `UnreachableJwksErrorShapeTest` moves from 401 to 503 |
| `DownstreamTimeoutTest` | A slow downstream → 504 `DOWNSTREAM_TIMEOUT` within the bound; a POST times out once and is not retried |
| `DownstreamCircuitBreakerTest` | Downstream 503s open the breaker; then every request is answered 503 `DOWNSTREAM_UNAVAILABLE` at once with `Retry-After`, and the downstream's request count stops growing. Repeated **500s never open it**, and each 500's body reaches the caller byte-identical. A downstream 502/503/504 comes back as the gateway's shape with its status and `DOWNSTREAM_ERROR`. After the open window a successful trial closes it. With `ledger`'s breaker open, the AuthCore routes still answer |
| `DownstreamRetryTest` | GET 503 then 200 → 200, two downstream requests; 502 likewise; POST 503 → no retry; GET timeout and GET 500 → no retry; a retried GET costs one rate-limit token |
| `DownstreamBulkheadTest` | With a limit of 2: two slow requests held, the third refused 503 `DOWNSTREAM_BUSY` at once; many refusals leave the breaker CLOSED; the other downstream is unaffected |
| `ResiliencePropertiesTest` | Binding, validation and strict binding, as in M5 and M6 |
| `ProductionValuesTest` | Loads the real `application.yml` with **no** test overrides and asserts the agreed values: 2 s connect and 5 s response on each route; breaker 20 / 10 / 50 % / 10 s / 3; bulkhead 50; retry GET-only, once, 100 ms, connect errors and 502/503; `CircuitBreaker` before `Retry` on every route; the TimeLimiter disabled. So small test values cannot hide a production change |

Existing tests are unchanged except the 401 that becomes 503 for an unreachable key set. M7 has no
two-gateway test: its breakers are per instance by design.

**Mutations**, each of which must turn a test red: count 500 as a failure; drop 502/503 from the
counted statuses; retry POST; retry on a timeout; put `Retry` before `CircuitBreaker`; let bulkhead
refusals count; leave the 1 s TimeLimiter on; remove the JWKS timeout; revert the JWKS answer to 401;
restore Lettuce's default reconnect delay; give both downstreams one breaker name.

**Live run**, against the real AuthCore and ledger-service:

1. Ledger stopped: the first GETs → 502 `DOWNSTREAM_UNREACHABLE` after one retry each; the breaker
   opens and calls are refused 503 in milliseconds; the AuthCore routes still answer; ledger started
   again → recovery within the open window plus a trial call.
2. A downstream that never answers (a second gateway instance pointed at a silent socket): 504 at 5 s
   with the real values, and the breaker opening after enough timeouts.
3. A key set that never answers (an instance with `jwk-set-uri` pointed at a silent socket): 503
   `KEYS_UNAVAILABLE` in about 2 s, where today it hangs.
4. Redis down then up: the revocation check's recovery time, expected about 7 s or less against M6's
   17.8 s.

The bulkhead is not live-run — 50 concurrent requests would need a load tool; the limit-2 test covers
it exactly, and the README says so.

---

## 12. Components

New package **`com.gatekeeper.resilience`**:

- **`ResilienceProperties`** — `gatekeeper.resilience`, strictly bound (`ignoreUnknownFields = false`)
  and validated in the constructor: the JWKS timeout, the per-route response timeouts in milliseconds,
  the breaker's window, minimum calls, failure-rate threshold, open duration and trial calls, and the
  bulkhead's limit.
- **`ResilienceConfig`** — applies those values to the `authcore` and `ledger` breakers and bulkheads
  through Spring Cloud CircuitBreaker's customizers; the breaker ignores `BulkheadFullException`; logs
  breaker state transitions (§14).

Changed:

- **`com.gatekeeper.redis.RedisConfig`** — the `ClientResourcesBuilderCustomizer` (§3).
- **`com.gatekeeper.config.JwtDecoderConfig`** — the decoder's own `WebClient` with timeouts (§4), and
  the JWKS state logging (§14).
- **`com.gatekeeper.error.GlobalErrorWebExceptionHandler`** — the statuses and `detail`s of §8; the
  unreachable-key-set case moves from 401 to 503.
- **`application.yml`** — the HTTP client's global timeouts; each route's `metadata` timeouts and its
  `CircuitBreaker` and `Retry` filters; the `gatekeeper.resilience` block; `disable-time-limiter`. Each
  commented.
- **`pom.xml`** — `spring-cloud-starter-circuitbreaker-reactor-resilience4j` and `resilience4j-bulkhead`,
  versions managed by Spring Cloud's BOM. Their jars are not yet in the local repository: the first
  build after adding them runs online once.

**No new endpoint**, so no new row in `RouteScopeAuthorizationManager`. The rate limiter and the
revocation check are unchanged.

**Verified before planning** (jars, source at the release tags, and a throwaway probe app on the same
versions): the registries come from the transitive `resilience4j-spring-boot3`; a connect error reaches
the handler as `java.net.ConnectException` (refused, or Netty's `ConnectTimeoutException`), a response
timeout as a 504 `ResponseStatusException` caused by the gateway's `TimeoutException`, an open breaker as
the gateway's `ServiceUnavailableException`, a counted status as `CircuitBreakerStatusCodeException` —
which Boot would render as 500, so the handler maps it explicitly — and a full bulkhead as Resilience4j's
`BulkheadFullException`; the breaker's status check runs before the body is written (route filters take
orders 1, 2, … by position, inside `NettyWriteResponseFilter` at −1); route `metadata` accepts a property
placeholder; a JWKS timeout reaches the handler as the "Could not obtain the keys" failure it already
recognises; and the breaker-state listener must be registered once per breaker
(`Customizer.once`), since the factory's customizer runs on every call.

---

## 13. Out of scope, and open items it leaves

- **A downstream whose every request fails with 500** does not open its breaker (§7). Owned by the
  downstreams: they should answer 503 when a dependency they need is down.
- **No fallback responses with content** (cached data, defaults): every failure is an honest error.
- **Breaker state is per instance**, not shared through Redis.
- **The constants item** in the handoff gains §3's reconnect delay, which stays a constant.
- **Observability** — counters for refusals, timeouts and retries, breaker state as a metric — is M8's.

---

## 14. Logging

The rule of M5 and M6: log **state changes**, not requests.

- **Breakers:** WARN when one opens, naming it and its failure rate; INFO when it goes half-open and
  when it closes.
- **Bulkhead refusals, timeouts, connect errors and retries:** DEBUG per request. They happen under load
  or during an outage, so per-request INFO would flood the log exactly when it matters; the breaker's
  WARN reports the outage, and M8 will count them.
- **The key set:** WARN on the first failed fetch after a success, DEBUG for further failures, INFO when
  a fetch succeeds again.

---

## 15. Documentation changed alongside

- **README** — an M7 section: the timeouts, the breakers and what counts (§7 stated plainly), the
  retry, the bulkhead, the response table, the live run; the test tables and counts; known limitations.
- **Handoff** — §1 to "Next: M8"; §4 M7 built; §5 the two owned items closed and §13's open items added.
- **`application.yml`** — every new value commented.

---

## 16. Definition of done

- Every row of §8 is produced as described, and a downstream 500 passes through untouched.
- The breaker opens on 502/503/504, connect errors and timeouts, never on a 500 or a bulkhead refusal.
- `CircuitBreaker` precedes `Retry` on every route; POST is never retried; a retried GET costs one
  rate-limit token.
- An unreachable key set is 503 within about 2 s.
- The revocation check recovers within about 7 s of Redis returning.
- Every mutation in §11 is caught; the full suite passes with Redis running; the live run is done and
  recorded in the README.
- AuthCore and ledger-service are unchanged.
- No commit, file or document credits anyone but the repo owner as an author or contributor.
