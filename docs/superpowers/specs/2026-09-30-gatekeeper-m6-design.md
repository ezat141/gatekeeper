# GateKeeper M6 — Token revocation check — Design

M5 decided how much a caller may use. M6 decides whether a token that is still validly signed and
unexpired may be used at all: AuthCore can revoke a token before its expiry, and from M6 the gateway
refuses a revoked token on the next request, at every instance.

This is a **single-repo milestone**. AuthCore already publishes the deny-list the check reads (§2), and
ledger-service is not involved; nothing below requires either to change. The open items the handoff
records stay where they are, with the one exception §12 names.

---

## 1. Purpose

A bearer JWT is checked by signature, so without a shared deny-list, revoking one would not take effect
until it expired — up to ten minutes for AuthCore's access tokens. M6 closes that window at the edge.

Revocation is a **security control**, the opposite of M5's capacity control, and that decides its
failure mode: when the gateway cannot tell whether a token is revoked, it **refuses** (§4). It must
also refuse **fast** — AuthCore itself, with Redis stopped during the M5 run, hung about 60 seconds
before answering — so the connection handling M5 built is reused rather than bypassed (§7).

---

## 2. What AuthCore and the framework provide, verified

**AuthCore's contract**, read from its source (`com.authcore.revocation`):

| Fact | Consequence |
|---|---|
| `RevocationService.revokeJti` writes **`authcore:revoked:jti:<jti>`**, value `"revoked"`, TTL = the token's remaining lifetime (at least one second) | One `EXISTS` answers the question; an expired entry disappears exactly when the token would have expired anyway |
| `RevocationSuccessHandler` deny-lists a JWT revoked at `/oauth2/revoke`; for a refresh token (opaque) it deletes the rotation family in Postgres and writes nothing to Redis | There is **no family key** to check. M6 checks `jti` only (§12) |
| `RevokedTokenValidator` checks the same key, blocking, inside AuthCore's own JWT validation, and **passes a token with no `jti`** | M6 departs from that on purpose (§6) |
| `DataSeeder` gives its clients access tokens of 5 or 10 minutes | The window M6 closes |

**Spring Authorization Server 7.1.0** (`JwtGenerator`, bytecode): the builder's `.id(UUID.randomUUID())`
runs **before** the branch on token type, so every JWT AuthCore issues — access token and ID token
alike — carries a `jti`. Refusing a token without one (§6) therefore costs nothing today, and it does
not distinguish ID tokens from access tokens; the handoff's ID-token item stays open.

**Spring Security 7.0.6**, bytecode:

| Fact | Consequence |
|---|---|
| `JwtReactiveAuthenticationManager` calls the `ReactiveJwtDecoder`, then `onErrorMap(JwtException.class, …)`: a `BadJwtException` becomes `InvalidBearerTokenException`, any other `JwtException` becomes `AuthenticationServiceException` | A revoked token thrown as `BadJwtException` is an ordinary invalid-token 401 |
| Anything that is not a `JwtException` passes the manager untouched | `RevocationUnavailableException` extends neither `JwtException` nor `AuthenticationException` |
| `AuthenticationWebFilter` resumes only on `AuthenticationException`, sending it to the entry point | So that exception reaches `GlobalErrorWebExceptionHandler`, which picks the status — the route M3's `IntrospectionUnavailableException` already takes to its 503 |

---

## 3. Decision: the check runs inside JWT authentication

**Chosen with the repo owner:** the check is a `ReactiveJwtDecoder` wrapping the existing Nimbus
decoder. `JwtDecoderConfig` returns the wrapper as the bean.

- **After every existing check.** The Nimbus decoder verifies the signature against the JWKS and
  validates `exp`, `nbf` and the pinned `iss` first. Only a token that passes all of it reaches Redis,
  so a forged or expired token — whose `jti` an outsider picks freely — cannot generate Redis load.
- **Before authorization and rate limiting.** A revoked token is not authenticated, so it never
  receives a 403 that would describe the rule table, never spends a bucket, and is never stamped or
  forwarded.
- **The same place AuthCore checks**, in its own `RevokedTokenValidator` — a revoked token is one more
  reason a token is invalid, not a separate concern.
- **No new filter, and no order to pin.**

Rejected: a `WebFilter` after authentication, which would duplicate the entry point's 401 and sit
between two Spring Security filters in an order someone would have to keep; and a gateway
`GlobalFilter` like `RateLimitFilter` — the milestone plan's `RevocationCheckFilter` — which runs after
authorization, so a revoked token could still be answered 403.

API-key callers never pass through the decoder. Disabling an API key in AuthCore takes effect when the
gateway's introspection cache expires (M3); M6 does not change that.

---

## 4. Decision: when Redis cannot answer, refuse with 503

**Chosen with the repo owner.** An error, a timeout, an empty answer, or an open breaker (§7) is a
`RevocationUnavailableException`, which `GlobalErrorWebExceptionHandler` maps to **503** with
`Retry-After: 5`, the platform body with `"detail": "REVOCATION_UNAVAILABLE"`, and no
`WWW-Authenticate`.

Why 503 and not 401, although an unreachable JWKS answers 401:

- **The token is very likely valid.** A 401 tells a well-behaved OAuth client to discard it and
  refresh. During this outage a refresh means AuthCore's token endpoint, and AuthCore hangs about 60 s
  with Redis down: a 401 would turn a Redis outage into a refresh storm against a service that is
  already stuck. A 503 tells the client to back off and retry the same token.
- **It is M3's precedent for the same situation** — the gateway cannot complete a check that depends
  on another component — and M3 answers it 503 with `Retry-After: 5`.
- **`Retry-After: 5` is truthful:** it is the breaker's window (§7).

Either status is a refusal, so the security property holds either way; the choice is which refusal
does the least collateral damage. The `detail` lets an operator or a client tell this 503 from M3's.
M3's 503 keeps its body unchanged; giving it a `detail` is outside this milestone.

---

## 5. Decision: no local cache

**Chosen with the repo owner, departing from the milestone plan**, which says to "cache negative
results briefly". Every JWT request makes one `EXISTS`; nothing about revocation is remembered in the
gateway process.

- The plan's own acceptance line is "revoke a token in AuthCore → gateway rejects it on the next call".
  A cache of "not revoked" answers breaks that for up to its TTL, at each instance separately.
- The cost it would save is one sub-millisecond command on a connection already open for the limiter,
  beside the Lua script every request already runs.
- It would not help during an outage: failing closed, a cached "not revoked" would only be a window in
  which a revoked token gets through — failing open by another route.

Caching positives ("revoked until `exp`") is safe but saves calls only for a caller replaying a revoked
token; not built. The two-gateway test (§11) fails the day an in-process cache is added.

---

## 6. Decision: a token with no `jti` is refused

**Chosen with the repo owner.** A missing or blank `jti` is a `BadJwtException`, answered exactly like
a revoked token (§8). Blank matters: it would check the key `authcore:revoked:jti:`, which nobody
writes.

- A token that cannot be revoked should not pass a gateway whose job includes enforcing revocation.
  That is failing closed, the direction of this milestone.
- It costs nothing: every token AuthCore issues carries one (§2).
- If a future issuer omits it, the symptom is a loud 401 and a WARN (§8), not a silent gap.

AuthCore's own validator passes such tokens; the two now differ, deliberately. Not configurable — no
caller needs the other behaviour.

---

## 7. Connection handling and the breaker

M5's §7 is the reference for why each piece exists. What M6 reuses, and how:

- **One connection step, shared.** `RedisRateLimitStore`'s single-flight, uncancellable connect —
  `Mono.defer(ping).subscribeOn(boundedElastic).single().thenReturn(TRUE).cache(ok → forever, error →
  zero, empty → zero)` — moves unchanged into `com.gatekeeper.redis.RedisConnectionStep`, one bean
  that the limiter's store, the revocation store and the warm-up all wait on. Without it the revocation
  check's first `EXISTS` against a silent Redis would block inside `subscribe()`, before its timeout
  had started.
- **A bounded wait:** `gatekeeper.revocation.redis-timeout`, 200 ms, on the store call.
- **A circuit breaker**, because failing closed does not stop Lettuce buffering every command without
  bound while disconnected: something must stop issuing them. **An open breaker refuses** — 503,
  without calling Redis. It never skips the check; copying the limiter's handling of `DENIED` would
  silently fail open, which is the handoff's warning and a mutation in §11.
- **Three consecutive failures open it**, as for the limiter, and here it matters more: a
  failing-closed breaker that opened on one GC-pause timeout would answer every JWT caller 503 for five
  seconds. An isolated failure still refuses its own request (§4). While open, one probe per window;
  a failed probe re-opens it at once; only the probe's success closes it.

**Two breakers, one class — chosen with the repo owner.** `RedisCircuitBreaker` moves to
`com.gatekeeper.redis` and gains a name and a phrase for what its consumer does while it is open, so
each log line says truthfully what is happening. Two beans, `rateLimitBreaker` and
`revocationBreaker`, injected by qualifier:

- each consumer bounds its own share of Lettuce's buffer to about one command per window;
- each logs its own outage;
- each counts only its own failures. A request makes one call for each, so a shared count would make
  "three in a row" mean one and a half requests.

Rejected: one shared breaker (a probe permit handed to the limiter leaves the revocation check denied,
so that request is refused 503 even when the probe succeeds), and no breaker (every request during an
outage adds a command to the buffer — M5's leak in another form).

The **permit is taken when the check is subscribed**, not when the decoder's `Mono` is assembled, and
the fail-closed mapping covers the store call only: a `BadJwtException` from a revoked token must not
be recorded as a Redis failure.

**How fast the refusals are:**

- Redis down (connection refused): the connect step fails in milliseconds; three failures open the
  breaker; after that no refusal touches Redis.
- A Redis that accepts and never answers: the first requests share one connection attempt and give up
  at 200 ms each; once the breaker opens, refusals are immediate.

**`RedisWarmUp`** moves with the connection step. Its warning now says both consequences: the limiter
fails open and the revocation check refuses until Redis answers. It still never fails the boot.

**Not changed:** M3's API-key cache uses the same template without these protections. That is recorded
in the handoff and stays open; fixing it would widen the milestone.

---

## 8. The responses

**A revoked token — 401, indistinguishable from any other rejected token.** `BadJwtException` becomes
`InvalidBearerTokenException`, and `JsonServerAuthenticationEntryPoint` answers:

- `WWW-Authenticate: Bearer`, as for every rejected token (RFC 6750 makes the `error` parameter
  optional, and the gateway has never sent one);
- `{"error":"unauthorized","status":401,"path":"…"}`, with no `detail`.

The gateway does not tell a caller why a token was rejected — expired, forged or revoked — and
revocation is not made the exception; that is also RFC 7009's posture. Nothing is stamped,
rate-limited or forwarded.

**A missing or blank `jti` — the same 401.**

**Revocation unavailable — 503**, as §4: `Retry-After: 5`, the platform body with
`"detail":"REVOCATION_UNAVAILABLE"`, no `WWW-Authenticate`. The handler gains a bare type match for
`RevocationUnavailableException`, on the same reasoning as M3's: a type the gateway declares for itself
and throws from one place for one reason.

**Logging**, chosen so an outsider cannot flood it:

| Event | Level | Why |
|---|---|---|
| A revoked token | DEBUG, with its `jti` | A holder of a revoked token can replay it as fast as they like, and the limiter never sees it. Counting these is M8's audit event |
| A missing `jti` | WARN, with `sub` and `iss` | Only the issuer can produce a validly signed token without one: an issuer bug, and not something an outsider can trigger |
| Each 503 | DEBUG | The outage is logged by the breaker instead |
| The breaker opening / closing | WARN with the cause, once / INFO | Named "Revocation check", saying it refuses bearer-token requests while open |

**Stated consequences of failing closed:**

- If Redis is down at boot, JWT callers are answered 503 until it answers. The warm-up still runs
  before the port binds.
- During a Redis outage, JWT callers get fast 503s, while API-key callers still hang on M3's cache (the
  open item above).
- A bearer token sent to `/actuator/health` is authenticated even though the path is `permitAll`, so
  during an outage it is answered 503. An anonymous health probe is unaffected.

---

## 9. Components

New package **`com.gatekeeper.revocation`**:

- **`RevocationCheckingJwtDecoder`** — `ReactiveJwtDecoder`. `decode(token)` = the inner decoder, then
  the `jti` check, the breaker permit, the store call with its timeout, and the verdict (§3, §6, §7).
- **`RevocationStore`** — `Mono<Boolean> isRevoked(String jti)`.
- **`RedisRevocationStore`** — waits on `RedisConnectionStep`, then `hasKey("authcore:revoked:jti:" +
  jti)`. Owns the prefix, with AuthCore's `RevocationService` cited beside it as the contract.
- **`RevocationUnavailableException`** — `RuntimeException`; deliberately neither `JwtException` nor
  `AuthenticationException` (§2).
- **`RevocationProperties`** — `gatekeeper.revocation`, `ignoreUnknownFields = false`,
  `redisTimeout` validated positive in the constructor.
- **`RevocationConfig`** — the store and `revocationBreaker` beans.

New package **`com.gatekeeper.redis`**, moved from `ratelimit`:

- **`RedisConnectionStep`** — the connect step, extracted from `RedisRateLimitStore` with its test
  constructor (any ping, for a Redis that answers, fails or never answers).
- **`RedisCircuitBreaker`** — gains its name and while-open phrase; otherwise unchanged.
- **`RedisWarmUp`** — waits on the connection step.

Changed:

- **`RedisRateLimitStore`** — takes the connection step instead of building one.
- **`RateLimitConfig` / `RateLimitFilter`** — `rateLimitBreaker` by qualifier.
- **`JwtDecoderConfig`** — returns the wrapper.
- **`GlobalErrorWebExceptionHandler`** — the 503 mapping and its `detail`.
- **`ErrorBody`**'s Javadoc — a fifth call site with a `detail`.

AuthCore and ledger-service: unchanged.

---

## 10. Configuration

```yaml
gatekeeper:
  revocation:
    # A revoked token is a security failure, so an unanswered check refuses (503). It must refuse
    # fast, not hang. See the M6 design, sections 4 and 7.
    redis-timeout: 200ms
```

No default in code, as for the limiter: a missing value fails the boot. The breaker's window (5 s),
its threshold (three) and the warm-up's timeout (2 s) stay constants, and the handoff's item about
that now covers two breakers.

---

## 11. Testing

**The existing fail-open tests change.** `DeadRedisFailOpenTest` and `SilentRedisFailOpenTest` send
JWT callers and expect 200 with Redis unreachable; under M6 those are 503s, correctly. Both exist to
test the limiter, so each replaces the `RevocationStore` bean with a stub that answers "not revoked",
and the fail-closed behaviour gets its own classes with the real store. `TestKey.mint` already writes a
random `jti`, so no other JWT test changes. `RateLimitTest`'s "touch no Redis" still holds: `EXISTS`
writes nothing.

| Class | What it proves |
|---|---|
| `RevocationCheckingJwtDecoderTest` (unit) | Revoked, missing `jti`, blank `jti` → `BadJwtException`; not revoked → the `Jwt` unchanged; error, empty, timeout → `RevocationUnavailableException`; open breaker → refused without calling the store; a token the inner decoder rejects never reaches the store; only a probe's success closes the breaker; a revoked token is not recorded as a Redis failure |
| `RedisRevocationStoreTest` (real Redis) | The exact key `authcore:revoked:jti:<jti>`; an expired entry reads as not revoked; it waits on the connection step |
| `RevocationTest` (integration, WireMock JWKS and downstream) | Revoked → 401 in the platform shape with `WWW-Authenticate: Bearer`, downstream never called, no `gatekeeper:rl:*` key written; missing `jti` → 401; not revoked → 200; an API-key caller → 200 with the store not consulted |
| `DeadRedisFailClosedTest` | Redis on a closed port: a JWT caller gets 503, `Retry-After: 5`, `detail: REVOCATION_UNAVAILABLE`, no `WWW-Authenticate`, in well under a second; still 503, never 200, once the breaker is open |
| `SilentRedisFailClosedTest` | A server that accepts and never answers: 503 within the bound, and exactly one connection |
| `TwoGatewaysShareOneLimitTest`, one more case | Revoke once in the shared Redis: both instances refuse on their next call |
| `ErrorShapeTest`, one more case | `RevocationUnavailableException` → 503 in the platform shape, with the `detail` |
| `RevocationPropertiesTest` | Binds the value; zero, negative, missing or an unknown key fails |
| Moved: breaker, connection step, warm-up | Move to `redis` with their classes; the breaker's name and phrase appear in its log lines |

**Mutations**, in a scratch copy; each must turn at least one test red:

1. Remove the `EXISTS` (always "not revoked").
2. Admit a token with no `jti`.
3. Make an open breaker skip the check — the handoff's warning.
4. Map `RevocationUnavailableException` to 401.
5. `onErrorResume` → admit, on the store call.
6. Check before the inner decoder instead of after it.
7. Add a 5-second in-process cache of "not revoked".

**Live run** against the real AuthCore, gateway started with `java -jar`:

1. A client-credentials token → `/api/machine/…` → 200.
2. `POST /oauth2/revoke` with it → the next call → 401.
3. `docker compose stop redis`: time ten JWT calls — fast 503s; the ledger route with a JWT is 503
   too; an API-key caller is recorded as still hanging (M3's open item).
4. Start Redis: within about five seconds an unrevoked token is answered 200 again.

The suite grows by about 25 from 242, and the no-Redis failure count is remeasured.

**As built:** the suite grew by 36, to 278. `RevocationCheckingJwtDecoderTest` gained a fourteenth
case, `aLateSuccessDoesNotCloseTheBreaker`. The 503's shape is asserted in `DeadRedisFailClosedTest`,
where the exception really arises, rather than in `ErrorShapeTest`; `IntrospectionUnavailableTest`
now asserts that M3's 503 still has no `detail`. Without Redis (`-Dspring.data.redis.port=1`) the run
reports `Tests run: 275, Failures: 54, Errors: 20` — `TwoGatewaysShareOneLimitTest` folds its four
tests into one setup failure — so 77 of 278 do not pass, up from 45 of 242: every bearer-token test
is now answered 503, which is correct. The mutation sweep made all seven mutations above and three
more — `JwtDecoderConfig` returning the Nimbus decoder unwrapped, the revocation 503 without its
`detail`, and that `detail` leaking onto M3's 503 — and each of the ten turned at least one test red.

**Live run, 2026-10-02**, against the real AuthCore, with the gateway started with `java -jar`:

- **Revocation.** A client-credentials token for `authcore-machine` with `payments:read` (`jti`
  `9a23e3ae-…`, a 600-second lifetime) got 200 on `GET /api/machine/payments`. `POST /oauth2/revoke`
  answered 200, and the next call got **401**, with `WWW-Authenticate: Bearer` and
  `{"error":"unauthorized","status":401,"path":"/api/machine/payments"}`. Redis held
  `authcore:revoked:jti:9a23e3ae-6488-47bd-9b58-3c06018cf32c` with a TTL of about 588 s.
- **Redis stopped.** Ten JWT calls, all **503**: the first three in 0.247, 0.229 and 0.228 s — the
  200 ms timeout — and the next seven in 0.009–0.032 s, with the breaker open. The ledger route
  answered 503 with `Retry-After: 5`, no `WWW-Authenticate`, and
  `{"error":"service_unavailable","status":503,"path":"/api/ledger/entries","detail":"REVOCATION_UNAVAILABLE"}`.
  The breaker logged one WARN — `Revocation check: Redis failed 3 times in a row; refusing
  bearer-token requests with 503 for 5 s at a time until it answers` — with the `TimeoutException`
  as its cause. An API-key caller hung until curl's 15-second limit, as M3's open item predicts.
- **Redis restarted: recovery took 17.8 s, not the five or so item 4 expected.** JWT calls stayed 503
  until 17.8 s after Redis was up. The breaker probed every five seconds as designed, but the probes
  at 6.4 s and 12.1 s each timed out at about 220 ms: the gateway had not reconnected. Lettuce's
  `ConnectionWatchdog` backs off between reconnect attempts — during this outage they came about 9,
  8, 17 and then 30 s apart — and the last one reconnected 17 s after Redis was up. The breaker
  closed straight after it: `Revocation check: Redis answered again; breaker closed`. So recovery is
  Lettuce's reconnect delay, which grows with the outage's length up to about 30 s, plus up to one
  breaker window, and JWT callers are refused 503 throughout. The limiter has the same delay, where
  it only means requests go unlimited a little longer; here it means refusals. A shorter reconnect
  delay would shorten it — in Lettuce 6.8 that is `ClientResources.reconnectDelay`, not a
  `ClientOptions` setting — and it would apply client-wide. That was deliberately not done in M6,
  and the handoff (§5) records it as open.
- **After recovery** the token revoked earlier was still 401: the deny-list survived the Redis
  restart.

---

## 12. Out of scope, and departures from the milestone plan

- **No refresh-token family check.** AuthCore records families in Postgres and deny-lists nothing for
  them in Redis (§2). A family revocation invalidates the refresh tokens; access tokens already issued
  from it run to their expiry unless revoked individually. That is AuthCore's contract to extend, not
  the gateway's to infer.
- **No local cache** (§5), where the plan asked for one.
- **The check is in the decoder**, not a `RevocationCheckFilter` (§3).
- **API keys** are not deny-listed; they revoke through AuthCore's `enabled` flag and M3's cache TTL.
- **M3's API-key cache on a Redis outage** keeps its open item (§7).
- **Counting revoked-token replays** is M8's audit event (§8).

---

## 13. Documentation changed alongside

- **README** — an M6 section: where the check runs, the 401 and 503, why it fails closed and fast, the
  consequences in §8; the test table and counts; the no-Redis figure, remeasured.
- **Handoff** — §1 to "Next: M7", the repo table, M6 "Built" in §4 with the three departures in §12,
  the open items touched (the constants item, the API-key cache item's contrast with M6).
- **`application.yml`** — the `gatekeeper.revocation` block, commented.

---

## 14. Definition of done

- A revoked token is refused 401 on the next request, at every instance; a token without a `jti` too.
- An unanswerable check is refused 503 with `Retry-After: 5` and the `detail`, within 200 ms per
  request and immediately once the breaker is open; never admitted.
- The limiter's fail-open behaviour is unchanged and still tested.
- Every mutation in §11 is caught.
- The full suite passes with Redis running; the live run in §11 is done and recorded in the README.
- AuthCore and ledger-service are unchanged.
- No commit carries a `Co-Authored-By` line or Claude attribution.
