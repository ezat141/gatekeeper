# GateKeeper M3–M6 — Handoff

Written at the close of M0–M2 so the next session starts productive rather than rediscovering what
this one learned by failing, and kept current through M7. Read this before touching code.

---

## 1. Where things stand

**M0–M7 are complete.** M0–M2 was verified against three live services; M3 (API-key authentication)
landed across AuthCore and GateKeeper with its own spec and plan, dated 2026-08-24; M4 (route-to-scope
authorization and the tenant check) was a GateKeeper-only milestone, spec and plan dated 2026-09-26,
verified by mutation and against the three live services. M5 (distributed rate limiting and daily
quotas) was GateKeeper-only too, spec and plan dated 2026-09-27, verified by mutation and by two
gateway processes against the live platform and one shared Redis. M6 (the token revocation check) was
GateKeeper-only in code, spec and plan dated 2026-09-30, verified by ten mutations and against the
real AuthCore with Redis stopped and restarted. M7 (resilience) was GateKeeper-only, spec and plan
dated 2026-10-03: timeouts toward the downstreams and on the JWKS fetch, a circuit breaker and a
semaphore bulkhead per downstream, one retry for a GET, an unreachable key set answered 503 rather than
401, and Lettuce reconnecting within 2 s. It was verified by fourteen mutations and against the real
AuthCore, ledger-service and Redis, with ledger stopped and restarted, a downstream and a key set that
never answer, and Redis stopped and restarted twice.

| Repo | `master` | Tests | Visibility |
|---|---|---|---|
| [authcore](https://github.com/ezat141/authcore) | `f345f8d` | 78 | public |
| [ledger-service](https://github.com/ezat141/ledger-service) | `3cd3738` | 26 | public |
| [gatekeeper](https://github.com/ezat141/gatekeeper) | `ee64220` — M7's last code merge; the merge of M7's documentation follows it | 323 | public |

All three clean. GateKeeper's count was confirmed by running its suite at the close of M7; AuthCore's
and ledger-service's are unchanged since they were last run. ledger-service was not changed by M4, M5,
M6 or M7. AuthCore's code was not changed either, and M7 did not touch it at all; its one M6 commit,
`f345f8d`, is a README paragraph naming the deny-list key `authcore:revoked:jti:<jti>` as a
cross-service contract, since the gateway now reads it. AuthCore's run takes over ten minutes — every
test class starts its own Spring context against Testcontainers, at roughly 45 seconds each — so give
it a generous timeout or run it in the background rather than assume it has hung.

**GateKeeper's suite requires Redis.** Without it (measured with `-Dspring.data.redis.port=1`), the run
reports `Tests run: 320, Failures: 73, Errors: 21`: 94 failures reported, one of them
`TwoGatewaysShareOneLimitTest`'s setup standing for its four tests — 97 of 323 not passing, up from
77 of 278 before M7 and 45 of 242 before M6. The increase is correct behaviour: without Redis the
revocation check refuses every bearer token with 503, so every test that expects a JWT to get through
fails — and since M7 that includes every downstream resilience test, whose requests are refused before
any downstream is called. By class: `AuthorizationTest` 13, `RedisRateLimitStoreTest` 11,
`ApiKeyAuthenticationTest` 9, `RateLimitTest` 8, `DownstreamRetryTest` 8, `IdentityPropagationTest` 7,
`DownstreamCircuitBreakerTest` 7, `RedisApiKeyCacheTest` 5, `IntrospectionUnavailableTest` 4,
`RoutingTest` 4, `KeyRotationTest` 3, `RedisRevocationStoreTest` 3, `RevocationTest` 3,
`JwtAuthenticationTest` 2, `DownstreamTimeoutTest` 2, `DownstreamUnreachableTest` 2, `ErrorShapeTest` 1,
`DownstreamBulkheadTest` 1, and `TwoGatewaysShareOneLimitTest` 1 (folded from 4). It reads like a
regression and is not one. Start Redis first: `docker compose up -d redis` from the authcore directory.

**GateKeeper today:** three routes (`/api/accounts/**` and `/api/machine/**` to AuthCore with the path
preserved, `/api/ledger/**` to ledger-service with `StripPrefix=1` and `X-API-Key` removed). A caller
authenticates with **either** a bearer JWT, verified against AuthCore's JWKS with the issuer pinned,
**or** an `X-API-Key`, checked through AuthCore's introspection endpoint and cached in Redis. When
AuthCore cannot answer an introspection, the gateway says 503 rather than 401. Inbound `X-GK-*` headers
are stripped before authentication and re-stamped from verified identity afterwards, including the
subject of a key caller.

Authorization is an ordered rule table (`RouteScopeAuthorizationManager`): accounts authenticated
only, machine `SCOPE_payments:read` / `:write` by method, ledger a JWT *and* the scope, anything else
refused. The gateway reads scopes only; ledger-service checks permissions only; AuthCore checks both
(scopes on its machine routes, permissions and roles on accounts). `TenantAuthorizationManager` wraps
the table: every `X-Tenant` value and every `tenant` query value must equal the JWT's `tenant` claim
exactly, and tenant-less callers — client-credentials tokens and all API keys — are never checked. A
refusal is a 403 in the platform shape plus one of four fixed `detail` strings, with no
`WWW-Authenticate`; an unauthenticated caller still gets 401 with `WWW-Authenticate: Bearer`. The M4
design (`specs/2026-09-26-gatekeeper-m4-design.md`) is the reference for all of it.

Every routed request is then rate limited (`RateLimitFilter`, a `GlobalFilter` just after
`IdentityStampFilter`, so a 401 or 403 is never counted). The caller's identity is `tenant:<slug>` for
a user token, else `client:<aud[0]>` (falling back to `sub`), else `apikey:<name>`; `aud` is read, not
validated. Plans and assignments are `gatekeeper.rate-limit.*` in `application.yml`, strictly bound and
validated at startup. One atomic Lua script per request checks a token bucket
(`gatekeeper:rl:{id}`) and then a daily quota (`gatekeeper:quota:{id}`) on Redis's clock, so every
instance sharing the Redis enforces one limit. A refusal is a 429 in the platform shape, with the
fixed `detail` of its reason (`RATE_LIMITED` or `QUOTA_EXCEEDED`), a computed `Retry-After`, and
`X-RateLimit-*` and `X-Quota-*` headers, which allowed responses carry too. A Redis failure **fails
open** within 200 ms: a single-flight connection off the event loop, a warm-up before the port binds,
and a five-second circuit breaker keep it from hanging or leaking connections. The M5 design
(`specs/2026-09-27-gatekeeper-m5-design.md`) is the reference, section 7 especially.

Since M6 every bearer JWT is also checked for revocation, before any of that, inside JWT decoding:
`RevocationCheckingJwtDecoder` wraps the Nimbus decoder, so only a token whose signature, `exp`, `nbf`
and `iss` already passed reaches Redis, and a revoked token is never authorized, counted or forwarded.
It asks `EXISTS authcore:revoked:jti:<jti>`, AuthCore's deny-list, on every request, and nothing is
cached in the gateway, so a revoked token is refused on its next call at every instance. A revoked
token, and one with no or a blank `jti`, is the ordinary 401 with `WWW-Authenticate: Bearer` and no `detail`. When Redis cannot
answer, the check **fails closed**: 503 with `Retry-After: 5` and `"detail":"REVOCATION_UNAVAILABLE"`,
no `WWW-Authenticate`, because a 401 would send clients holding valid tokens to refresh against an
AuthCore that is itself stuck. It refuses fast through the same pieces M5 built, now in
`com.gatekeeper.redis`: the shared single-flight `RedisConnectionStep`, a 200 ms timeout
(`gatekeeper.revocation.redis-timeout`), the warm-up, and a breaker of its own — `revocationBreaker`
beside the limiter's `rateLimitBreaker`, one `RedisCircuitBreaker` class — whose open state refuses. API
keys are not deny-listed. The M6 design (`specs/2026-09-30-gatekeeper-m6-design.md`) is the reference;
its section 11 records the live run, including recovery after a Redis restart taking 17.8 s, not about
five, because of Lettuce's reconnect backoff — fixed in M7 (§5).

Since M7 the gateway survives its dependencies being slow, sick or gone, through Spring Cloud Gateway's
own `CircuitBreaker` and `Retry` route filters, backed by Resilience4j through Spring Cloud
CircuitBreaker and configured from `gatekeeper.resilience` (`ResilienceProperties`, strictly bound).
Every routed call has a 2 s connect and a 5 s response timeout — globally, and stated by each route in
its `metadata` as **plain milliseconds**, because Spring Cloud Gateway silently ignores a non-numeric
route timeout. One breaker per downstream service, `authcore` (both AuthCore routes) and `ledger`:
a 20-call window judged after 10, opening at 50 %, open 10 s, 3 trial calls; while open, 503
`DOWNSTREAM_UNAVAILABLE` with `Retry-After: 10`. It counts exactly three things —
a `ConnectException`, the gateway's response timeout, and a downstream 502/503/504 — through
`DownstreamFailures`, the single source of truth for what the breaker records and what
`GlobalErrorWebExceptionHandler` maps. **The assumption it rests on, the M7 design's section 7:** a
downstream 502/503/504 is an availability signal, counted, and replaced by the gateway's shape with
`DOWNSTREAM_ERROR`, headers included; a 500 is the downstream's own answer and passes through untouched,
never counted, so one caller cannot cut a service off for everyone — at the stated cost that an
all-500 downstream never opens its breaker (§5). Everything else is neutral: the breaker records only
availability failures and ignores every other exception, so a caller's own error or a bulkhead refusal
counts neither for nor against the downstream — a final-review fix, since Resilience4j counts an
exception it neither records nor ignores as a success. One retry, for GET only, 100 ms later, on a
connect error, 502 or 503, inside the breaker and costing no second rate-limit token. A semaphore
bulkhead per downstream, 50 in flight, refusing 503 `DOWNSTREAM_BUSY` with `Retry-After: 1`; a refusal
has two guards, that ignore rule and an explicit `ignoreExceptions(BulkheadFullException)`, and removing
either one alone is harmless by design. The JWKS fetch has a 2 s connect and response timeout, and an
unreachable key set is now 503 `KEYS_UNAVAILABLE`, not 401 — a change from M2, made for the reason M3
and M6 already gave. `JwksFetchLogging` logs it once per outage, judging a fetch by its body. Lettuce
reconnects with full jitter from 100 ms up to 2 s. The M7 design
(`specs/2026-10-03-gatekeeper-m7-design.md`) is the reference; its section 11 records what was built
beyond the plan and the live run: ledger cut off after nine 502s and recovering on its own, a silent
downstream answered 504 at about 5 s, a silent key set answered 503 at about 2 s, and recovery from a
Redis restart in 0.55–5.96 s against M6's 17.8 s.

**Next: M8 — audit and observability**, the milestone plan's per-request audit event (principal, tenant,
route, status, latency) to Kafka `gateway.audit` through a reactive producer, Micrometer metrics
(request rate, 401/403/429 counts, per-route latency percentiles, gateway overhead, circuit state), a
Grafana dashboard, and W3C `traceparent` propagation so a trace spans gateway and downstream. Two open
items in §5 are natural for it. The first is counting what M7 logs per request only at DEBUG or TRACE:
bulkhead refusals, response timeouts, connect errors, counted statuses and open-breaker refusals are
each one DEBUG line per request from Boot's error handler, which `GlobalErrorWebExceptionHandler`
inherits, enabled with
`logging.level.org.springframework.boot.webflux.autoconfigure.error.AbstractErrorWebExceptionHandler=DEBUG`;
and Resilience4j's `CircuitBreakerStateMachine` logs "recorded … as failure" or "ignored …" at DEBUG;
retries are visible only at TRACE on
`org.springframework.cloud.gateway.filter.factory.RetryGatewayFilterFactory`, several lines per GET;
breaker state changes are already WARN and INFO. The second is quieting Reactor Netty's per-request WARN
on a timed-out key-set fetch. Any endpoint M8 adds — a metrics scrape, say — needs its own row in
`RouteScopeAuthorizationManager`, or it is refused `NO_RULE`.

Design and plan documents are in `docs/superpowers/specs/` and `docs/superpowers/plans/`. Milestone
scope for M3–M10 is in `GateKeeper-Implementation-Plan.md`, two levels up from the repository.

---

## 2. Environment rules — expensive to rediscover

- **`.\mvnw.cmd`, never `mvn`.** System Maven is 3.2.5 and far too old. Prefer `-o` (offline).
- **`curl.exe`, never `curl`** in PowerShell — `curl` is an alias for `Invoke-WebRequest`.
- **The Bash tool's PATH broke mid-session** (`git`, `grep`, `head` all vanished) and later recovered.
  If it happens again, switch to the PowerShell tool.
- **`&&` does not work in Windows PowerShell 5.1.** Use `;` or `if ($?) { ... }`.
- **`Set-Content -Encoding utf8` writes a BOM**, which lands as the first character of a commit
  subject. Two commits shipped that way before it was caught. Use instead:
  `[System.IO.File]::WriteAllText($path, $text, (New-Object System.Text.UTF8Encoding($false)))`.
  Verify with raw bytes — reading a subject through a PowerShell string *consumes* the BOM and hides it.
- **`git commit -m` breaks on quotes.** Write a message file and use `git commit -F`.
- **`mvnw.cmd spring-boot:run "-Dspring-boot.run.arguments=…"` fails here**, because the project path
  contains spaces (`'D:\courses\My' is not recognized`). To start GateKeeper with arguments — two
  instances on different ports, say — build with `.\mvnw.cmd -o -q package -DskipTests` and run
  `java -jar target/gatekeeper-0.0.1-SNAPSHOT.jar --server.port=… …`.
- **Never add a `Co-Authored-By` line, or any tool attribution.** Standing rule: the repo owner is the
  only contributor.
- **Docker Desktop must be running** for AuthCore (Postgres + Redis):
  `docker compose up -d postgres redis` from the authcore directory. It stops often.
- Heredocs with markdown content fail in this shell often enough that a file-writing tool is the
  saner choice for documents.
- **User tokens need a browser and PKCE — for the confidential `authcore-client` too.** Log in and
  consent in a private browser window, then exchange the code with `curl.exe`. Without
  `code_challenge`, AuthCore refuses `authcore-client`'s authorize request with `invalid_request`,
  secret or not. The working calls are in the M4 plan, Task 6 Step 2.

---

## 3. Boot 4 and Spring Cloud facts, all verified against the jars

Boot 4 renamed starters and relocated packages more than any release since Boot 2, and the old names
frequently still resolve as deprecated aliases — so a wrong one compiles cleanly and only drifts.

| Wrong (Boot 3 habit) | Correct |
|---|---|
| `spring-boot-starter-web` | `spring-boot-starter-webmvc` |
| `spring-boot-starter-oauth2-resource-server` | `spring-boot-starter-security-oauth2-resource-server` |
| `spring-boot-starter-test` | per-feature: `-webmvc-test`, `-webflux-test`, `-security-test`, `-actuator-test` |
| `spring-cloud-starter-gateway` | `spring-cloud-starter-gateway-server-webflux` |

| Class | Boot 4 package |
|---|---|
| `AutoConfigureMockMvc` | `org.springframework.boot.webmvc.test.autoconfigure` |
| `AutoConfigureWebTestClient` | `org.springframework.boot.webtestclient.autoconfigure` |
| `AbstractErrorWebExceptionHandler` | `org.springframework.boot.webflux.autoconfigure.error` |
| `ErrorAttributes`, `ErrorWebExceptionHandler` | `org.springframework.boot.webflux.error` |
| `ReactiveSecurityAutoConfiguration` | renamed `ReactiveWebSecurityAutoConfiguration`, and moved |

Three more, each of which cost a build:

- **Gateway routes bind under `spring.cloud.gateway.server.webflux.routes`.** A wrong prefix binds
  nothing, starts cleanly, and yields silent 404s — the one failure mode here with no error message.
- **`HttpHeaders` no longer implements `MultiValueMap`** in Spring Framework 7. `keySet()` does not
  exist; use `headerNames()` and `remove(String)`.
- **Verify before writing.** `jar tf <jar> | grep ClassName` and `javap -cp <jar> <FQCN>` settle these
  in one command. Nearly every defect in M0–M2 was a confidently-remembered name that had changed.

---

## 4. What M3–M7 build

**M3 — API-key authentication.** An `X-API-Key` converter plus a reactive authentication manager,
composed with JWT so *either* mechanism authenticates.

The *data* already exists in AuthCore: table `api_keys`, where `key_hash` is **SHA-256 hex** — not
bcrypt, because this is a per-request lookup rather than a password — with comma-separated `scopes`,
`enabled`, and `expires_at`. Keys carry an `ak_` prefix so a leaked one is greppable. Seeded demo key:
`ak_demo_reporting_job_local_only_0000000000`, scope `payments:read`.

What does **not** exist is any way for another service to ask about it. There is no HTTP seam, only a
database table — which is the wrong kind of seam for this platform. The decision below settles what
to do about that before any code is written.

### Decided: M3 may change AuthCore, and should

The question comes up immediately, so it is answered here rather than re-argued. **AuthCore exposes
no seam for validating an API key.** It has fourteen HTTP endpoints and none of them do this; the
`api_keys` table is reached only through `ApiKeyStore.findByRawKey()`, a direct `JdbcTemplate` query
used solely by `ApiKeyAuthenticationProvider` inside AuthCore's own filter chain. The only seam that
exists is a database table.

**Adding one to AuthCore is in scope, and is the right choice rather than a concession**, because
every alternative is worse and one of them destroys what this platform exists to demonstrate:

- *GateKeeper reading AuthCore's Postgres directly* would mean three services sharing a database.
  The design claim, stated in the responsibility matrix and all three READMEs, is that these services
  couple by a wire contract with no shared code and no shared database, and that GateKeeper is
  stateless and owns no business data. A JDBC connection into AuthCore's schema quietly deletes the
  most distinctive property of the project. (M5 has since made the gateway hold one kind of business
  data — which tenant, client or key is on which plan — in its configuration, deliberately and until
  M9; the M5 design, section 3.)
- *A shared Redis cache* only appears to dodge the question. Nothing populates such a cache today —
  AuthCore hits Postgres per request — so adding that population **is itself an AuthCore change**. It
  does not avoid modifying AuthCore; it makes the contract implicit and undocumented instead of
  explicit and reviewable.
- *Not validating at the edge* contradicts M3's own acceptance criterion.

There is precedent: M0–M2 scoped AuthCore as untouched **for that milestone**, and explicitly recorded
one deferred AuthCore change (pinning `issuer-uri`) as something to revisit. That was a milestone
boundary, not a standing rule.

It is also the honest architecture. AuthCore owns identity, and "is this credential valid, and what
does it grant" is an identity question. The issuer answering it is correct; the enforcer inferring it
from another service's tables is not. RFC 7662 token introspection is the same shape — API keys are
not OAuth tokens, but an issuer exposing an authenticated endpoint that answers whether a credential
is valid is the standard pattern.

**Constraints on the change:**

- One small endpoint, **authenticated**, so only trusted callers reach it. Left open it becomes an
  oracle for testing stolen keys at line rate.
- Return validity, scopes and expiry only. Never the key or its hash.
- Cache the answer in GateKeeper's Redis with a short TTL rather than calling per request. GateKeeper
  needs Redis for M5 and M6 regardless.
- Treat it as a contract change: add it to the design spec's integration table beside JWKS and the
  revocation key, so it is documented rather than folklore.

**Two consequences to plan for:**

- **M3 is a two-repo milestone**, as Task 13 was. AuthCore gets its own branch, tests and review
  rather than riding along inside a GateKeeper commit.
- **`last_used_at` becomes less accurate.** `ApiKeyStore.touchLastUsed()` updates it on validation;
  once GateKeeper caches introspection results, the timestamp stops reflecting real usage. Decide
  deliberately whether the endpoint touches it, and record the consequence either way.

**M4 — Route-to-scope authorization and tenant check.** A
`ReactiveAuthorizationManager<AuthorizationContext>` mapping route to required authority, and refusing
a token whose `tenant` does not match the requested path. Deny is `403`. **Built.** No routed path
carries a tenant, so the check compares the `X-Tenant` header and `tenant` query parameter instead —
the M4 design, section 3, records why.

**M5 — Distributed rate limiting.** `RedisRateLimiter` token bucket keyed by tenant or client, plus a
daily quota counter with a TTL. `429` with `Retry-After`. **Built** — but not on `RedisRateLimiter`,
which takes its rates per route id rather than per caller: the gateway runs its own script, bucket and
quota together, on Redis's clock, keyed by tenant, else client, else API key. The M5 design, sections
2, 4 and 6, records why.

**M6 — Revocation check.** A reactive `EXISTS` against AuthCore's deny-list. The contract is already
live: `RevocationService` writes Redis key **`authcore:revoked:jti:<jti>`**, value `"revoked"`, with a
TTL equal to the token's remaining lifetime. Revoked means `401`. A Redis that cannot answer must
refuse, not admit — the opposite of M5's choice, and deliberately so (§1). **Built** — refusing with
503, not 401, when Redis cannot answer (the M6 design, section 4) — with three departures from the
milestone plan, which the M6 design, section 12, records:

- **No refresh-token family check.** The plan says `jti`/family, but AuthCore records families in
  Postgres and deny-lists nothing for them in Redis, so there is no family key to check. Access tokens
  issued from a revoked family run to their expiry unless revoked individually; that is AuthCore's
  contract to extend, not the gateway's to infer.
- **No local cache.** The plan says to cache negative results briefly. A cache of "not revoked" would
  break the plan's own acceptance line — rejected on the next call — at each instance for up to its
  TTL, to save one sub-millisecond command; and during an outage it would be a window in which a
  revoked token gets through.
- **In the decoder, not a `RevocationCheckFilter`.** A gateway `GlobalFilter` runs after
  authorization, so a revoked token could still be answered 403. Inside JWT decoding, after the
  signature and claims, a revoked token is simply an invalid one, refused before authorization, rate
  limiting and routing.

**M7 — Resilience.** Resilience4j through the gateway's `CircuitBreaker` filter, per-route timeouts,
a bounded retry for idempotent GETs only, and bulkheads. Kill a downstream: the circuit opens, the
gateway fails fast, and it recovers when the downstream returns. **Built**, and demonstrated live with
ledger-service stopped and started (the M7 design, section 11) — with these departures from the
milestone plan, each in the M7 design:

- **No `FallbackController`.** An open breaker is answered 503 `DOWNSTREAM_UNAVAILABLE` by
  `GlobalErrorWebExceptionHandler`, like every other error. A fallback endpoint would be a new path
  needing its own rule-table row and tests, to return nothing the handler cannot (section 6).
- **One breaker per downstream service, not per route.** Both AuthCore routes share `authcore`, since
  they reach one process (section 6).
- **A downstream 500 never counts and passes through untouched**; 502/503/504 count and are replaced,
  headers included (section 7).
- **Configured from `gatekeeper.resilience`**, strictly bound, rather than Resilience4j's own loosely
  bound `resilience4j.*` properties, where a misspelt key leaves a breaker silently on its defaults
  (section 11).
- **Two items it took over from §5:** the JWKS fetch's timeout, with an unreachable key set now 503
  rather than 401 (section 4), and Lettuce's reconnect delay (section 3).

---

## 5. Deferred items these milestones inherit

Found during M0–M7 and recorded rather than fixed, or closed by a later milestone and marked so. Each
names the milestone that owns it, or says it has none.

- ~~**M4 — the 403 path still has the empty-body gap that 401 lost.**~~ **Closed in M4.**
  `JsonServerAccessDeniedHandler` renders every 403 in the platform shape with a fixed `detail` and no
  `WWW-Authenticate`, wired once on `exceptionHandling` for JWT and key callers alike — the M4 design,
  section 7.
- ~~**M4 — the two AuthCore routes are separate on purpose.**~~ **Closed in M4, used as intended.** The
  machine route carries scope rules; the accounts route is authenticated only, because its real checks
  are argument-dependent and live in AuthCore's own `@PreAuthorize` — the M4 design, section 4.
- ~~**M4 — strip `X-API-Key` from ledger**~~ (deferred by M3 design §13). **Closed in M4.** The ledger
  route has `RemoveRequestHeader=X-API-Key`, and a key caller is refused 403 before reaching it — the
  M4 design, section 6.
- **Unowned — firewall rejections have no JSON body.** Spring Security's default
  `StrictServerWebExchangeFirewall` refuses `..`, `//`, `%2F`, `;`, `%25` and similar with a bare 400,
  outside the platform error shape. Pre-existing Spring default; M4 came to depend on the firewall
  (the rule table and the routes must see the same path) but did not change its response. The natural
  home is whichever milestone next touches the error shape.
- **M9 (or sooner, if touched) — duplicate `X-API-Key` headers.** A JWT caller sending `X-API-Key:`
  (blank) followed by `X-API-Key: <valid key>` authenticates as the JWT, because the converter reads
  only the first value. On the machine route both values are then forwarded to AuthCore while
  `X-GK-Subject` names the JWT's subject. Consistent only while AuthCore also reads the first value,
  which servlet `getHeader` does. Pre-existing since M3.
- **Unowned, the repo owner's decision — AuthCore's session as a tenant source.** A caller holding an
  AuthCore `JSESSIONID` cookie can make AuthCore resolve the session's tenant when the request names
  none. The gateway forwards cookies and AuthCore refuses the mismatch itself, so it is not an
  escalation. Stripping `Cookie` on the two AuthCore routes would close it at the edge — a behaviour
  change left undecided (M4 design, section 5).
- **ledger-service, the repo owner to decide which way — it does not enforce client scope.** Its
  `AuthCoreAuthoritiesConverter` Javadoc
  (`ledger-service/src/main/java/com/ledger/config/AuthCoreAuthoritiesConverter.java`) says "scope
  stays the client's delegated ceiling, while roles and permissions describe the user. A request is
  only permitted when both agree", but no ledger rule reads a `SCOPE_*` authority —
  `POST /ledger/entries` checks only the `payments:write` permission. Since M4 the gateway enforces
  the scope on ledger routes, so a direct call to ledger is the one path where a client's grant is not
  enforced. Either ledger should enforce scope too, or that Javadoc is wrong.
- **AuthCore (token typing), with the gateway able to act — OIDC ID tokens may authenticate as bearer
  tokens. Not verified live.** Spring Authorization Server issues ID and access tokens with the same
  issuer, key and `aud` (the client id), and sets no distinct `typ` such as `at+jwt`; the gateway's
  default `JwtTypeValidator` accepts `JWT` or no `typ` at all. So an ID token would pass the gateway's
  decoder. It carries no `scope`, so every scope rule refuses it, and no `tenant` (AuthCore's
  customizer writes that to access tokens only), so the tenant check never applies — but the
  authenticated-only rules (`/api/accounts/**`, `/actuator/info`) would admit it. Read from the
  Spring Authorization Server 7.1.0 and Spring Security 7.0.6 bytecode and AuthCore's
  `AuthCoreTokenCustomizer`, not by sending an ID token. The fix belongs in AuthCore's token typing;
  the gateway could also refuse tokens that carry no `scope`, if wanted. **Since M5 it also picks a
  bucket:** an ID token has no `tenant`, so the rate limiter counts it against `client:<aud>` rather
  than the user's tenant — a user holding both tokens can choose which of two buckets to spend, and
  ID-token callers from every tenant share one. Fixing this item closes that too (M5 design,
  section 4).
- **Whoever configures trusted proxies — the subdomain stays out of reach only while
  `spring.cloud.gateway.server.webflux.trusted-proxies` is unset.** With it set, the client's host
  travels on as `X-Forwarded-Host`, and if AuthCore ever runs with a forward-headers strategy the
  subdomain returns as a tenant source that outranks `X-Tenant` (M4 design, section 5).
- **AuthCore's concern — its own 403s have an empty body.** Observed in the M4 run. Recorded so nobody
  assumes the gateway's 403 shape extends past the gateway: a 403 with no body came from AuthCore.
- ~~**M7 — the JWKS fetch has no response timeout.**~~ **Closed in M7.** Spring Security's
  `ReactiveRemoteJWKSource` built a bare `WebClient.create()`, so a host that accepted the connection
  and never answered hung the request. `JwtDecoderConfig.jwksWebClient` now gives the decoder its own
  `WebClient` with a 2 s connect and a 2 s response timeout (`gatekeeper.resilience.jwks-timeout`,
  bounded to 1 ms–60 s), and any failed fetch is answered 503 `KEYS_UNAVAILABLE` with `Retry-After: 5`
  instead of the former 401 — the M7 design, section 4. In the M7 run a silent key set was refused in
  2.01–2.49 s. `JwksTimeoutTest` pins it.
- **Do not "fix" `TenantRequiredException` in ledger-service.** It is unreachable in production:
  clearing the permission gate requires the `permissions` claim, and AuthCore writes `tenant`, `roles`
  and `permissions` inside one block, so a token carries all of them or none. It is a deliberate guard
  against a future issuer breaking that coupling, and the spec explains it. Deleting it as dead code
  would be wrong.
- **The platform error shape agrees on 401 and 403 and diverges below that.** GateKeeper reshapes
  every error it produces; ledger-service reshapes only those two. Deliberate scope. Do not let a
  README claim a uniformity that stops at 403.

Found during M5, by its reviews and its live run:

- **AuthCore's concern, and a warning for M6 — AuthCore hangs when Redis is down.** Observed in the M5
  run: with Redis stopped, requests through the gateway's AuthCore routes hung about 60 seconds and
  ended 401, and AuthCore called directly gave no answer in 15 seconds. The gateway's ledger route
  answered in 22–26 ms meanwhile. M6's revocation check must fail closed *fast*, not like this (§1).
  It does: in the M6 run, JWT callers were refused 503 in 9–247 ms with Redis stopped. Since M7 the
  gateway bounds AuthCore's hang at the route's 5 s response timeout, answering 504
  `DOWNSTREAM_TIMEOUT`.
- **Whoever next touches the API-key path — M3's cache on a Redis outage.** It uses the same template
  as the limiter and the revocation check, without their protections. Observed in the M5 run: an
  API-key caller hung with Redis stopped, waiting in Lettuce's disconnected buffer up to the command
  timeout. And a Redis that accepts connections and never answers could block an event loop on the
  cache's first connection, for up to Lettuce's 60-second handshake timeout (M5 design, section 7).
  **The M6 run made the contrast plain:** with Redis stopped, JWT callers got fast 503s — 0.23–0.25 s
  for the first three, 9–32 ms once the revocation breaker opened — while an API-key caller hung until
  curl's 15-second limit, and would have hung longer.
- **Unowned — Lettuce buffers commands without bound while disconnected.** The two Redis circuit
  breakers, the limiter's and the revocation check's, each bound their consumer's share to about one
  command per five-second window. The client-wide fix
  (`REJECT_COMMANDS` as the disconnected behaviour, or a bounded `requestQueueSize`) was considered and
  not adopted, because it changes M3's API-key cache behaviour during a reconnect.
- **The M4 ID-token item above — ID tokens pick their bucket.** Recorded there; fixing it closes this.
- **Unowned, natural home M10 or later — no per-IP flood protection.** The limiter counts only
  authenticated, authorized requests. Floods of unauthenticated or forbidden requests never reach a
  downstream, but cost gateway CPU and, for random API keys, negatively cached introspection calls
  (M5 design, sections 5 and 12).
- **Whoever changes AuthCore's `aud` — `aud[0]` stops naming the client if AuthCore adopts resource
  indicators or an audience customizer.** `aud` would then name a resource server, alone or beside the
  client, and every client would silently share one bucket. That change must change
  `RateLimitIdentity` with it (M5 design, section 4).
- **Unowned, accepted — Redis's clock stepping backwards.** After a backward step a drained bucket stays
  drained, refused with `Retry-After: 1`, until Redis's clock passes the stored time again; a step
  back across midnight resets the day's count. Triggered by an NTP step on the Redis host or a failover
  to a replica with a skewed clock (M5 design, section 6).
- **Unowned — a downstream sending `X-RateLimit-*` or `X-Quota-*` would duplicate the gateway's.**
  Spring Cloud Gateway appends downstream response headers to those a filter set. No downstream sends
  them today; setting the headers in `beforeCommit` would fix it. **Since M7 it has a second face** —
  see the M7 list below.
- **Unowned — the warm-up's timeout (2 s), the breakers' window (5 s) and their threshold (three
  consecutive failures) are constants, not properties**, and the warm-up does not run under lazy
  initialisation. Since M6 this covers two breakers, `rateLimitBreaker` and `revocationBreaker`, which
  share the constants in `RedisCircuitBreaker`. Since M7 it covers Lettuce's reconnect delay too —
  `RedisConfig.RECONNECT_DELAY`, full jitter from 100 ms to 2 s — a constant by design (M7 design,
  section 3). M7's own values — timeouts, breakers, bulkheads — are all properties.
- **Anyone deploying — rate-limit assignment keys cannot be set through environment variables.**
  Relaxed binding lowercases an environment variable and splits it on underscores, so a name like
  `demo-reporting-job` cannot be expressed. Use a mounted configuration file or
  `SPRING_APPLICATION_JSON`.

Found during M6, by its live run:

- ~~**Unowned (or M7) — Lettuce's reconnect backoff lengthens the revocation check's recovery.**~~
  **Closed in M7**, as its first task: `RedisConfig` sets `ClientResources.reconnectDelay` to full
  jitter from 100 ms up to 2 s, through a `ClientResourcesBuilderCustomizer` (M7 design, section 3;
  `ReconnectDelayTest`). In the M7 run, with Redis stopped for over 30 s and started twice, the gateway
  reconnected 0.90 s and 0.48 s after `docker start`, and bearer tokens were served again at 5.96 s
  (the revocation breaker had tripped: one window) and 0.55 s (it had not), against 17.8 s. AuthCore's
  own client still backs off the old way — a new item below. The original finding, observed in the M6
  run: after Redis was started again, JWT callers kept getting 503 for 17.8 s, not
  the five or so the design expected. The breaker probed every five seconds as designed, but its
  probes at 6.4 s and 12.1 s each timed out at about 220 ms, because the gateway had not reconnected:
  Lettuce's `ConnectionWatchdog` backs off between reconnect attempts — about 9, 8, 17 and then 30 s
  apart during that outage — and the last one reconnected 17 s after Redis was up. The breaker closed
  straight after it. So recovery is Lettuce's reconnect delay, which grows with the outage's length up
  to about 30 s, plus up to one breaker window, and JWT callers are refused 503 throughout. The limiter
  has the same delay, but there it only means requests go unlimited a little longer; here it means
  refusals. A possible fix is a shorter reconnect delay — in Lettuce 6.8 that is
  `ClientResources.reconnectDelay`, not a `ClientOptions` setting — deliberately not made in M6: it
  applies to the whole client, so it also changes the limiter's and M3's cache's reconnects (the M6
  design, section 11).

Found during M7, by its design, its reviews and its live run:

- **The downstreams, the repo owner to decide — a downstream whose every request fails with 500 never
  opens its breaker.** The stated cost of the M7 design's section 7: a 500 is the downstream's own
  answer, passed through and never counted, so that one caller cannot cut a service off for everyone.
  A broken deployment, or a ledger-service whose database is down — Spring Boot answers that with
  500 — is therefore never cut off; callers get prompt 500s, not hangs. The fix belongs in the
  downstreams, which should answer 503 when a dependency they need is down. Not built in the gateway as
  a "500 rate across all callers" rule.
- **AuthCore's concern, the repo owner to decide — AuthCore's own Redis client still uses Lettuce's
  default reconnect backoff.** Observed in the M7 run: its reconnect attempts came about 9, 8, 16 and
  30 s apart, so after Redis returned the AuthCore routes were answered 504 `DOWNSTREAM_TIMEOUT` by the
  gateway, AuthCore still hanging, for about 20 s and 31 s in two cycles — long after the gateway had
  recovered — and those timeouts counted toward the `authcore` breaker. AuthCore should adopt the same
  reconnect delay as the gateway (full jitter, 100 ms to 2 s). That is an AuthCore change, outside M7.
- **M8 — Reactor Netty logs a WARN of its own on every timed-out key-set fetch** ("The connection
  observed an error", with a `ReadTimeoutException`). Observed in the M7 run: the gateway's own WARN
  appeared once over three requests to a silent key set, Reactor Netty's on each. So the log as a whole
  is not one line per outage. Quieting the `reactor.netty.http.client.HttpClientConnect` logger is the
  candidate fix.
- **Unowned, pre-existing — a downstream echoing an `X-RateLimit-*` header can make the gateway's copy
  disappear.** On a counted status (502/503/504) `GlobalErrorWebExceptionHandler` removes every header
  the downstream added, by name, so a downstream sending one of the gateway's rate-limit header names
  would take the gateway's own value with it on that error. No downstream sends them today. The fix is
  to spare the names the gateway sets itself; it belongs with the duplicate-header item above.
- **Accepted — breaker state is per instance.** Each gateway instance judges a downstream from its own
  traffic, deliberately; nothing is shared through Redis, and M7 has no two-gateway test.
- **Accepted — the bulkhead is covered by tests only, not by the live run.** Fifty concurrent requests
  would need a load tool; `DownstreamBulkheadTest` covers it with a limit of two. M10's load test is the
  natural place to see it live.
- **Unowned — the JWKS connect timeout is not exercised by a test.** `JwksTimeoutTest` covers a key set
  that accepts and never answers, and `UnreachableJwksErrorShapeTest` a refused connection; nothing
  stages a host that never accepts the connection at all.

---

## 6. How M0–M2 was run, and why it is worth repeating

Every task got a `feature/task-N` branch off `master`, merged back with `git merge --no-ff` so the
topology stays visible on GitHub. Two reviews per task — spec compliance first, then code quality —
each by an independent agent explicitly told **not to trust the implementer's report**, followed by
fix-and-re-review loops until clean. M4 used `feature/m4-task-N` because the `feature/task-N` names
from M0–M3 still exist, M5 used `feature/m5-task-N`, M6 `feature/m6-task-N` and M7
`feature/m7-task-N`; M8 should use `feature/m8-task-N`.

One practical note from M5: implementer subagents occasionally stalled, waiting on "background work"
that had already ended, without reporting. When one goes quiet, check the branch — a reviewer can
verify the commit directly rather than wait on the implementer's report, which the reviews are told
not to trust anyway.

Roughly a dozen genuine defects surfaced this way, and **almost every one originated in the plan
rather than in the implementation.** Two techniques did most of the work:

**Mutation testing.** Delete the line a test claims to cover, in a scratch copy, and confirm the test
fails. This caught a key-rotation test that would have passed against a decoder with refresh-on-miss
removed, and an anti-spoofing suite where four of five tests still passed with the strip filter deleted
entirely. In M5 it caught a shared-tenant test that sent every user through one client, and so could not
tell a tenant's bucket from a client's. In M6 all ten mutations were caught, one of them — the
revocation `detail` leaking onto M3's 503 — by an assertion M6 added to M3's test; before the sweep, a
dead-Redis timing test was found timing an already-open breaker, and passed a mutation that delayed
every refusal by 1.5 s. In M7 fourteen mutations were run, the bulkhead one in two variants, and all
were caught but one: 6a, removing `ignoreExceptions(BulkheadFullException)` alone. It was recorded as
surviving by design, the record predicate taken for a second guard. The final review found it was not
one: without the explicit ignore, a refusal was neither recorded nor ignored, so it counted as a
success, and no test looked at successes. The breaker now ignores every exception that is not an
availability failure, the tests pin success counts, and three more mutations were run: removing only the
new ignore predicate is caught by the CR/LF test (four successes, not none), the bulkhead test surviving
it; removing both ignores is caught by the bulkhead test (four successes, not two); and removing only
the explicit ignore survives by design, the two guards now genuinely equivalent. One mutation, counting
a 500 on an AuthCore route, is caught only by `ProductionValuesTest`, because the behavioural 500 test
exercises the ledger route.

M7's reviews found three defects, each fixed with a test that pins it:

- **The breaker counted every exception thrown inside the chain**, because Resilience4j records all of
  them unless told otherwise — so a caller's own bad request, a claim with CR/LF answered 401, counted
  against the downstream, and ten could have opened it for everyone. Fixed by `DownstreamFailures`
  and `recordException(DownstreamFailures::isAvailabilityFailure)`.
- **A caller's own error then counted as a success**, found in the final review: Resilience4j counts an
  exception it neither records nor ignores as a success, so the same 401s padded the window and, in
  half-open, could have closed the breaker without the downstream being reached; a bulkhead refusal
  would have too, without its explicit ignore. Fixed by an ignore predicate, everything that
  `DownstreamFailures.isAvailabilityFailure` does not match: a caller's own error is neutral. The CR/LF
  test pins no successes, the bulkhead test exactly two.
- **The JWKS logging judged a fetch by its status, not its body**, so a 200 carrying a login page was
  refused 503 by the decoder with nothing logged, and could even log "answered again".
  `JwksFetchLogging` now parses a 2xx body as a key set before calling it an answer.

**Running the thing.** Booting the service and hitting it with `curl` found what reading the diff
could not: a cross-tenant leak that the tests asserted was correct, a missing `WWW-Authenticate` on
two of three 401 paths, and a 403 branch that cannot occur in production at all. In M5 it found that
AuthCore itself hangs when Redis is down, and that a burst can be demonstrated only once each
gateway's cold path — its first JWKS fetch or introspection — has been paid. In M6 it found that
recovery from a Redis outage waits on Lettuce's reconnect backoff, more than three times the breaker's
window in that run, which nothing in the suite exercises. In M7 it found that AuthCore's own Redis
client backs off the same way, and that Reactor Netty logs a WARN on every timed-out key-set fetch.

A test that passes the moment you write it has proven nothing yet. Make it fail first, on purpose.
