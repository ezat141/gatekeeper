# GateKeeper M3–M6 — Handoff

Written at the close of M0–M2 so the next session starts productive rather than rediscovering what
this one learned by failing, and kept current through M5. Read this before touching code.

---

## 1. Where things stand

**M0–M5 are complete.** M0–M2 was verified against three live services; M3 (API-key authentication)
landed across AuthCore and GateKeeper with its own spec and plan, dated 2026-08-24; M4 (route-to-scope
authorization and the tenant check) was a GateKeeper-only milestone, spec and plan dated 2026-09-26,
verified by mutation and against the three live services. M5 (distributed rate limiting and daily
quotas) was GateKeeper-only too, spec and plan dated 2026-09-27, verified by mutation and by two
gateway processes against the live platform and one shared Redis.

| Repo | `master` | Tests | Visibility |
|---|---|---|---|
| [authcore](https://github.com/ezat141/authcore) | `4f0a228` | 78 | public |
| [ledger-service](https://github.com/ezat141/ledger-service) | `3cd3738` | 26 | public |
| [gatekeeper](https://github.com/ezat141/gatekeeper) | `4f54b9f` — M5's last code merge; the merge of M5's documentation follows it | 233 | public |

All three clean, and all three counts confirmed by running the suites. AuthCore and ledger-service
were not changed by M4 or M5. AuthCore's run takes over ten minutes — every test class starts its own
Spring context against Testcontainers, at roughly 45 seconds each — so give it a generous timeout or
run it in the background rather than assume it has hung.

**GateKeeper's suite requires Redis.** Without it (measured with `-Dspring.data.redis.port=1`), the run
reports `Tests run: 231, Failures: 25, Errors: 17`: 41 tests fail on Redis connection failures, and
`TwoGatewaysShareOneLimitTest` fails in its setup, reported as one failure in place of its three
tests — 44 of 233 not passing, up from 23 before M5. It reads like a regression and is not one. Start
Redis first: `docker compose up -d redis` from the authcore directory.

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
`X-RateLimit-*` and `X-Quota-*` headers, which allowed responses carry too. A Redis failure **fails open** within 200 ms:
a single-flight connection off the event loop, a warm-up before the port binds, and a five-second
circuit breaker keep it from hanging or leaking connections. The M5 design
(`specs/2026-09-27-gatekeeper-m5-design.md`) is the reference, section 7 especially.

**Next: M6 — the revocation check.** It reads the same Redis M5 does, and must decide the opposite way:
a failure to answer must **refuse**, because a revoked token getting through is a security failure,
where an unlimited request is only a capacity one. It must also refuse **fast**. AuthCore itself shows
what happens otherwise: with Redis stopped in M5's run, AuthCore's routes hung about 60 seconds before
answering, and a direct call got no answer in 15. Read the M5 design, section 7, before designing it:
why M5 failed open, and how it avoided hanging — Lettuce's first connection blocks inside
`subscribe()` before any timeout's clock starts, cancelling that wait leaks a connection per request,
and Lettuce buffers commands without bound while disconnected. A fail-closed check needs the same
single-flight connection and bounded wait, or it turns a Redis outage into a hung gateway rather than
a prompt refusal; which status that refusal carries is M6's to decide. If M6 uses a circuit breaker,
an open breaker must mean *refuse*, not *skip the check*: copying the limiter's pattern would silently
fail open. The contract is in §4 below. Any endpoint M6 adds needs its own row in
`RouteScopeAuthorizationManager`, or it is refused `NO_RULE`.

Design and plan documents are in `docs/superpowers/specs/` and `docs/superpowers/plans/`. Milestone
scope for M3–M10 is in `GateKeeper-Implementation-Plan.md`, two levels up.

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
- **Never add a `Co-Authored-By` line.** Standing preference: it keeps Claude out of the contributors graph.
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

## 4. What M3–M6 build

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
refuse, not admit — the opposite of M5's choice, and deliberately so (§1).

---

## 5. Deferred items these milestones inherit

Found during M0–M5 and recorded rather than fixed. Each names the milestone that owns it, or says it
has none.

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
- **M7 — the JWKS fetch has no response timeout.** Spring Security's `ReactiveRemoteJWKSource` builds
  a bare `WebClient.create()`, so a host that accepts the connection and never answers hangs the
  request rather than failing closed. An active refusal is handled; a silent hang is not.
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
- **Whoever next touches the API-key path — M3's cache on a Redis outage.** It uses the same template
  as the limiter, without the limiter's protections. Observed in the M5 run: an API-key caller hung
  with Redis stopped, waiting in Lettuce's disconnected buffer up to the command timeout. And a Redis
  that accepts connections and never answers could block an event loop on the cache's first
  connection, for up to Lettuce's 60-second handshake timeout (M5 design, section 7).
- **Unowned — Lettuce buffers commands without bound while disconnected.** M5's circuit breaker bounds
  the limiter's share to about one command per five-second window. The client-wide fix
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
  them today; setting the headers in `beforeCommit` would fix it.
- **Unowned — the warm-up's timeout (2 s) and the breaker's window (5 s) are constants, not
  properties**, and the warm-up does not run under lazy initialisation.
- **Anyone deploying — rate-limit assignment keys cannot be set through environment variables.**
  Relaxed binding lowercases an environment variable and splits it on underscores, so a name like
  `demo-reporting-job` cannot be expressed. Use a mounted configuration file or
  `SPRING_APPLICATION_JSON`.

---

## 6. How M0–M2 was run, and why it is worth repeating

Every task got a `feature/task-N` branch off `master`, merged back with `git merge --no-ff` so the
topology stays visible on GitHub. Two reviews per task — spec compliance first, then code quality —
each by an independent agent explicitly told **not to trust the implementer's report**, followed by
fix-and-re-review loops until clean. M4 used `feature/m4-task-N` because the `feature/task-N` names
from M0–M3 still exist, and M5 used `feature/m5-task-N`; M6 should use `feature/m6-task-N`.

One practical note from M5: implementer subagents occasionally stalled, waiting on "background work"
that had already ended, without reporting. When one goes quiet, check the branch — a reviewer can
verify the commit directly rather than wait on the implementer's report, which the reviews are told
not to trust anyway.

Roughly a dozen genuine defects surfaced this way, and **almost every one originated in the plan
rather than in the implementation.** Two techniques did most of the work:

**Mutation testing.** Delete the line a test claims to cover, in a scratch copy, and confirm the test
fails. This caught a key-rotation test that would have passed against a decoder with refresh-on-miss
removed, and an anti-spoofing suite where four of five tests still passed with the strip filter
deleted entirely. In M5 it caught a shared-tenant test that sent every user through one client, and so
could not tell a tenant's bucket from a client's.

**Running the thing.** Booting the service and hitting it with `curl` found what reading the diff
could not: a cross-tenant leak that the tests asserted was correct, a missing `WWW-Authenticate` on
two of three 401 paths, and a 403 branch that cannot occur in production at all. In M5 it found that
AuthCore itself hangs when Redis is down, and that a burst can be demonstrated only once each
gateway's cold path — its first JWKS fetch or introspection — has been paid.

A test that passes the moment you write it has proven nothing yet. Make it fail first, on purpose.
