# GateKeeper M3–M6 — Handoff

Written at the close of M0–M2 so the next session starts productive rather than rediscovering what
this one learned by failing, and kept current through M4. Read this before touching code.

---

## 1. Where things stand

**M0–M4 are complete.** M0–M2 was verified against three live services; M3 (API-key authentication)
landed across AuthCore and GateKeeper with its own spec and plan, dated 2026-08-24; M4 (route-to-scope
authorization and the tenant check) was a GateKeeper-only milestone, spec and plan dated 2026-09-26,
verified by mutation and against the three live services.

| Repo | `master` | Tests | Visibility |
|---|---|---|---|
| [authcore](https://github.com/ezat141/authcore) | `4f0a228` | 78 | public |
| [ledger-service](https://github.com/ezat141/ledger-service) | `3cd3738` | 26 | public |
| [gatekeeper](https://github.com/ezat141/gatekeeper) | `106c3db` is the last code merge; M4's documentation was merged after it | 151 | public |

All three clean, and all three counts confirmed by running the suites. AuthCore and ledger-service
were not changed by M4. AuthCore's run takes over ten minutes — every test class starts its own
Spring context against Testcontainers, at roughly 45 seconds each — so give it a generous timeout or
run it in the background rather than assume it has hung.

**GateKeeper's suite requires Redis.** Without it, 19 tests fail and 4 error on Redis connection
failures, which reads like a regression and is not one. Start it first: `docker compose up -d redis`
from the authcore directory.

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

**Next: M5.** Read the M4 design before designing it, sections 4 and 5 especially. Rate limiting keyed
by tenant or client inherits M4's picture of who carries what: a user token has a `tenant`, while a
client-credentials token and every API key have none, so a tenant key needs a rule for tenant-less
callers — the same question M4 had to answer for its tenant check. Keying by client means reading the
token's `aud` (Spring Authorization Server's default: the client id; access tokens carry no
`client_id` claim). The README's audience rationale is safe only while the gateway never decides by
client identity — per-client rate limiting is exactly that, so decide audience validation in the M5
design. Any endpoint M5 adds needs its own row in `RouteScopeAuthorizationManager`, or it is refused
`NO_RULE`.

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
  most distinctive property of the project.
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
daily quota counter with a TTL. `429` with `Retry-After`.

**M6 — Revocation check.** A reactive `EXISTS` against AuthCore's deny-list. The contract is already
live: `RevocationService` writes Redis key **`authcore:revoked:jti:<jti>`**, value `"revoked"`, with a
TTL equal to the token's remaining lifetime. Revoked means `401`.

---

## 5. Deferred items these milestones inherit

Found during M0–M4 and recorded rather than fixed. Each names the milestone that owns it, or says it
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
  the gateway could also refuse tokens that carry no `scope`, if wanted.
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

---

## 6. How M0–M2 was run, and why it is worth repeating

Every task got a `feature/task-N` branch off `master`, merged back with `git merge --no-ff` so the
topology stays visible on GitHub. Two reviews per task — spec compliance first, then code quality —
each by an independent agent explicitly told **not to trust the implementer's report**, followed by
fix-and-re-review loops until clean. M4 used `feature/m4-task-N` because the `feature/task-N` names
from M0–M3 still exist; M5 should use `feature/m5-task-N`.

Roughly a dozen genuine defects surfaced this way, and **almost every one originated in the plan
rather than in the implementation.** Two techniques did most of the work:

**Mutation testing.** Delete the line a test claims to cover, in a scratch copy, and confirm the test
fails. This caught a key-rotation test that would have passed against a decoder with refresh-on-miss
removed, and an anti-spoofing suite where four of five tests still passed with the strip filter
deleted entirely.

**Running the thing.** Booting the service and hitting it with `curl` found what reading the diff
could not: a cross-tenant leak that the tests asserted was correct, a missing `WWW-Authenticate` on
two of three 401 paths, and a 403 branch that cannot occur in production at all.

A test that passes the moment you write it has proven nothing yet. Make it fail first, on purpose.
