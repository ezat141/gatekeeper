# GateKeeper M3–M6 — Handoff

Written at the close of M0–M2 so the next session starts productive rather than rediscovering what
this one learned by failing. Read this before touching code.

---

## 1. Where things stand

**M0–M3 are complete.** M0–M2 was verified against three live services; M3 (API-key authentication)
landed across AuthCore and GateKeeper with its own spec and plan, dated 2026-08-24.

| Repo | `master` | Tests | Visibility |
|---|---|---|---|
| [authcore](https://github.com/ezat141/authcore) | `4f0a228` | 78 | public |
| [ledger-service](https://github.com/ezat141/ledger-service) | `3cd3738` | 26 | public |
| [gatekeeper](https://github.com/ezat141/gatekeeper) | `27b988d` | 70 | public |

All three clean, and all three counts confirmed by running the suites. AuthCore's run takes over ten
minutes — every test class starts its own Spring context against Testcontainers, at roughly 45 seconds
each — so give it a generous timeout or run it in the background rather than assume it has hung.

**GateKeeper's suite now requires Redis.** Without it, 15 tests fail and 4 error on
`RedisConnectionFailureException`, which reads like a regression and is not one. Start it first:
`docker compose up -d redis` from the authcore directory.

**GateKeeper today:** three routes (`/api/accounts/**` and `/api/machine/**` to AuthCore with the path
preserved, `/api/ledger/**` to ledger-service with `StripPrefix=1`). A caller authenticates with
**either** a bearer JWT, verified against AuthCore's JWKS with the issuer pinned, **or** an
`X-API-Key`, checked through AuthCore's introspection endpoint and cached in Redis. When AuthCore cannot
answer an introspection, the gateway says 503 rather than 401. Inbound `X-GK-*` headers are stripped
before authentication and re-stamped from verified identity afterwards, including the subject of a key
caller. One JSON error shape. **Still no authorization beyond `anyExchange().authenticated()`** — that
is M4's job, and M4 now has to answer for key callers as well as token callers.

**Next: M4.** Read §8 of the M3 spec, "Identity, tenant, and reach"
(`specs/2026-08-24-gatekeeper-m3-design.md`), before designing it — it records what an API-key
principal carries and what it may reach, and M4's scope rules have to read exactly that. The same
spec says outright that scope enforcement was left for M4.

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
a token whose `tenant` does not match the requested path. Deny is `403`.

**M5 — Distributed rate limiting.** `RedisRateLimiter` token bucket keyed by tenant or client, plus a
daily quota counter with a TTL. `429` with `Retry-After`.

**M6 — Revocation check.** A reactive `EXISTS` against AuthCore's deny-list. The contract is already
live: `RevocationService` writes Redis key **`authcore:revoked:jti:<jti>`**, value `"revoked"`, with a
TTL equal to the token's remaining lifetime. Revoked means `401`.

---

## 5. Deferred items these milestones inherit

Found during M0–M2 and recorded rather than fixed. Each names the milestone that owns it.

- **M4 — the 403 path still has the empty-body gap that 401 lost.** The default `accessDeniedHandler`
  commits its own response, exactly as the default authentication entry point did before Task 13.
  Unreachable today because no authorization rules exist; M4 makes it live. Wire a JSON access-denied
  handler reusing `ErrorBody`. ledger-service already has one whose shape is worth copying.
- **M4 — the two AuthCore routes are separate on purpose.** `authcore-accounts` and `authcore-machine`
  are distinct routes rather than one combined predicate specifically so a scope rule can attach to
  the machine route without forcing a hollow one onto the accounts route, whose real checks are
  argument-dependent and live in AuthCore's own `@PreAuthorize`.
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
fix-and-re-review loops until clean.

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
