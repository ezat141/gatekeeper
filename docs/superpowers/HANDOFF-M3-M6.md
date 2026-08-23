# GateKeeper M3–M6 — Handoff

Written at the close of M0–M2 so the next session starts productive rather than rediscovering what
this one learned by failing. Read this before touching code.

---

## 1. Where things stand

M0–M2 is complete, and was verified against three live services rather than only against stubs.

| Repo | `master` | Tests | Visibility |
|---|---|---|---|
| [authcore](https://github.com/ezat141/authcore) | `3a8aceb` | 65 | public |
| [ledger-service](https://github.com/ezat141/ledger-service) | `3c32b32` | 26 | public |
| [gatekeeper](https://github.com/ezat141/gatekeeper) | `4d29912` | 24 | public |

All three clean and synced with their remotes.

**GateKeeper today:** three routes (`/api/accounts/**` and `/api/machine/**` to AuthCore with the path
preserved, `/api/ledger/**` to ledger-service with `StripPrefix=1`); JWT authentication against
AuthCore's JWKS with the issuer pinned; inbound `X-GK-*` stripped before authentication and re-stamped
from verified claims afterwards; one JSON error shape. **No authorization beyond
`anyExchange().authenticated()`** — that is M4's job.

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

The seam already exists in AuthCore: table `api_keys`, where `key_hash` is **SHA-256 hex** — not
bcrypt, because this is a per-request lookup rather than a password — with comma-separated `scopes`,
`enabled`, and `expires_at`. Keys carry an `ak_` prefix so a leaked one is greppable. Seeded demo key:
`ak_demo_reporting_job_local_only_0000000000`, scope `payments:read`.

Note GateKeeper is **stateless and owns no database**; reaching Postgres directly would break that
property. Prefer a reactive Redis cache or a call to AuthCore, decide deliberately, and record why.

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
