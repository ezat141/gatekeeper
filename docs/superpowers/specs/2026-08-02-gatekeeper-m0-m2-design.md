# GateKeeper M0–M2 — Design

**Zero-Trust API Gateway & Access-Governance Edge**
Date: 2026-08-02 · Status: approved, ready for planning · Revision 2

---

## 1. Purpose

GateKeeper is the **enforcer** in a three-service platform:

| Service | Role | Repo |
|---|---|---|
| **AuthCore** | issuer — authenticates users, mints signed JWTs | `ProjectsCVs/authcore` (exists, M0–M7 shipped) |
| **GateKeeper** | enforcer — validates every request at the edge, routes it onward | `ProjectsCVs/gatekeeper` (this document) |
| **ledger-service** | resource — a protected downstream that trusts nothing | `ProjectsCVs/ledger-service` (new, this milestone) |

This document covers **M0–M2 only**: a running reverse proxy that authenticates AuthCore-issued JWTs
and propagates a trustworthy identity to a downstream service that independently re-validates it.
Later milestones are listed in §12 and are out of scope.

---

## 2. Responsibility matrix

The single most common misreading of this platform is that GateKeeper replaces the security in the
services behind it. It does not. Each service owns a distinct concern, and nothing takes another's
word for anything.

| Concern | AuthCore | GateKeeper | ledger-service |
|---|---|---|---|
| Authenticate a human (password, MFA) | **Owns** | never | never |
| Issue / refresh / revoke tokens | **Owns** | never | never |
| Hold the signing keys | **Owns** (private) | public half only, via JWKS | public half only, via JWKS |
| Publish JWKS | **Owns** | consumes | consumes |
| Decide a user's roles & permissions | **Owns** | never | never |
| Reject unauthenticated traffic at the edge | — | **Owns** | also does, independently |
| Route / rewrite paths to downstreams | — | **Owns** | — |
| Rate limiting, quotas (M5) | — | **Owns** | — |
| Revocation deny-list | **Owns** (writes) | reads (M6) | — |
| Propagate caller identity downstream | — | **Owns** (`X-GK-*`) | reads, but does not trust |
| Enforce business authorization on its own data | for its own `/api/**` | coarse, route-level (M4) | **Owns**, fine-grained |
| Own business data | — | never (stateless) | **Owns** |

Two rules fall out of this table, and both are deliberate:

1. **GateKeeper is stateless and owns no business data.** It can be killed and restarted at any
   time. Everything it needs is in the token or in Redis.
2. **ledger-service does not trust GateKeeper.** It re-validates the JWT signature against AuthCore's
   JWKS itself. If someone bypasses the gateway and calls it directly, it is still secure. The
   `X-GK-*` headers are *informational* — convenient, never authoritative.

---

## 3. Integration contract with AuthCore

The services share **no code and no database**. They are coupled only by a wire contract, which is
what makes the pairing meaningful rather than cosmetic. All four seams already exist in AuthCore.

| Seam | AuthCore side | Consumer side | Used in M0–M2? |
|---|---|---|---|
| Signature trust | `GET /oauth2/jwks` — multiple keys, `kid`-addressed, rotation-aware (AuthCore M7) | `NimbusReactiveJwtDecoder.withJwkSetUri(...)` (GateKeeper), `NimbusJwtDecoder` (ledger-service) | **Yes** |
| Claim vocabulary | `AuthCoreTokenCustomizer` stamps `tenant`, `roles`, `permissions` | read from the verified `Jwt` | **Yes** |
| Revocation | `RevocationService` writes Redis `authcore:revoked:jti:<jti>`, TTL = token's remaining life | reactive `EXISTS` on the same key | No — M6 |
| API keys | `api_keys` table; SHA-256 hex `key_hash`, `ak_` prefix, comma-separated `scopes` | same lookup, reactive | No — M3 |

### Claims AuthCore actually emits on an access token

Standard: `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, `scope`.
Custom: `tenant` (slug), `roles` (e.g. `ROLE_ADMIN`), `permissions` (e.g. `payments:read`,
`accounts:read:all`).

`roles`, `permissions` and `tenant` are **absent** on client-credentials tokens — there is no user
behind them, and AuthCore deliberately omits the claims rather than emitting empty arrays. Both
consumers must treat them as optional.

---

## 4. Request sequence

The full journey, from a client with no token to a response from a protected downstream.

```mermaid
sequenceDiagram
    autonumber
    actor C as Client
    participant A as AuthCore :8080<br/>(issuer)
    participant G as GateKeeper :8081<br/>(enforcer)
    participant L as ledger-service :8082<br/>(resource)

    Note over C,A: Phase 1 — obtain a token (GateKeeper is not involved)
    C->>A: POST /oauth2/token (code + PKCE verifier)
    A->>A: authenticate, load roles/permissions/tenant
    A-->>C: access_token (RS256, kid=K1)

    Note over C,L: Phase 2 — call a protected resource through the edge
    C->>G: GET /api/ledger/entries<br/>Authorization: Bearer …<br/>X-GK-Tenant: acme (spoof attempt)
    G->>G: strip ALL inbound X-GK-* headers
    G->>A: GET /oauth2/jwks (cached; refetched on unknown kid)
    A-->>G: {keys:[K1, K0]}
    G->>G: verify signature, exp, issuer

    alt token invalid, expired, or unknown kid
        G-->>C: 401 + WWW-Authenticate: Bearer error="invalid_token"
    else token valid
        G->>G: stamp X-GK-Subject / -Tenant / -Permissions<br/>from VERIFIED claims
        G->>L: GET /ledger/entries (StripPrefix=1)<br/>Authorization: Bearer … (forwarded)<br/>X-GK-*: gateway's values
        Note over L: does NOT trust X-GK-*
        L->>A: GET /oauth2/jwks (cached)
        A-->>L: {keys:[K1, K0]}
        L->>L: verify signature independently,<br/>derive identity from the token itself
        L-->>G: 200 {entries, identity}
        G-->>C: 200
    end
```

The two things this diagram is meant to make obvious: the spoofed `X-GK-Tenant` dies at **step 5**,
before authentication has even run, and ledger-service repeats the whole verification at **step 14**
rather than believing the gateway.

---

## 5. Stack

| Component | Version | Note |
|---|---|---|
| Java | 21 | all three services |
| GateKeeper — Spring Boot | **4.0.7** | see below |
| GateKeeper — Spring Cloud BOM | **2025.1.2** | ships Spring Cloud Gateway 5.0.2 |
| GateKeeper — gateway starter | `spring-cloud-starter-gateway-server-webflux` | renamed in SCG 5.x — **not** `spring-cloud-starter-gateway` |
| ledger-service — Spring Boot | **4.1.0** | matches AuthCore; no Spring Cloud dependency, so unconstrained |
| Build | Maven | matches AuthCore |

**Why GateKeeper is not on Boot 4.1.0.** Spring Cloud Gateway 5.0.2 is built and tested against Boot
4.0.7. AuthCore runs 4.1.0, one minor ahead. Since the services couple only over HTTP and Redis keys,
the Boot versions need not match, and running the officially tested combination removes a class of
hard-to-debug reactive failures. That ledger-service sits on 4.1.0 while GateKeeper sits on 4.0.7 is
itself the proof the coupling is contractual, not shared-JAR.

### The reactive constraint (GateKeeper only)

Spring Cloud Gateway runs on Netty/WebFlux. **No blocking call may appear in any filter.** Servlet
habits that are wrong there: `SecurityFilterChain` (use `SecurityWebFilterChain`),
`OncePerRequestFilter` (use `GlobalFilter`/`WebFilter` returning `Mono<Void>`), `JwtDecoder` (use
`ReactiveJwtDecoder`), `RedisTemplate` (use `ReactiveStringRedisTemplate`), any `jdbcTemplate` call
inside a filter (pre-load or use R2DBC). This table goes in the README.

**ledger-service is deliberately a normal servlet application.** It is an ordinary microservice, and
making it reactive would add difficulty without demonstrating anything the gateway does not already
demonstrate.

---

## 6. Architecture

```
client ──Bearer JWT──▶  GateKeeper :8081  (Netty / WebFlux, stateless)
                          │  1. strip inbound X-GK-*        (unconditional, pre-auth)
                          │  2. ReactiveJwtDecoder ──JWKS──▶ AuthCore :8080/oauth2/jwks
                          │  3. stamp X-GK-Subject / -Tenant / -Permissions from verified claims
                          │
                          ├── /api/accounts/**  ──────────────▶ AuthCore :8080      ← re-checks independently
                          ├── /api/machine/**   ──────────────▶ AuthCore :8080      ← re-checks independently
                          └── /api/ledger/**    ─StripPrefix=1─▶ ledger-service :8082 ← re-checks independently
```

**Ports:** AuthCore `8080` (unchanged), GateKeeper `8081`, ledger-service `8082`.

**AuthCore is not modified in this milestone.** One deferred exception is recorded in §10.

---

## 7. Components

### GateKeeper

| Component | Responsibility | Depends on |
|---|---|---|
| `GateKeeperApplication` | boot entry point | — |
| `RouteConfig` (`application.yml`) | path predicates → downstream URIs, `StripPrefix` | — |
| `GatewaySecurityConfig` | `@EnableWebFluxSecurity`; public vs authenticated matchers | `JwtDecoderConfig` |
| `JwtDecoderConfig` | `ReactiveJwtDecoder` from AuthCore's JWKS URI + pinned issuer validator | AuthCore JWKS |
| `IdentityHeaderFilter` (`GlobalFilter`) | strips inbound `X-GK-*`; stamps verified identity | Spring Security context |
| `GlobalErrorWebExceptionHandler` | uniform JSON errors matching AuthCore's shape | — |

### ledger-service

| Component | Responsibility | Depends on |
|---|---|---|
| `LedgerServiceApplication` | boot entry point | — |
| `ResourceServerConfig` | `spring-boot-starter-oauth2-resource-server`; JWKS URI + pinned issuer; method security enabled | AuthCore JWKS |
| `LedgerController` | the three endpoints in §8 | `LedgerRepository` |
| `LedgerRepository` | in-memory seeded entries — **no database in this milestone** | — |
| `AuthCoreAuthoritiesConverter` | maps `permissions` claim → `GrantedAuthority` so `@PreAuthorize` works | — |

`LedgerRepository` being in-memory is a scope decision, not an oversight: this milestone is about the
edge, and a Postgres dependency would add migration and Testcontainers work that proves nothing new.

---

## 8. Routing and endpoints

### GateKeeper routes (M1)

| Path at gateway | Downstream | Filters | Rationale |
|---|---|---|---|
| `/api/accounts/**` | `http://localhost:8080` | none | AuthCore serves this path verbatim |
| `/api/machine/**` | `http://localhost:8080` | none | AuthCore serves this path verbatim |
| `/api/ledger/**` | `http://localhost:8082` | `StripPrefix=1` | gateway namespaces downstreams under `/api`; the service itself serves `/ledger/**` |

Having `StripPrefix` on exactly one of three routes is what makes test 2 in §11 meaningful — it
must apply to the ledger route and must **not** apply to the AuthCore routes.

### AuthCore endpoints reachable through the gateway

| Endpoint | AuthCore's own requirement |
|---|---|
| `GET /api/accounts/me` | any authenticated user |
| `GET /api/accounts/{ownerId}` | `hasPermission(#ownerId, 'Account', 'read')` |
| `POST /api/accounts/{ownerId}/payments` | `hasAuthority('payments:write')` |
| `GET /api/accounts/admin/all` | `hasRole('ADMIN')` |
| `GET\|POST /api/machine/payments` | client-credentials token or `X-API-Key` |

**M1 acceptance:** `curl :8081/api/accounts/me` reaches AuthCore and returns AuthCore's **401**. That
is the correct and expected result at M1 — it proves the proxy works before any gateway-side
authentication exists.

### ledger-service endpoints

| Endpoint | Requirement | Purpose |
|---|---|---|
| `GET /ledger/entries` | authenticated, **scoped to the caller's `tenant` claim** | the ordinary case — returns only that tenant's entries |
| `POST /ledger/entries` | `hasAuthority('payments:write')` **and** a `tenant` claim | proves the service enforces permissions itself, independent of GateKeeper |
| `GET /ledger/whoami` | authenticated | **the demo endpoint** — see below |

`GET /ledger/whoami` returns both identities side by side:

```json
{
  "fromToken":   { "subject": "ezzat", "tenant": "acme", "permissions": ["payments:read"] },
  "fromHeaders": { "subject": "ezzat", "tenant": "acme", "permissions": ["payments:read"] },
  "match": true
}
```

**A tenant-less token cannot write either.** The read and write paths agree on what a missing
`tenant` claim means. A client-credentials caller holding `payments:write` is refused with `403`
rather than having its entry stored — because reads are tenant-scoped, an accepted write would
produce a row unreadable by every caller in the system including its own author. Returning `201` for
an operation whose result can never be observed is worse than refusing it.

**Known limitation — no input validation.** `NewEntryRequest` is unvalidated in M0–M2. A null or
absent `reference`, a null `amount`, a negative amount, an arbitrarily large amount, and a
non-ISO `currency` are all accepted, and a duplicate `reference` creates a second row. This is
deliberate scope, not an oversight: the milestone is about the edge, and closing it requires
`spring-boot-starter-validation` plus a decision about error shape. It is recorded in the
ledger-service README rather than silently carried.

**Tenant scoping is enforced here, not only at the edge.** The seeded entries span two tenants, and
`GET /ledger/entries` returns only those matching the caller's `tenant` claim. A client-credentials
token carries no `tenant` claim — AuthCore omits it when there is no user — and such a caller
therefore receives an empty list. Failing closed is the point: the wrong answer to "which tenant is
this?" must be *nothing*, never *everything*. GateKeeper's tenant rules (M4) are a coarse outer
layer; this is the authoritative check, and it still applies when the gateway is bypassed.

`fromToken` is derived by ledger-service verifying the JWT itself. `fromHeaders` is whatever
`X-GK-*` arrived. In normal operation they match. Call ledger-service directly on `:8082` with no
gateway in front and `fromHeaders` is empty while `fromToken` is populated — which demonstrates in
one response both that the headers are not authoritative and that the service is secure without the
gateway. This is the endpoint to open in an interview.

---

## 9. Authentication (M2)

### GateKeeper

- `@EnableWebFluxSecurity` with a single `SecurityWebFilterChain`.
- `NimbusReactiveJwtDecoder.withJwkSetUri("http://localhost:8080/oauth2/jwks")`.
- CSRF disabled (stateless, token-authenticated API edge); HTTP Basic and form login disabled.
- `/actuator/health` permitted; **everything else** `.authenticated()`.
- Authorization *by scope or permission* is deliberately **not** implemented at the gateway here —
  that is M4. M2 answers only "is this a valid, unexpired token from AuthCore".

### Issuer pinning

AuthCore does not set `issuer-uri`, so Spring Authorization Server derives the issuer from the
request host. A token obtained at `127.0.0.1:8080` carries `iss: http://127.0.0.1:8080`; one obtained
at `localhost:8080` carries `iss: http://localhost:8080`. These are different strings and a validator
rejects the mismatch — the same `localhost` ≠ `127.0.0.1` class of bug that previously broke an
AuthCore redirect.

**Decision for M0–M2:** both GateKeeper and ledger-service pin the expected issuer to
`http://localhost:8080` via configuration, and all documented demo commands use `localhost`
consistently. Failing closed on a mismatch is correct behaviour; the README states the cause so the
failure is diagnosable rather than mysterious.

### Identity propagation and header anti-spoofing

GateKeeper forwards three headers, derived **only** from verified claims:

| Header | Source claim | Absent when |
|---|---|---|
| `X-GK-Subject` | `sub` | never |
| `X-GK-Tenant` | `tenant` | client-credentials token |
| `X-GK-Permissions` | `permissions`, comma-joined | client-credentials token, or user has none |

"Inbound `X-GK-*`" means **every** request header whose name begins with `X-GK-`, matched
case-insensitively — not just the three above. A future header must not become spoofable because the
filter enumerated a fixed list.

Inbound `X-GK-*` headers are **stripped unconditionally** — on every route, including permitted ones
such as `/actuator/health`, and before authentication runs. Without that strip, any client could send
`X-GK-Tenant: acme`, and the moment a downstream trusts the header, cross-tenant access follows for
free. The strip is not conditional on authentication succeeding, because an unauthenticated request
must not be able to launder a header through an error path either.

The `Authorization` header is forwarded unchanged, which is what lets ledger-service re-verify.

---

## 10. Deferred item that touches AuthCore

Pinning AuthCore's own `issuer-uri` in its `AuthorizationServerSettings` is the durable fix for the
host-mismatch problem in §9 — it makes the issuer deterministic regardless of which host name the
token was obtained through. It is **deliberately not done in this milestone** because M0–M2 is scoped
to leave AuthCore untouched. Revisit when a token must be accepted that was obtained through a host
other than `localhost`.

---

## 11. Error handling

| Condition | Response |
|---|---|
| No / malformed / expired token | `401` + `WWW-Authenticate: Bearer error="invalid_token"` (RFC 6750), JSON body |
| **Bad signature or unknown `kid`** | `401`, same shape — never `500` |
| Authenticated but not permitted | `403`, JSON body — **cannot occur at the gateway in M2**; the handler exists so M4 has a landing place |
| Downstream unreachable or timed out | `503`, JSON body — never a raw Netty stack trace |
| JWKS fetch failure | `401` (fail closed), logged at `WARN` |

A single `GlobalErrorWebExceptionHandler` renders all of these as JSON matching AuthCore's existing
error shape, so a client sees one error format across the platform. Circuit breaking, retries and
fallbacks are **M7**, not here; M2 only guarantees the error is clean.

---

## 12. Testing

WireMock serves both the JWKS document and, where needed, a downstream. No Testcontainers are needed
until Redis arrives at M5.

### GateKeeper

| # | Test | Asserts |
|---|---|---|
| 1 | Context loads | app starts on **Netty**, not Tomcat |
| 2 | Route forwarding | request reaches the downstream; `StripPrefix=1` applied to `/api/ledger/**` and **not** to `/api/accounts/**` |
| 3 | No token | `401` with `WWW-Authenticate: Bearer` |
| 4 | Valid token | signed by the test key → `200`, proxied |
| 5 | Expired token | `401` |
| 6 | **Invalid signature** | token signed by a key **not** in the JWKS → `401`, not `500` |
| 7 | **Unknown `kid`** | header names a `kid` absent from the JWKS → `401` after a JWKS refetch attempt |
| 8 | **Header spoofing** | client sends `X-GK-Tenant: acme`; downstream receives the gateway's value, not the client's |
| 9 | **Key rotation** | JWKS serves two keys; a token signed with the newer one still → `200` |

Tests 6 and 7 are separated because they fail on different code paths: a bad signature over a *known*
key fails verification outright, whereas an unknown `kid` first triggers a JWKS refetch and only then
fails. Collapsing them would leave the refetch path untested.

### ledger-service

| # | Test | Asserts |
|---|---|---|
| 10 | Context loads | starts, endpoints mapped |
| 11 | No token, direct call | `401` — the service is secure without the gateway in front |
| 12 | Valid token, direct call | `200`; `whoami.fromToken` populated, `fromHeaders` empty |
| 13 | Missing permission | `POST /ledger/entries` without `payments:write` → `403` |
| 14 | **Header-only, no token** | request carrying `X-GK-Subject`/`-Tenant` but **no** `Authorization` → `401` |

Test 14 is the one that proves the second rule in §2: the service treats `X-GK-*` as informational,
so headers alone can never authenticate a caller. Tests 8 and 14 together close the spoofing hole
from both ends — the gateway overwrites the header, and the downstream would not have trusted it
anyway.

---

## 13. Out of scope (later milestones)

M3 API-key authentication · M4 route→scope authorization + tenant enforcement · M5 distributed rate
limiting and per-plan quotas · M6 revocation check against AuthCore's Redis deny-list · M7 resilience
(circuit breaker, timeout, retry, bulkhead) · M8 audit events to Kafka + observability · M9 dynamic
route admin · M10 hardening, load test, CI/CD.

No work in M0–M2 may assume any of these exist.

---

## 14. Definition of done for M0–M2

- [ ] `mvn verify` green in both repos; all 14 tests passing
- [ ] AuthCore on `:8080`, GateKeeper on Netty at `:8081`, ledger-service on `:8082`
- [ ] `curl :8081/api/ledger/entries` with no token → `401`
- [ ] `curl :8081/api/ledger/entries` with an AuthCore token → `200`
- [ ] `curl :8081/api/ledger/whoami` with a token → `fromToken` and `fromHeaders` both populated and matching
- [ ] `curl :8082/ledger/whoami` **direct, bypassing the gateway** → `200`, `fromHeaders` empty — the service stands alone
- [ ] `curl :8082/ledger/whoami` with only `X-GK-*` headers and no token → `401`
- [ ] `curl :8081/api/accounts/me` with an AuthCore token → `200` from AuthCore
- [ ] Client-supplied `X-GK-Tenant` is demonstrably overwritten
- [ ] Rotating AuthCore's signing key does not break a freshly issued token through the gateway
- [ ] Both READMEs document the reactive-rules table, the issuer-pinning trap, the anti-spoofing rule,
      and the responsibility matrix from §2
- [ ] Both repos committed and pushed
