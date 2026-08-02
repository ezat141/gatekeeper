# GateKeeper M0–M2 — Design

**Zero-Trust API Gateway & Access-Governance Edge**
Date: 2026-08-02 · Status: approved, ready for planning

---

## 1. Purpose

GateKeeper is the **enforcer** half of a two-service platform whose **issuer** half is
[AuthCore](../../../../authcore). AuthCore decides who a caller is and what they may do, and mints a
signed JWT saying so. GateKeeper checks that assertion on every request, at the edge, before traffic
reaches any service.

This document covers **M0–M2 only**: a running reverse proxy that authenticates AuthCore-issued JWTs
and propagates a trustworthy identity downstream. Later milestones are listed in §11 and are out of
scope.

---

## 2. Relationship to AuthCore

The two services share **no code and no database**. They are coupled only by a wire contract, which
is what makes the pairing meaningful rather than cosmetic. All four seams already exist in AuthCore
today.

| Seam | AuthCore side | GateKeeper side | Used in M0–M2? |
|---|---|---|---|
| Signature trust | `GET /oauth2/jwks` — multiple keys, `kid`-addressed, rotation-aware (AuthCore M7) | `NimbusReactiveJwtDecoder.withJwkSetUri(...)` | **Yes** |
| Claim vocabulary | `AuthCoreTokenCustomizer` stamps `tenant`, `roles`, `permissions` | read from the verified `Jwt` | **Yes** (propagated; not yet enforced) |
| Revocation | `RevocationService` writes Redis `authcore:revoked:jti:<jti>`, TTL = token's remaining life | reactive `EXISTS` on the same key | No — M6 |
| API keys | `api_keys` table; SHA-256 hex `key_hash`, `ak_` prefix, comma-separated `scopes` | same lookup, reactive | No — M3 |

### Claims AuthCore actually emits on an access token

Standard: `iss`, `sub`, `aud`, `exp`, `iat`, `nbf`, `jti`, `scope`.
Custom: `tenant` (slug), `roles` (e.g. `ROLE_ADMIN`), `permissions` (e.g. `payments:read`,
`accounts:read:all`).

`roles`/`permissions`/`tenant` are **absent** on client-credentials tokens — there is no user behind
them, and AuthCore deliberately omits the claims rather than emitting empty arrays. GateKeeper must
treat them as optional, not assume presence.

### Defense in depth

GateKeeper rejects unauthenticated traffic at the edge. AuthCore's own `/api/**` filter chain still
independently re-validates the token, the tenant, and the required permission. Neither service takes
the other's word. This is the property the platform is meant to demonstrate, and it is why the
primary downstream is AuthCore's real protected API rather than a mock.

---

## 3. Stack

| Component | Version | Note |
|---|---|---|
| Java | 21 | matches AuthCore |
| Spring Boot | **4.0.7** | see below |
| Spring Cloud BOM | **2025.1.2** | ships Spring Cloud Gateway 5.0.2 |
| Gateway starter | `spring-cloud-starter-gateway-server-webflux` | renamed in SCG 5.x — **not** `spring-cloud-starter-gateway` |
| Build | Maven | matches AuthCore |

**Why not Boot 4.1.0 to match AuthCore.** Spring Cloud Gateway 5.0.2 is built and tested against
Boot 4.0.7. AuthCore runs 4.1.0, one minor ahead. Since GateKeeper couples to AuthCore only over
HTTP and Redis keys, the Boot versions need not match, and running the officially tested combination
removes a class of hard-to-debug reactive failures. Independently versioned services is also how
real estates work.

### The reactive constraint

Spring Cloud Gateway runs on Netty/WebFlux. **No blocking call may appear in any filter.** Servlet
habits that are wrong here: `SecurityFilterChain` (use `SecurityWebFilterChain`),
`OncePerRequestFilter` (use `GlobalFilter`/`WebFilter` returning `Mono<Void>`), `JwtDecoder` (use
`ReactiveJwtDecoder`), `RedisTemplate` (use `ReactiveStringRedisTemplate`), any `jdbcTemplate` call
inside a filter (pre-load or use R2DBC). This table goes in the README.

---

## 4. Architecture

```
client ──Bearer JWT──▶  GateKeeper :8081
                          │  1. strip inbound X-GK-*        (unconditional, pre-auth)
                          │  2. ReactiveJwtDecoder ──JWKS──▶ AuthCore :8080/oauth2/jwks
                          │  3. stamp X-GK-Subject / -Tenant / -Permissions from verified claims
                          │
                          ├── /api/accounts/**  ──▶ AuthCore :8080   ← re-checks independently
                          ├── /api/machine/**   ──▶ AuthCore :8080   ← re-checks independently
                          └── /echo/**          ──▶ echo stub :8082  ← reflects what was forwarded
```

**Ports:** AuthCore `8080` (unchanged), GateKeeper `8081`, echo stub `8082`.

**AuthCore is not modified in this milestone.** One deferred exception is recorded in §9.

---

## 5. Components

| Component | Responsibility | Depends on |
|---|---|---|
| `GateKeeperApplication` | boot entry point | — |
| `RouteConfig` (`application.yml`) | path predicates → downstream URIs, `StripPrefix` | — |
| `GatewaySecurityConfig` | `@EnableWebFluxSecurity`; public vs authenticated matchers; wires the decoder | `JwtDecoderConfig` |
| `JwtDecoderConfig` | builds `ReactiveJwtDecoder` from AuthCore's JWKS URI + pinned issuer validator | AuthCore JWKS |
| `IdentityHeaderFilter` (`GlobalFilter`) | strips inbound `X-GK-*`; stamps verified identity | Spring Security context |
| `GlobalErrorWebExceptionHandler` | uniform JSON errors matching AuthCore's shape | — |

Each is independently testable; the only cross-component contract is the `X-GK-*` header set.

---

## 6. Routing (M1)

| Path at gateway | Downstream | Filters | Rationale |
|---|---|---|---|
| `/api/accounts/**` | `http://localhost:8080` | none | AuthCore serves this path verbatim |
| `/api/machine/**` | `http://localhost:8080` | none | AuthCore serves this path verbatim |
| `/echo/**` | `http://localhost:8082` | `StripPrefix=1` | stub should see a clean path |

Real AuthCore endpoints behind those routes, with the authorization each one applies:

| Endpoint | AuthCore's own requirement |
|---|---|
| `GET /api/accounts/me` | any authenticated user |
| `GET /api/accounts/{ownerId}` | `hasPermission(#ownerId, 'Account', 'read')` |
| `POST /api/accounts/{ownerId}/payments` | `hasAuthority('payments:write')` |
| `GET /api/accounts/admin/all` | `hasRole('ADMIN')` |
| `GET|POST /api/machine/payments` | client-credentials token or `X-API-Key` |

**M1 acceptance:** `curl :8081/api/accounts/me` reaches AuthCore and returns AuthCore's **401**.
That is the correct and expected result at M1 — it proves the proxy works before any gateway-side
authentication exists.

### Echo stub

`mendhak/http-https-echo` via `docker-compose.yml`, published on `8082`. It returns the full request
— including headers — as JSON, which is exactly what is needed to demonstrate identity propagation.
No Java module is written or maintained for this.

---

## 7. Authentication (M2)

- `@EnableWebFluxSecurity` with a single `SecurityWebFilterChain`.
- `NimbusReactiveJwtDecoder.withJwkSetUri("http://localhost:8080/oauth2/jwks")`.
- CSRF disabled (stateless, token-authenticated API edge); HTTP Basic and form login disabled.
- Authorization rules: `/actuator/health` permitted; **everything else** `.authenticated()`.
- Authorization *by scope or permission* is deliberately **not** implemented here — that is M4.
  M2 answers only "is this a valid, unexpired token from AuthCore".

### Issuer pinning

AuthCore does not set `issuer-uri`, so Spring Authorization Server derives the issuer from the
request host. A token obtained at `127.0.0.1:8080` carries `iss: http://127.0.0.1:8080`; one
obtained at `localhost:8080` carries `iss: http://localhost:8080`. These are different strings and a
validator will reject the mismatch — the same `localhost` ≠ `127.0.0.1` class of bug that previously
broke an AuthCore redirect.

**Decision for M0–M2:** GateKeeper pins the expected issuer to `http://localhost:8080` via
configuration (`gatekeeper.auth.issuer`), and all documented demo commands use `localhost`
consistently. Failing closed on a mismatch is correct behaviour, and the README states the cause so
the failure is diagnosable rather than mysterious.

### Identity propagation and header anti-spoofing

The gateway forwards three headers, derived **only** from verified claims:

| Header | Source claim | Absent when |
|---|---|---|
| `X-GK-Subject` | `sub` | never |
| `X-GK-Tenant` | `tenant` | client-credentials token |
| `X-GK-Permissions` | `permissions`, comma-joined | client-credentials token, or user has none |

"Inbound `X-GK-*`" means **every** request header whose name begins with `X-GK-`, matched
case-insensitively — not just the three listed above. A future header must not become spoofable
because the filter enumerated a fixed list.

Inbound `X-GK-*` headers are **stripped unconditionally** — on every route, including permitted ones
such as `/actuator/health`, and before authentication runs. Without that strip, any client could
send `X-GK-Tenant: acme`, and the moment a downstream trusts the header, cross-tenant access follows
for free. The strip is not conditional on authentication succeeding, because an unauthenticated
request must not be able to launder a header through an error path either.

Nothing downstream is *required* to trust these headers; AuthCore ignores them and re-derives
identity from the token itself. They exist so a downstream that is not itself an OAuth2 resource
server can still be told who the caller is.

---

## 8. Error handling

| Condition | Response |
|---|---|
| No / malformed / expired token | `401` + `WWW-Authenticate: Bearer error="invalid_token"` (RFC 6750), JSON body |
| Authenticated but not permitted | `403`, JSON body — **cannot occur in M2**; the handler exists so M4 has a landing place |
| Downstream unreachable or timed out | `503`, JSON body — never a raw Netty stack trace |
| JWKS fetch failure | `401` (fail closed), logged at `WARN` |

A single `GlobalErrorWebExceptionHandler` renders all of these as JSON matching AuthCore's existing
error shape, so a client sees one error format across the platform. Circuit breaking, retries and
fallbacks are **M7**, not here; M2 only guarantees the error is clean.

---

## 9. Deferred item that touches AuthCore

Pinning AuthCore's own `issuer-uri` in its `AuthorizationServerSettings` is the durable fix for the
host-mismatch problem in §7 — it makes the issuer deterministic regardless of which host name the
token was obtained through. It is **deliberately not done in this milestone** because M0–M2 is
scoped to leave AuthCore untouched. Revisit when GateKeeper first needs to accept tokens obtained
through a host other than `localhost`.

---

## 10. Testing

WireMock serves both the JWKS document and the downstream. No Testcontainers are needed until Redis
arrives at M5.

| # | Test | Asserts |
|---|---|---|
| 1 | Context loads | app starts on **Netty**, not Tomcat |
| 2 | Route forwarding | request reaches the WireMock downstream; `StripPrefix=1` applied on `/echo/**` only |
| 3 | No token | `401` with `WWW-Authenticate: Bearer` |
| 4 | Valid token | signed by the test key → `200`, request proxied |
| 5 | Expired token | `401` |
| 6 | **Header spoofing** | client sends `X-GK-Tenant: acme`; downstream receives the gateway's value, not the client's |
| 7 | **Key rotation** | JWKS serves two keys; a token signed with the newer one still → `200` |

Tests 6 and 7 are the two that would actually catch a regression that matters: 6 guards the trust
boundary, 7 guards the AuthCore integration.

---

## 11. Out of scope (later milestones)

M3 API-key authentication · M4 route→scope authorization + tenant enforcement · M5 distributed rate
limiting and per-plan quotas · M6 revocation check against AuthCore's Redis deny-list · M7
resilience (circuit breaker, timeout, retry, bulkhead) · M8 audit events to Kafka + observability ·
M9 dynamic route admin · M10 hardening, load test, CI/CD.

No work in M0–M2 may assume any of these exist.

---

## 12. Definition of done for M0–M2

- [ ] `mvn verify` green, all 7 tests passing
- [ ] `docker compose up` starts the echo stub; GateKeeper starts on Netty at `:8081`
- [ ] `curl :8081/echo/hello` with no token → `401`
- [ ] `curl :8081/echo/hello` with an AuthCore token → `200`, response JSON shows `x-gk-subject`,
      `x-gk-tenant`, `x-gk-permissions`
- [ ] `curl :8081/api/accounts/me` with an AuthCore token → `200` from AuthCore
- [ ] Client-supplied `X-GK-Tenant` is demonstrably overwritten
- [ ] Rotating AuthCore's signing key does not break a freshly issued token through the gateway
- [ ] README documents the reactive-rules table, the issuer-pinning trap, and the anti-spoofing rule
- [ ] Committed and pushed
