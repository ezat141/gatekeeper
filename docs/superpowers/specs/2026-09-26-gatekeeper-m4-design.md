# GateKeeper M4 — Route-to-scope authorization and tenant check — Design

Until now the gateway has decided only *whether the caller is who they claim*. Every authenticated
caller reaches every route, because the whole authorization model is `anyExchange().authenticated()`.
M4 makes the gateway decide *what the caller may reach*, for bearer-token and API-key callers alike,
and refuses with `403` in the platform's JSON error shape.

This is a **single-repo milestone**. AuthCore and ledger-service are unchanged; every rule below is
written against what they already expose.

---

## 1. Purpose

Authorization at the edge as defence in depth. A request the downstream would refuse anyway is refused
one hop earlier, and a request the downstream has no way to refuse — a client application acting beyond
what it was granted — is refused where the grant is visible.

The gateway's authorization is **coarse and route-level**, exactly as the responsibility matrix in the
M0–M2 design has always said. Fine-grained, argument-dependent decisions stay with the service that
owns the data.

---

## 2. What the downstreams already enforce

The rules below are only defensible against what already exists, so it is recorded first.

| Downstream | Endpoint | Its own check |
|---|---|---|
| AuthCore | `GET /api/machine/**` | `SCOPE_payments:read` (URL rule) |
| AuthCore | `POST /api/machine/**` | `SCOPE_payments:write` (URL rule) |
| AuthCore | `GET /api/accounts/me` | authenticated |
| AuthCore | `GET /api/accounts/{ownerId}` | `hasPermission(#ownerId, 'Account', 'read')` |
| AuthCore | `POST /api/accounts/{ownerId}/payments` | `hasAuthority('payments:write')` — a permission |
| AuthCore | `GET /api/accounts/admin/all` | `hasRole('ADMIN')` |
| ledger-service | `GET /ledger/entries` | authenticated; results filtered by the token's `tenant` |
| ledger-service | `POST /ledger/entries` | `hasAuthority('payments:write')` — a permission — plus a `tenant` claim |
| ledger-service | `GET /ledger/whoami` | authenticated |

AuthCore additionally wraps every `/api/**` rule in `TenantAuthorizationManager`, which compares a
JWT's `tenant` claim with the tenant the request resolved to and returns `403` on a mismatch. A caller
with no `tenant` claim — a client-credentials token or an API key — is never tenant-checked there.

Two vocabularies are in play and must not be confused:

- **Scope** (`SCOPE_payments:read`) — what the *client application* was granted on the user's behalf.
  Present on every token and on every API key.
- **Permission** (`payments:write`) — what the *user* may do. Present only on user tokens, derived
  from roles.

The gateway today derives only `SCOPE_*` authorities from a JWT (Spring's default converter), and M3
made API-key scopes the same `SCOPE_*` shape. M4 keeps it that way: **the edge checks scope, the
downstream checks permission.** Each check is made where the information that justifies it lives.

---

## 3. Decision: no path carries a tenant

The implementation plan asks M4 to refuse "a token whose tenant does not match the requested path". No
routed endpoint has a tenant in its path, so that sentence has nothing to match against as written.

- **ledger-service** reads the tenant only from the token and filters by it. A cross-tenant read
  through ledger cannot be expressed.
- **AuthCore** resolves the requested tenant from the subdomain, then the `X-Tenant` header, then the
  `tenant` request parameter, falling back to `default`. GateKeeper forwards `X-Tenant` unchanged, so
  on the AuthCore routes the client *does* name a tenant — in a header or the query string, not the
  path.

Three readings were considered.

**Chosen — refuse explicit mismatches only.** Every tenant the request names must equal the token's
`tenant`; a request naming none passes. Stricter than AuthCore where it acts, and it needs to know
neither which tenants exist nor the order in which AuthCore consults its sources.

**Rejected — also mirror AuthCore's `default` fallback.** A request naming no tenant would be treated
as naming `default`, so an `acme` token without `X-Tenant` would be refused at the edge exactly as
AuthCore refuses it. Faithful, but it copies an AuthCore resolution rule into the gateway, where it
would silently go stale the day AuthCore changes it.

**Rejected — stamp instead of check.** Overwrite `X-Tenant` from the token and strip it for tenant-less
callers, so a cross-tenant request cannot be expressed at all. Kinder to `acme` users, who would stop
having to send `X-Tenant`, but it rewrites the request instead of refusing it, and there would be no
`403` — which fails the plan's own acceptance criterion.

---

## 4. The rule table

`RouteScopeAuthorizationManager` evaluates these in order; the first match decides. The health
`permitAll` stays in `GatewaySecurityConfig`, ahead of the manager, and never reaches it.

| Path | Method | Requirement |
|---|---|---|
| `/actuator/info` | `GET` | authenticated (unchanged) |
| `/api/accounts/**` | any | authenticated |
| `/api/machine/**` | `GET` | `SCOPE_payments:read` |
| `/api/machine/**` | `POST` | `SCOPE_payments:write` |
| `/api/ledger/**` | `GET` | JWT principal **and** `SCOPE_payments:read` |
| `/api/ledger/**` | `POST` | JWT principal **and** `SCOPE_payments:write` |
| any | any | **deny** (`NO_RULE`) |

**accounts — authenticated only, deliberately.** Its real checks are argument-dependent and live in
AuthCore's `@PreAuthorize`. Any method passes, because AuthCore decides per endpoint. This is why
`authcore-accounts` and `authcore-machine` are separate routes: a scope rule attaches to the machine
route without forcing a hollow one onto accounts. An API-key caller authenticates here, as §8 of the
M3 design states.

**machine — mirrors AuthCore's own two rules.** Defence in depth: the edge refuses what AuthCore would
refuse, one hop earlier. One `SCOPE_*` authority covers a client-credentials token and an API key with
no branching on mechanism — the composability property M3 was built to provide.

**ledger — JWT principal and scope.** "JWT principal" means the `Authentication` is a
`JwtAuthenticationToken`. ledger-service is a JWT-only resource server, so an API-key caller could only
ever receive its `401`; the gateway refuses that caller with `403` instead (§6). Reads require
`payments:read` and writes `payments:write`, as *scopes*.

**Deny by default.** A request no rule matches is refused. A route added later without a rule fails
closed rather than open to every authenticated caller.

### Consequences, stated rather than discovered

- **HEAD, PUT, DELETE and OPTIONS on machine and ledger are refused at the edge**, because no
  downstream serves them there. No CORS is configured today, so refusing OPTIONS costs nothing now; a
  browser client would need a preflight rule of its own.
- **Users of `authcore-spa` become read-only on ledger through the gateway.** That client can only
  ever be granted `payments:read`, yet today an ADMIN signed in through it can write ledger entries
  because ledger checks only the user's permission. The edge now enforces what the client was actually
  granted. This is the intended change, not a regression.
- **A client-credentials token bearing `payments:write` passes the edge on a ledger `POST`, and ledger
  then refuses it** — the token carries no permissions. That is the division of labour working: the
  edge checks the client's grant, ledger checks the user's.
- **`GET /api/ledger/whoami` now requires `SCOPE_payments:read`.** A token with only `openid profile`
  is refused there. Accepted: it sits in the payments service's space.
- **An authenticated caller's typo yields `403`, not `404`.** Less helpful, and the price of failing
  closed.
- **Order is load-bearing.** A future rule inserted above an overlapping one silently shadows it. The
  tests pin the whole table, row by row, so a reordering that changes an outcome fails.

---

## 5. The tenant check

`TenantAuthorizationManager` wraps `RouteScopeAuthorizationManager`, mirroring AuthCore's class of the
same name, so no individual rule can forget it.

1. **The rule table decides first.** A deny is returned unchanged, so a missing scope reads as a
   missing scope and is never masked by a tenant message.
2. **The token's tenant** is read only from a `JwtAuthenticationToken`'s `tenant` claim. Absent — a
   client-credentials token, or any API key — the table's grant stands. This is the single rule for
   tenant-less principals that §8 of the M3 design anticipated: API keys are not special-cased.
3. **The requested tenants** are every `X-Tenant` header value and every `tenant` query value, the
   latter URL-decoded (`?tenant=ac%6De` is `acme`).
4. **Each must equal the token's tenant exactly**, or the result is `403` with reason
   `TENANT_MISMATCH`. A request naming no tenant passes.

**Exact comparison, and what it means at the edges:**

- **Case-sensitive.** `ACME` is not `acme`. AuthCore compares with `equals`; the gateway does the same.
- **Values are compared raw, never split.** `X-Tenant: acme,default` is one value and is refused. It
  cannot smuggle a second tenant past the check.
- **A blank value is a named tenant and is refused.** AuthCore would ignore a blank, so this is
  stricter, but "every name must match" admits no exceptions, and a blank is never legitimate.

**Deliberately not inspected:**

- **The subdomain.** Spring Cloud Gateway replaces the client's `Host` with the downstream's unless a
  route adds `PreserveHostHeader`, and none does, so a client's subdomain never reaches AuthCore. This
  is an assumption until the run in §9 confirms it.
- **The request body.** AuthCore's `TenantResolutionFilter` reads the parameter through servlet
  `getParameter` (`TenantResolutionFilter.java:64`), which also parses a form-encoded POST body. The
  gateway does not read bodies at authorization time, so a tenant named in a form body passes the edge.
  **It is not an escalation**: AuthCore's own check compares whatever it resolved with the token and
  refuses a mismatch. The edge check is defence in depth; AuthCore remains the authority for its data.

**Consequence to document:** an `acme` user must still send `X-Tenant: acme` to reach AuthCore, which
otherwise falls back to `default` and refuses. The gateway does not fix this for them — that was the
rejected stamping design in §3.

---

## 6. Stripping `X-API-Key` from ledger

M3 deferred this to M4 (M3 design §13): forwarding a credential to a service that can do nothing with it
widens exposure for no benefit. The ledger route gains:

```yaml
filters:
  - StripPrefix=1
  - RemoveRequestHeader=X-API-Key
```

After §4 a key caller never reaches ledger at all. What remains is a JWT caller sending a *blank*
`X-API-Key`, which the precedence rules of M3 §7 route to the JWT path and which would otherwise be
forwarded. One line of YAML closes the deferred item exactly.

The AuthCore routes keep the header: AuthCore re-authenticates the key itself, and that is how an
API-key caller works end-to-end on `/api/machine/**`.

---

## 7. The 403 response

`JsonServerAccessDeniedHandler` closes the gap recorded in the handoff (§5): the default handler commits
an empty body, exactly as the default entry point did before M2 replaced it.

- It writes `ErrorBody` through the same `ServerCodecConfigurer` writers as
  `JsonServerAuthenticationEntryPoint` — one write path for one shape.
- **It sets no `WWW-Authenticate` on a `403`.** ledger-service's handler already states this as the
  platform contract, and the two must agree.

**It is wired once, through `exceptionHandling().accessDeniedHandler(...)`, and that one wiring covers
both kinds of caller.** Without it, the resource server's `BearerTokenServerAccessDeniedHandler` would
answer for bearer requests with an empty body and `WWW-Authenticate: Bearer
error="insufficient_scope"` — escaping the shape, and calling a tenant mismatch an insufficient scope,
which is false.

An earlier draft of this section said the handler also had to be set on
`oauth2ResourceServer().accessDeniedHandler(...)`. The 7.0.6 bytecode says otherwise:
`ServerHttpSecurity.getAccessDeniedHandler()` returns the explicitly configured handler whenever one is
set, and consults the per-mechanism defaults — the resource server's among them — only when none is.
Setting it in the second place would be dead configuration, and a mutation test removing it could
never fail. Both a JWT caller and a key caller are still tested, because the single wiring has to be
shown to reach both.

**`ErrorBody` gains `of(status, path, detail)`**, the overload ledger-service already has. A `403`
carries one of four fixed strings authored by the gateway, never an exception message:

| Reason | `detail` |
|---|---|
| `MISSING_SCOPE` | `the credential does not carry the scope this route requires` |
| `API_KEY_NOT_ACCEPTED` | `this route does not accept API keys` |
| `TENANT_MISMATCH` | `the request names a tenant other than the token's` |
| `NO_RULE` | `no rule permits this method and path` |

`401` bodies are unchanged: no `detail`, `WWW-Authenticate: Bearer`.

### How the reason reaches the handler

This is the one place the design had to be shaped around the framework, verified against the Spring
Security 7.0.6 jars rather than remembered.

- `ReactiveAuthorizationManager.verify()`'s default turns every deny into
  `new AccessDeniedException("Access Denied")`. The `AuthorizationResult` is discarded.
- `authorizeExchange` wraps every configured manager in `DelegatingReactiveAuthorizationManager`, which
  is `final` and calls only `authorize()` on its delegates. Overriding `verify()` on ours would never be
  invoked.

So **our managers deny by returning `Mono.error(new GatewayAccessDeniedException(reason))` from
`authorize()`** rather than a `false` decision. `GatewayAccessDeniedException` extends
`AccessDeniedException` and carries a `Reason`. The error passes through every wrapper unchanged — the
delegating manager, `verify()`, and, because Actuator enables observations,
`ObservationReactiveAuthorizationManager`, which only records the error — to
`ExceptionTranslationWebFilter`, which still routes an anonymous caller to the
`401` entry point and anyone else to our handler. The handler maps `Reason` to `detail`, and falls back
to a generic `detail` for a plain `AccessDeniedException`.

**An unauthenticated caller never sees a `Reason`.** Every rule denies a caller with no authentication
— an `authenticated` rule and a scope rule alike — and `ExceptionTranslationWebFilter` sends any
principal-less exchange to the entry point before consulting the access-denied handler. So the answer is
`401` with `WWW-Authenticate: Bearer`, whichever rule matched, and the reason carried is never rendered.

**Deny-by-default stays in our table.** Its last rule matches every exchange and denies with `NO_RULE`,
so the wrapper's own fallback — a plain `false` decision, verified in the bytecode — is never reached.

**This is off the usual contract**, which expects a decision rather than an error. It is the only path
the 7.0.6 bytecode leaves open. The integration tests assert every `detail` string end to end, so a
future Spring release that handles errors from `authorize()` differently fails loudly rather than
degrading to a generic body.

---

## 8. Components

- **`authz.RouteScopeAuthorizationManager`** — `ReactiveAuthorizationManager<AuthorizationContext>`; the
  rule table in §4.
- **`authz.TenantAuthorizationManager`** — wraps the table; §5.
- **`authz.GatewayAccessDeniedException`** — `AccessDeniedException` carrying a `Reason`.
- **`authz.Reason`** — `MISSING_SCOPE`, `API_KEY_NOT_ACCEPTED`, `TENANT_MISMATCH`, `NO_RULE`, each
  carrying its own `detail` string, so a reason cannot exist without its wire text.
- **`error.JsonServerAccessDeniedHandler`** — §7.
- **`error.ErrorBody`** — gains the `detail` overload.
- **`config.GatewaySecurityConfig`** — `.anyExchange().access(tenantChecked(routeTable))` after the
  health `permitAll`; the access-denied handler on `exceptionHandling`. The class comment stops saying authorization is M4's.
- **`application.yml`** — `RemoveRequestHeader=X-API-Key` on the ledger route.

**No dependencies are added.** Everything above is in `spring-security-web` and `-core` 7.0.6, already
on the classpath, and each class name was checked against those jars.

---

## 9. Testing

A test that passes the moment it is written has proven nothing. Each is made to fail first, on purpose.

**Unit — no Spring context.**

- `RouteScopeAuthorizationManagerTest` — a parameterised matrix: every row of §4 against a JWT with and
  without the scope, an API key with and without it; PUT, DELETE, HEAD and OPTIONS on machine and
  ledger; an unknown path. Each case asserts the specific `Reason`, not merely "denied".
- `TenantAuthorizationManagerTest` — no tenant named; matching header; mismatched header; mismatched
  query; encoded query; two `X-Tenant` headers with one bad; `acme,default`; blank; wrong case; a
  tenant-less JWT naming any tenant; an API key naming any tenant; a missing scope *and* a mismatched
  tenant together reports `MISSING_SCOPE`.
- `JsonServerAccessDeniedHandlerTest` — each `Reason` to its `detail`; a plain `AccessDeniedException`
  to the generic `detail`; no `WWW-Authenticate`.

**Integration** — WebTestClient, with WireMock standing in for the downstreams as it already does.

- **Every `403` also asserts the downstream received zero requests.** A `403` that forwarded anyway
  would be worse than no check.
- The plan's acceptance criteria: a token without `payments:write` on `POST /api/ledger/entries` is
  `403` in the platform shape; the correct scope is proxied, with WireMock counting exactly one
  request; a cross-tenant `X-Tenant` is `403`.
- An API key on ledger is `403` with `API_KEY_NOT_ACCEPTED`'s detail.
- Deny by default: an authenticated caller on an unknown path is `403`; an anonymous one is still `401`
  with `WWW-Authenticate: Bearer`.
- The `403` shape for both kinds of caller — once for a JWT caller, once for a key caller — through
  the single wiring.
- `RemoveRequestHeader`: a JWT caller sending a blank `X-API-Key` to ledger — WireMock sees no
  `X-API-Key`.
- **Existing tests will break**, because `RoutingTest` and others mint tokens without scopes. Every
  such change is inspected individually: a test gaining a scope so it can keep asserting the same
  behaviour is correct; a test whose assertion is weakened is not.

**Mutation checks.** Each change must make the named test fail.

| Mutation | Test that must fail |
|---|---|
| Remove the tenant wrapper | the cross-tenant tests |
| Drop "JWT principal" from the ledger rules | the key-on-ledger test |
| Replace the final `NO_RULE` rule with `authenticated()` | the unknown-path test |
| Remove the `exceptionHandling` access-denied wiring | the JWT *and* the key `403`-shape tests |
| Remove `RemoveRequestHeader` | the header test |

**Run it.** Boot AuthCore, ledger-service and GateKeeper and drive `curl.exe`:

| Request | Expected |
|---|---|
| Demo key, `GET /api/machine/payments` | `200` |
| Demo key, `POST /api/machine/payments` | `403` — the key carries only `payments:read` |
| Demo key, `GET /api/ledger/entries` | `403` from the gateway |
| `authcore-machine` token, `POST /api/ledger/entries` | passes the edge; ledger's own `403` |
| User token with `payments:write`, `POST /api/ledger/entries` | `201` |
| `acme` user, `X-Tenant: default` | `403` from the gateway |
| `acme` user, `X-Tenant: acme` | reaches AuthCore |
| Unknown path, authenticated | `403` |

The same run settles the two assumptions in §5: that a client's `Host` does not reach AuthCore, and that
a tenant named in a form-encoded body passes the edge and is refused by AuthCore.

---

## 10. Documentation changed alongside

- **`README.md`** — the authorization model; the route table with its requirements; API keys refused on
  ledger at the edge.
- **M3 design §8** — the reach table's ledger row changes from "`401` from ledger" to "`403` at the
  gateway", with a pointer here.
- **The handoff** — M4's state, and the M4 items in its §5 marked closed.
- **Separately, as its own commit:** the M0–M2 design says the `roles` claim reads `ROLE_ADMIN`;
  AuthCore emits `ADMIN` (`AuthCoreUser.roleNames()` strips the prefix). Unrelated to M4, found while
  designing it.

---

## 11. Out of scope

- **Permission checks at the edge.** Duplicates ledger's and AuthCore's own checks and adds nothing;
  API keys and client-credentials tokens carry no permissions to check.
- **Stamping `X-Tenant`** — rejected in §3.
- **Tenant-bound API keys.** `api_keys` still has no `tenant` column.
- **Configuration-driven rules.** The table is Java. Rules in `application.yml` would sit beside their
  routes and change without a rebuild, but a wrongly-prefixed block binds nothing and starts cleanly —
  the one silent failure mode the handoff warns about. That trade is worth revisiting when routes become
  dynamic, not before.
- **The `gateway` actuator endpoint.** Still off. It now has an authorization model to hang off, but
  deciding who may read it is its own decision.
- **Rate limiting** — M5. **Revocation** — M6.

---

## 12. Definition of done

- A token without `payments:write` on a ledger write route is refused `403` in the platform shape; the
  correct scope is proxied.
- A request naming a tenant other than the token's is refused `403`, and the downstream never sees it.
- An API key on the ledger route is refused `403` at the edge; on the machine route it still works
  end-to-end.
- A request no rule covers is refused `403` when authenticated and `401` when not.
- Every `403` carries its fixed `detail` and no `WWW-Authenticate`, for JWT and key callers alike.
- The ledger route forwards no `X-API-Key`.
- Every mutation in §9 fails a test, and the run in §9 behaves as tabled.
- GateKeeper green, on its own branches, each task reviewed and merged.
