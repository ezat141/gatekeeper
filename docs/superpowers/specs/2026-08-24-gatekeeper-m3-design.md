# GateKeeper M3 — API-key authentication — Design

Machine callers that never perform the OAuth dance still need to get through the gateway. M3 makes
GateKeeper accept an `X-API-Key` alongside a bearer JWT, so that *either* mechanism authenticates and
nothing downstream of authentication has to know which one was used.

This is a **two-repo milestone**. AuthCore gains one endpoint; GateKeeper gains a converter, an
authentication manager, a cache, and an outbound client. The reasoning for touching AuthCore at all is
settled in `docs/superpowers/HANDOFF-M3-M6.md` §4 and is not re-argued here.

---

## 1. Purpose

Give machine clients — CI jobs, reporting scripts, internal services — a credential they can present on
every request without a token endpoint, and have the gateway validate it at the edge rather than
letting an unauthenticated request reach a downstream.

M3 is authentication only. It decides *whether the caller is who they claim*, not *what they may
reach*. Scope enforcement is M4.

---

## 2. What exists, and what does not

The distinction matters, because the data looks like a seam and is not one.

**Exists.** AuthCore's `api_keys` table (`V7__create_api_keys.sql`): `key_hash` as SHA-256 hex — not
bcrypt, because this is a per-request indexed lookup rather than a password check — plus `key_prefix`
kept in clear for log correlation, comma-separated `scopes`, `enabled`, `expires_at`, and
`last_used_at`. Keys carry an `ak_` prefix so a leaked one is greppable. A demo key is seeded:
`ak_demo_reporting_job_local_only_0000000000`, scope `payments:read`.

**Does not exist.** Any way for another process to ask about a key. `api_keys` is reached only through
`ApiKeyStore.findByRawKey()`, a `JdbcTemplate` query used solely by `ApiKeyAuthenticationProvider`
inside AuthCore's own filter chain. There is no HTTP seam. There is no Redis publication. The only
seam is a database table, and a database table is the wrong kind of seam for this platform.

**Already true and load-bearing.** AuthCore's resource chain
(`AuthorizationServerConfig.resourceApiSecurityFilterChain`) is `securityMatcher("/api/**")` and
already authenticates *both* a bearer JWT and an `X-API-Key`, because `ApiKeyAuthenticationFilter` is
registered before `BearerTokenAuthenticationFilter`. A new endpoint under `/api/**` therefore needs no
new security plumbing — only a rule.

---

## 3. Decision: introspect and forward, do not exchange

Three shapes were considered.

**Chosen — introspect, forward the key unchanged.** AuthCore exposes an authenticated endpoint that
answers "is this key valid, and what does it grant". GateKeeper calls it, caches the answer briefly,
builds an `Authentication` from it, and forwards the request with the key untouched.

**Rejected — exchange the key for a short-lived JWT at the edge.** Genuinely more elegant downstream:
every service would see one credential type, API keys would reach ledger-service, and M4/M5/M6 would
never branch on mechanism. Rejected because **it moves M6's problem somewhere harder.** A minted token
outlives the key it was minted from, so revoking a key would leave its already-issued JWT valid until
expiry — a second revocation problem stacked on top of the one M6 exists to solve. Under the chosen
shape every key caller is re-validated against a short-TTL cache, so revocation latency is bounded by
a number we choose.

**Rejected — teach ledger-service to accept keys too.** Uniform reach with no token machinery, but key
validation would then live in three services and ledger would inherit a dependency on the introspection
endpoint. A security decision spread across three codebases for a route no key caller currently needs.

---

## 4. Integration contract — the new endpoint

This is a contract change and belongs beside JWKS and the revocation key in the platform's integration
table, not in folklore.

| Property | Value |
|---|---|
| Method and path | `POST /api/internal/api-keys/introspect` |
| Caller authentication | `X-API-Key` bearing `SCOPE_apikeys:introspect` (§5) |
| Request body | `{"key": "ak_..."}` |
| Response | `{"active": true, "name": "...", "scopes": ["..."], "expiresAt": "..."}` or `{"active": false}` |

**The key travels in a POST body, never in the path or a query string.** A credential in a URL lands in
access logs, proxy logs, and `Referer` headers. This is the same reason the platform never puts
personal data in query parameters.

**The response never contains the key or its hash.** It answers a question; it does not echo the
credential.

**`active: false` is returned for unknown, disabled, and expired keys alike — one indistinguishable
answer.** Distinguishing them would turn the endpoint into an enumeration oracle: a caller who could
tell "no such key" from "that key exists but is disabled" could confirm which keys are real. AuthCore
still logs the distinction, exactly as `ApiKeyAuthenticationProvider` already does with its
`DisabledException` / `CredentialsExpiredException` split, so operators keep the diagnosis the caller
is denied.

**The endpoint is authenticated, not open.** An open introspection endpoint is an oracle for testing
stolen keys at line rate.

---

## 5. How GateKeeper authenticates to it

**GateKeeper holds its own API key**, seeded in `DataSeeder` with the single scope
`apikeys:introspect` and no others, and presents it as `X-API-Key` on the introspection call.
AuthCore's existing `ApiKeyAuthenticationFilter` already validates it — the endpoint sits under
`/api/**`, on the chain that authenticates both credential types, so this costs **no new dependency on
either side** and no new security plumbing.

It is not circular. GateKeeper's own key is validated by AuthCore locally against Postgres; there is no
second introspection call and no recursion.

The alternative was **making GateKeeper a `client_credentials` OAuth2 client** of AuthCore. It is the
more standard shape — RFC 7662 requires the introspection caller to authenticate, and a client secret
exchanged for a short-lived token is the textbook answer — and it was the initial recommendation. It
was set aside because the honest accounting favours the key: the gateway must hold a long-lived secret
in configuration under *both* designs (a client secret is no more rotating than an API key), so the
OAuth2 path buys only the freshness of the credential on the wire, and pays for it with a new starter,
authorized-client wiring, and a token lifecycle inside a component whose entire purpose is to be
stateless and fast. It also dogfoods the mechanism M3 exists to build.

### Follow-up: rotating the gateway's credential

The trade-off accepted above has a name, and it is recorded here rather than discovered later. **The
gateway's introspection key is long-lived and has no rotation path in M3.** Rotating it today means
editing configuration and restarting the gateway, with a window in which the old key is still seeded
and the new one is not yet deployed, or the reverse.

This is a real piece of debt, not a theoretical one, and it is worth noting that **the pattern to copy
already exists in this platform**: AuthCore shipped client-secret rotation with an overlap window in
its own M7 (`ClientSecretRotationStore`). The same overlap shape applied to `api_keys` — two valid
hashes for one identity during a cutover — would close this without a redesign. Natural owner is M9,
which brings key management under an API; until then the key is treated as a deployment secret.

Two constraints that keep the debt contained meanwhile:

- **The key carries `apikeys:introspect` and nothing else.** It is never granted `payments:*`, so a
  leak yields an introspection oracle rather than data access.
- **A caller key bearing `apikeys:introspect` must be refused at the gateway.** Otherwise presenting
  the gateway's own key as an ordinary `X-API-Key` would authenticate the caller *as the gateway*.
  This is a guard in the authentication manager, and it is tested (§12).

---

## 6. Caching

Calling AuthCore on every request would put a synchronous hop in front of every proxied request and
make AuthCore's availability the gateway's availability. GateKeeper caches in Redis, which it needs for
M5 and M6 regardless.

| Property | Value |
|---|---|
| Key | `gatekeeper:apikey:<sha256-hex-of-key>` |
| Value | the introspection result, compactly encoded |
| Positive TTL | `60s` (`gatekeeper.api-key.cache-ttl`) |
| Negative TTL | `10s` (`gatekeeper.api-key.negative-cache-ttl`) |

**The cache key is the SHA-256 of the key, never the key itself.** A Redis dump, a `KEYS` scan, or a
misconfigured replica must not yield usable credentials. This mirrors why the database stores a hash.

**Positive TTL bounds how long a revoked key keeps working.** That number is the revocation latency for
API keys and should be stated as such rather than discovered later.

**Negative results are cached too, but for less time.** Caching them absorbs a retry storm from a
misconfigured client; keeping that window short limits how much an enumeration attempt is amplified.

**A cached entry never outlives the key's own expiry.** The effective TTL is
`min(configured TTL, time until expiresAt)`. Without this clamp, a key expiring in two seconds cached
for sixty would authenticate for fifty-eight seconds after it died.

The cache sits behind a narrow interface so that the authentication manager can be unit-tested against
a fake, with one integration test proving the Redis implementation is wired correctly.

---

## 7. Components

### AuthCore

- **`ApiKeyIntrospectionController`** — the endpoint in §4. Reuses `ApiKeyStore.findByRawKey()`; adds
  no new query.
- **One authorization rule** in `resourceApiSecurityFilterChain` requiring `SCOPE_apikeys:introspect`
  on `/api/internal/**`. Verified safe: the chain wraps every rule in `tenantScoped(...)`, but
  `TenantAuthorizationManager.tenantClaimOf()` returns `null` for a tenant-less caller and the manager
  then returns the delegate's result unchanged — so an API-key caller is not refused there.
- **`DataSeeder`** — the gateway's own API key, scope `apikeys:introspect` only (§5).

### GateKeeper

- **`ApiKeyAuthenticationConverter`** (`ServerAuthenticationConverter`) — reads `X-API-Key`, returns
  empty when the header is absent or blank so the JWT path is untouched.
- **`ApiKeyReactiveAuthenticationManager`** (`ReactiveAuthenticationManager`) — cache lookup, then
  introspection on a miss; maps the result to an authenticated token or a failure.
- **`ApiKeyCache`** + Redis implementation — §6.
- **`IntrospectionClient`** — the outbound `WebClient` call, **with a response timeout** (see §9).
- **`GatewaySecurityConfig`** — adds the API-key `AuthenticationWebFilter` at the authentication
  position, alongside the existing resource-server configuration.
- **`IdentityStampFilter`** — extended to stamp key callers (§8).

**Scopes become `SCOPE_*` authorities**, the same shape Spring derives from a JWT's `scope` claim.
That is the whole composability property: M4 can write one `hasAuthority("SCOPE_payments:read")` rule
that accepts either credential with no branching. AuthCore already made this choice internally for the
same reason.

**Precedence, stated exhaustively, because "either mechanism authenticates" is ambiguous when both
arrive.** The API-key filter runs first and `X-API-Key` decides the outcome whenever it is present:

| `X-API-Key` | `Authorization: Bearer` | Result |
|---|---|---|
| absent | absent | 401 |
| absent | present | JWT path, unchanged from M2 |
| present, valid | either | Authenticated as the key; the bearer token is **not** consulted |
| present, invalid | either | 401 — **no fallthrough to the JWT path** |

The last row is the one that matters. A typo'd key should surface as "bad credentials", not as a
confusing "no credentials", and a caller must not be able to smuggle a bad key past the gateway by
attaching a good token. This matches `ApiKeyAuthenticationFilter`'s existing behaviour in AuthCore, and
consistency across the two services is worth more than the marginal convenience of a fallthrough.

**Filter order alone does not deliver this table, which is easy to get wrong.** Putting the API-key
filter at the authentication position places it *ahead of* the resource server's filter, not *instead
of* it: on success it continues the chain, and the resource server's own `AuthenticationWebFilter` then
runs regardless — it never checks whether the context is already populated. Measured, with both
credentials attached: a valid key plus a malformed bearer was refused `401`, and a valid key plus a
valid bearer authenticated as the *token's* subject, stamping the JWT's `X-GK-Tenant` on the proxied
request and silently discarding the key's principal. M4 would then have authorized the wrong identity.

Row three therefore requires the resource server to decline the bearer itself. It is given a
`bearerTokenConverter` that returns empty when `X-API-Key` carries text, so the token is genuinely never
consulted. **The emptiness test must match `ApiKeyAuthenticationConverter`'s `hasText` exactly**: keying
off mere header presence would let a blank `X-API-Key:` suppress bearer authentication while the
API-key converter also declined it, turning an empty header into a way to switch authentication off.

---

## 8. Identity, tenant, and reach

**API keys stay tenant-less in M3.** `api_keys` has no tenant column and gains none here. This is not a
dodge: client-credentials JWTs are *already* tenant-less, and `IdentityStampFilter` already omits
`X-GK-Tenant` when the claim is absent. M4 then writes one rule for tenant-less principals covering
both, instead of M3 inventing a separate one for keys and M4 having to reconcile them.

**`IdentityStampFilter` gains a key branch**, stamping `X-GK-Subject: apikey:<name>` so downstream logs
can attribute a request. No `X-GK-Tenant` (none exists) and no permissions header — scopes and
permissions are different vocabularies, and the only downstream that acts on a key's scopes is AuthCore,
which re-derives them from the key itself. `InboundHeaderStripFilter` already removes inbound `X-GK-*`
before authentication, so none of this is spoofable.

**Reach is uneven, deliberately.**

| Route | Downstream | API-key caller |
|---|---|---|
| `/api/machine/**` | AuthCore | Works end-to-end — AuthCore re-authenticates the key itself |
| `/api/accounts/**` | AuthCore | Authenticates; individual endpoints may still refuse on their own `@PreAuthorize` |
| `/api/ledger/**` | ledger-service | **401 from ledger** — it is a JWT-only resource server and the caller carries no bearer token |

The ledger 401 is the honest cost of not exchanging credentials (§3). API keys exist for machine callers
hitting the machine route; this is documented, not defective.

---

## 9. Error handling

The platform's single JSON `ErrorBody` shape applies throughout.

| Condition | Status |
|---|---|
| Unknown, disabled, or expired key | `401` |
| Malformed or blank `X-API-Key` | `401` |
| Introspection unreachable, timed out, or answering with anything other than a well-formed 200 | `503` with `Retry-After` |

A `401` from the introspection endpoint means *GateKeeper's own* client credential was refused — a
gateway misconfiguration, not a caller error — so it maps to 503 like any other upstream failure. It
must never be relayed to the caller as their 401.

**Failure is closed.** An unvalidatable key never authenticates.

**An unreachable AuthCore yields 503, not 401.** The caller's credential may be perfectly valid; telling
them "unauthorized" would be a lie that sends them to rotate a working key. 503 says *try again*, which
is the true statement.

**The introspection call carries an explicit response timeout.** M0–M2 left exactly this defect in the
JWKS fetch — Spring Security's `ReactiveRemoteJWKSource` builds a bare `WebClient.create()`, so a host
that accepts the connection and never answers hangs the request instead of failing closed. That is
recorded as an M7 item. Building a *second* outbound call with the same gap would be repeating a known
bug on purpose.

**No key-specific `WWW-Authenticate` challenge is emitted.** M2 established that every 401 tells the
caller how to authenticate, but API-key authentication has no registered challenge scheme. The shared
entry point continues to emit `Bearer`, which remains actionable — a caller can retry with a token.

---

## 10. Consequence: `last_used_at` becomes a lower bound

The introspection endpoint calls `ApiKeyStore.touchLastUsed()`, so the column keeps tracking real
validation. But because GateKeeper caches, a key used continuously is introspected only once per TTL,
and `last_used_at` therefore means **"last validated at the source, accurate to within the cache TTL"**
rather than "last used".

The alternative — not touching it — was rejected as worse: the column would silently come to mean "last
used *directly* against AuthCore, ignoring everything through the gateway", which looks accurate and is
not. A slightly coarse timestamp beats a quietly wrong one. This is recorded in AuthCore's schema
documentation, not only here.

---

## 11. Dependencies added

Verified against the Boot 4.0.7 BOM rather than remembered — §3 of the handoff exists because
confidently-remembered names are what actually break builds here.

| Repo | Artifact |
|---|---|
| GateKeeper | `spring-boot-starter-data-redis-reactive` |
| GateKeeper (test) | `spring-boot-starter-data-redis-reactive-test` |

**AuthCore adds nothing.** The introspection endpoint is a controller on a chain that already
authenticates API keys.

Choosing the gateway-held key (§5) removed the second runtime starter this design originally carried,
`spring-boot-starter-security-oauth2-client`, along with the reactive authorized-client classes that
could not be verified locally because that jar is absent from `~/.m2`. Nothing in M3 now depends on an
unverified name.

The Redis starter is present in `~/.m2` only at `2.3.7.RELEASE` and `3.2.0`, not `4.0.7`, so the first
M3 build still needs network and cannot run `-o`.

---

## 12. Testing

A test that passes the moment it is written has proven nothing. Each of these must be made to fail
first, on purpose.

**Unit.** Converter: header present, absent, blank, whitespace. Manager: active key, unknown key,
disabled key, expired key, upstream failure. Cache: TTL clamping against `expiresAt`, negative-result
TTL, key is the hash and not the raw key.

**Integration** (WireMock standing in for AuthCore's introspection endpoint, as it already does for
JWKS). Valid key proxies through; each invalid case yields 401 in the platform error shape; AuthCore
unreachable yields 503; a slow AuthCore yields 503 via the timeout rather than hanging.

**Composition.** JWT authentication still works untouched. A request bearing both credentials resolves
per §7's precedence table, every row of it. A request bearing neither is still 401.

**Privilege separation.** A caller presenting the gateway's own introspection key as an ordinary
`X-API-Key` is refused (§5), so nobody authenticates *as the gateway* by replaying the credential it
puts on the wire. This test must be written to fail first against a manager without the guard.

**Cache behaviour.** A second request inside the TTL performs no second introspection — asserted by
WireMock request count, which is the only assertion that actually proves caching rather than assuming
it.

**Mutation tests.** Delete the TTL clamp and confirm the expiry test fails. Delete the fail-closed
branch and confirm the upstream-failure test fails. Delete the API-key filter registration entirely and
confirm more than one test fails — the M2 anti-spoofing suite passed with its filter deleted, which is
why this check is now routine.

**Run it.** Boot AuthCore, ledger-service and GateKeeper, and drive the seeded demo key through
`curl.exe` against all three routes — including the ledger route, to confirm the 401 in §8 is what
actually happens rather than what this document predicts.

---

## 13. Out of scope

- **Scope-based authorization** — M4. M3 authenticates and attaches authorities; nothing consumes them
  yet.
- **Tenant-bound keys** — no `tenant` column, per §8.
- **Rate limiting and quotas** — M5.
- **Revocation of bearer tokens** — M6. Key revocation here is bounded by cache TTL, which is a
  different mechanism.
- **A key management API** — M9. Keys are seeded and managed in the database.
- **Rotating the gateway's own introspection key** — accepted debt, reasoned through in §5. The
  overlap-window pattern from AuthCore's `ClientSecretRotationStore` is the thing to copy; M9 is the
  natural owner. Until then the key is a deployment secret with no online rotation path.
- **Stripping `X-API-Key` from routes that cannot use it.** Forwarding a credential to ledger-service,
  which can do nothing with it, widens exposure for no benefit. The fix is route-conditional and
  therefore authorization-shaped, so it belongs with M4's route rules. **Deferred to M4.**

---

## 14. Definition of done

- The seeded demo key authenticates through GateKeeper and reaches AuthCore's machine route.
- An unknown, disabled, or expired key is refused with 401 in the platform error shape.
- A bearer JWT still authenticates exactly as it did before M3.
- AuthCore unreachable produces 503, not 401, and not a hang.
- A repeated request inside the cache TTL performs one introspection, proven by request count.
- The introspection endpoint refuses an unauthenticated caller.
- The gateway's own introspection key is refused when presented as an ordinary caller credential.
- Both repos green, each with its own branch, its own review, and its own merge.
