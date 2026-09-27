# GateKeeper M5 — Distributed rate limiting and daily quotas — Design

M4 decided what a caller may reach. M5 decides how much of it they may use: a per-second token bucket
and a daily quota per caller, sized by the caller's plan, enforced in Redis so that every gateway
instance sharing that Redis enforces one limit, not one each. An exceeded limit is answered `429` in
the platform's JSON error shape, with a `Retry-After` the caller can act on.

This is a **single-repo milestone**. AuthCore and ledger-service are unchanged: nothing below requires
them to change. The three follow-ups left open by M4 (ledger-service's scope enforcement, stripping
`Cookie` on the AuthCore routes, ID tokens on the authenticated-only rules) stay independent of M5 and
remain recorded in the handoff.

---

## 1. Purpose

Protect downstream capacity and share it fairly between callers, and give plans a meaning a caller can
observe: `free` and `pro` receive different allowances, per second and per day.

Rate limiting here is a **capacity control, not a security control**. It sits after authentication and
authorization, and nothing about who may reach what depends on it. That distinction drives the failure
mode in §7.

---

## 2. What the framework provides, verified against the jars

Spring Cloud Gateway 5.0.2 ships `RequestRateLimiterGatewayFilterFactory` and `RedisRateLimiter`. What
they do was established from the 5.0.2 jar, not from memory, and each fact below shaped a decision.

| Fact | Consequence |
|---|---|
| `RedisRateLimiter` reads `replenishRate`, `burstCapacity` and `requestedTokens` **per route id** (`loadConfiguration(routeId)`, package-private); the caller's key only names the Redis keys | Per-plan rates are impossible without a custom limiter |
| Its keys are `request_rate_limiter.{<routeId>.<key>}.tokens` and `.timestamp` | One bucket per route per caller, not per caller |
| Its Lua script is atomic, hash-tagged, and takes `now` from Redis `TIME` (whole seconds) unless a time is passed | The clock-source idea is sound and is kept; the precision is improved (§6) |
| A denial commits an **empty** body, with `X-RateLimit-*` headers and **no `Retry-After`** | The platform shape and `Retry-After` are ours to add |
| A Redis error **fails open**: allowed, `X-RateLimit-Remaining: -1` | Matches the choice in §7, but with invented header values |
| It runs as a gateway filter, after Spring Security's whole `WebFilter` chain | Only authorized requests reach it |

Spring Authorization Server 7.1.0, as AuthCore runs it, writes on every access token `aud = [client
id]` and `sub = principal name`: the client id for a `client_credentials` token, the username for a
user token. It writes no `client_id` claim, and `azp` only on ID tokens. AuthCore's customizer adds
`tenant` (with `roles` and `permissions`) to user access tokens only. Usernames are unique per tenant,
not globally.

---

## 3. Decision: plans come from gateway configuration

No plan data exists anywhere on the platform. Three sources were considered.

**Chosen — gateway configuration**, behind a `PlanResolver` interface. `application.yml` defines each
plan's limits and assigns tenants, clients and API keys to plans, with a default for everyone else.

**Rejected — a `plan` claim from AuthCore.** Arguably the plan's right home, but it makes M5 a two-repo
milestone, and a plan change would reach the gateway only as old tokens expired. Nothing in M5
requires it.

**Rejected — a plan registry in Redis.** Plans could change without a restart, but nothing writes the
keys until a management API exists (M9), so M5 would ship a seeding script standing in for a feature.

The cost is stated rather than discovered: the gateway holds business data — who is on which plan — in
configuration, and changing it means a redeploy until M9. The interface exists so that M9 can move the
data into Redis behind it without touching the limiter.

---

## 4. Decision: whose bucket a request counts against

| Caller | Identity |
|---|---|
| JWT carrying `tenant` (every user token) | `tenant:<slug>` |
| JWT without `tenant` (client credentials) | `client:<first aud>`, falling back to `client:<sub>` |
| API key | `apikey:<name>` |

**Chosen — tenant where there is one, otherwise the client.** Every user of `acme` shares `acme`'s
plan, which is what a plan means for a tenant. The `sub` fallback is exact for client-credentials
tokens, whose `sub` *is* the client id; it exists only so that a token without `aud` still has an
identity of its own.

**Rejected — tenant and client together.** One bucket per pair stops one integration starving a
tenant's others, but a plan belongs to a tenant, so which pair's allowance applies becomes ambiguous,
and the number of buckets grows as tenants times clients.

**Rejected — per user.** Fairest within a tenant, but it defeats the plan: a hundred `acme` users would
receive a hundred times `acme`'s allowance.

### The audience question, settled

The M4 documents recorded that skipping audience validation stays acceptable only while the gateway
never decides by client identity, and that per-client rate limiting is that moment. M5 settles it:

- **`aud` is read as the client's identity, and not validated.** Validating audience means checking
  that a token was issued *for this gateway*. AuthCore cannot express that: its `aud` names the client,
  not a resource server. Validation would need resource indicators or an audience customizer in
  AuthCore, a change M5 does not require.
- **Reading it is safe.** `aud` is inside the signed token and AuthCore sets it from the registered
  client, so a caller cannot name an arbitrary bucket.
- **One exception, found in Task 2's review: OIDC ID tokens.** An ID token carries `aud = [client]`,
  `sub = username` and no `tenant`, and M4 recorded that one may authenticate at the gateway. It would
  count against `client:<spa>` rather than the user's tenant. So a user holding both tokens can choose
  which of two buckets to spend, and ID-token callers from every tenant share one bucket. The root is
  the M4 open item — ID tokens should not authenticate here at all — and fixing it there closes this
  too. Treating ID tokens as having no identity would be worse: the filter forwards those unlimited.
- **What remains open is unchanged by M5:** were AuthCore ever to issue tokens for another resource
  server using the same scope names, those tokens would be accepted here. That was true before M5, is
  not made worse by it, and is recorded in the README.
- **The client derivation depends on AuthCore's `aud` shape.** Adopting resource indicators or an
  audience customizer — the route to real audience validation — would change `aud` to name a resource
  server, alone or beside the client. `aud[0]` would then stop naming the client, and every client
  would silently share one bucket. That change must change this derivation with it.

**A caller with no usable identity is forwarded unlimited.** A tenant-less JWT whose `aud` and `sub`
are both missing or blank has no identity, and the filter forwards it with a warning rather than
limiting it. AuthCore cannot issue such a token; the alternative — one shared bucket for every such
token — would let any one of them exhaust the others.

---

## 5. Decision: the limiter runs after authorization

**Chosen — after authorization, just before routing.** Only a request that would reach a downstream is
counted. A `401` or `403` never touches Redis and never consumes a caller's allowance, and the identity
of §4 exists only after authentication anyway.

**Rejected — between authentication and authorization.** A caller's `403`s would consume the allowance
they pay for, and the limiter would become a second security filter to order against the rule table.

**Rejected — before authentication, by IP.** Protects against anonymous floods, but an IP is not the
identity plans attach to. It is a different mechanism.

**What this does not do, stated:** it does not protect against floods of unauthenticated or forbidden
requests. Those cost gateway CPU and, for random API keys, a negatively cached introspection call, but
never reach a downstream. Per-IP flood protection is out of scope (§12).

Within the limiter the **bucket is checked before the quota**, so a request refused for arriving too
fast does not also spend the day's quota (§6).

---

## 6. Redis: one script, two keys per identity

### Keys

| Key | Type | Fields | Expiry |
|---|---|---|---|
| `gatekeeper:rl:{<identity>}` | hash | `tokens`, `ts` | `ceil(burst / rate × 2)` seconds, refreshed on each write |
| `gatekeeper:quota:{<identity>}` | hash | `day`, `count` | next UTC midnight + 1 hour, by Redis's clock |

- **One bucket and one quota per identity, across all routes.** A plan's rate is the caller's rate,
  not a rate per route.
- **`{<identity>}` is a hash tag**, so both keys share a Redis Cluster slot, which a multi-key script
  requires. The `gatekeeper:` prefix matches M3's `gatekeeper:apikey:` cache.
- **The day lives in a field, not in the key name.** A script must declare its keys before it runs,
  and the day is known only from Redis's clock, read inside the script. Storing `day` beside `count`
  and resetting the count when the day changes keeps every key declared up front.
- **An identity cannot be chosen by the caller.** Every part comes from a signed token or from
  introspection, never from the request. Any character outside `[A-Za-z0-9._-]` is still percent-encoded
  (UTF-8 bytes, `%XX`), so no name can break the key's structure or its hash tag.
- **Plan limits are script arguments.** Changing a plan in configuration needs no Redis migration.

### The script

One `EVAL` per request. Arguments: rate, burst, daily quota, and an optional `now`.

1. `now` is the argument if given, otherwise Redis `TIME` as seconds plus microseconds. Tests pass it;
   production never does, so every gateway instance shares Redis's clock and none relies on its own.
   Microseconds make the bucket refill smoothly at low rates, where Spring's whole-second clock does not.
2. `day = floor(now / 86400)` — the UTC day number. `untilMidnight = (day + 1) × 86400 − now`.
3. Refill the bucket: `tokens = min(burst, stored tokens + (now − ts) × rate)`, starting full.
4. If `tokens < 1`: refused, `RATE_LIMITED`, `retryAfter = ceil((1 − tokens) / rate)`. The quota is not
   touched.
5. Read the quota; if its `day` is not today, the count is zero. If `count + 1 > quota`: refused,
   `QUOTA_EXCEEDED`, `retryAfter = ceil(untilMidnight)`. No token is taken.
6. Otherwise: take one token, increment the count, write both hashes with their expiries.
7. Return: allowed, reason, tokens remaining (floor), quota remaining, `retryAfter`, `untilMidnight`.

The script is atomic, so two instances can never both take the last token. Redis 7 (the platform's
`redis:7-alpine`) replicates script effects by default, so reading `TIME` in a writing script is safe.

---

## 7. Decision: when Redis is unavailable, let requests through

**Chosen — fail open, fast.** The Redis call has its own timeout (`gatekeeper.rate-limit.redis-timeout`,
`200ms`). On an error or a timeout the request proceeds unlimited, a warning is logged, and the
response carries **no** rate-limit headers — not invented ones, as Spring's `-1` would be.

- The rule table and the tenant check use no Redis and keep working. A Redis outage costs unlimited
  traffic for its duration, not a platform outage. This is the default of Spring's limiter and of
  Envoy's.
- **The timeout is not optional.** M0–M2 left the JWKS fetch without one, so a host that accepts the
  connection and never answers hangs the request; that is an open M7 item. A second outbound call with
  the same gap would repeat a known defect on purpose.
- **M6 will decide the opposite, deliberately.** Its revocation check will also read Redis, and there a
  failure must refuse: a revoked token getting through is a security failure; an unlimited request is
  not.
- API-key callers already depend on Redis through M3's introspection cache. That path is unchanged by
  M5.

**Rejected — refuse with `503`.** Limits could never be escaped, but Redis would become a hard
dependency of every request, JWT callers included.

**Rejected — a configuration switch.** Two behaviours to test and document, for a choice no deployment
has asked to make.

---

## 8. The `429` response

```
HTTP/1.1 429 Too Many Requests
Content-Type: application/json
Retry-After: 1
X-RateLimit-Remaining: 0
X-RateLimit-Replenish-Rate: 5
X-RateLimit-Burst-Capacity: 10
X-Quota-Limit: 1000
X-Quota-Remaining: 612
X-Quota-Reset: 41213

{"error":"too_many_requests","status":429,"path":"/api/ledger/entries","detail":"the request rate exceeds the caller's plan"}
```

- **The platform shape**, `ErrorBody` with a `detail`, as M4's `403` has. Two fixed strings, one per
  reason, authored in one enum:

  | Reason | `detail` |
  |---|---|
  | `RATE_LIMITED` | `the request rate exceeds the caller's plan` |
  | `QUOTA_EXCEEDED` | `the caller's daily quota is used up` |

  Neither names the plan or the identity.
- **`Retry-After` is computed**, in whole seconds, at least `1`: time to one token for `RATE_LIMITED`,
  time to UTC midnight for `QUOTA_EXCEEDED`. It is actionable, unlike the fixed `5` on the gateway's
  `503`.
- **No `WWW-Authenticate`.** The caller is authenticated; the answer is to wait.
- **The downstream is never contacted.**

**The same headers on allowed responses.** Every response that passed through the limiter carries the
`X-RateLimit-*` and `X-Quota-*` headers, so a well-behaved client can slow down before it is refused.
The bucket headers keep Spring's names; the quota headers are the gateway's own, since Spring has no
quota. `X-Quota-Reset` is seconds until the quota resets.

Responses the limiter never saw carry none: `401` and `403` (it runs after authorization), the health
probe (not routed), and fail-open responses (§7).

**Written in one place.** A `TooManyRequestsWriter` in the `error` package renders the body through the
same `ErrorBody` and `CodecWriterContext` as M4's `403` handler. `RateLimitFilter` calls it and
completes the response itself: no exception, and no detour through `GlobalErrorWebExceptionHandler`.

---

## 9. Components

All in a new package, `com.gatekeeper.ratelimit`, except the writer.

- **`RateLimitProperties`** — binds `gatekeeper.rate-limit.*` (§10) and validates it at startup.
- **`Plan`** — record: name, requests per second, burst, daily quota.
- **`RateLimitIdentity`** — derives the identity of §4 from the authenticated caller, and encodes it.
- **`PlanResolver`** / **`ConfiguredPlanResolver`** — assignment by kind (tenant, client, API key),
  otherwise the default plan. A tenant and a client of the same name resolve independently.
- **`RateLimitStore`** / **`RedisRateLimitStore`** — `check(identity, plan)` → `Decision`; runs the
  script of §6.
- **`Decision`** — allowed, reason, tokens remaining, quota remaining, `retryAfter`, seconds until the
  quota resets.
- **`RateLimitReason`** — `RATE_LIMITED`, `QUOTA_EXCEEDED`, each with its `detail`.
- **`RateLimitFilter`** — a `GlobalFilter` ordered just after `IdentityStampFilter` and before every
  routing filter. It applies to all three routes with no route configuration. It resolves identity and
  plan, calls the store under the timeout, and on allow adds the headers and continues; on refusal
  writes the `429`; on error or timeout continues without headers.
- **`error.TooManyRequestsWriter`** — §8.

**No new endpoints, so no new rule-table rows.** The rule table is unchanged.

**No new dependencies.** Reactive Redis is already on the classpath from M3.

---

## 10. Configuration

```yaml
gatekeeper:
  rate-limit:
    redis-timeout: 200ms
    default-plan: free
    plans:
      free: { requests-per-second: 5,  burst: 10,  daily-quota: 1000 }
      pro:  { requests-per-second: 50, burst: 100, daily-quota: 100000 }
    assignments:
      tenants:  { acme: pro }
      clients:  { authcore-machine: pro }
      api-keys: { demo-reporting-job: free }
```

**Validated at startup; a violation stops the boot:** at least one plan; the default plan exists; every
assignment names an existing plan; every number is at least `1`; the timeout is positive. The first rule
is also the defence against the silent failure the handoff warns about: a mistyped prefix binds no
plans, and the gateway refuses to start rather than limiting nothing.

---

## 11. Testing

A test that passes the moment it is written has proven nothing. Each is made to fail first, on purpose.

**Unit.**
- `RateLimitIdentity`: tenant token → `tenant:`; tenant-less token → `client:<aud>`; no `aud` →
  `client:<sub>`; API key → `apikey:`; unusual characters percent-encoded, braces included.
- `ConfiguredPlanResolver`: each kind of assignment; the default; a tenant and a client with the same
  name kept apart.
- `RateLimitProperties`: each validation rule fails startup.
- `TooManyRequestsWriter`: the exact body and headers, for both reasons; no `WWW-Authenticate`.

**The script, against the real Redis, with a fixed `now`.** A burst of N allowed and N+1 refused
`RATE_LIMITED`; refill after `t` seconds exact; the quota refused at limit + 1; a rate refusal spends no
quota; a quota refusal takes no token; the count resets across UTC midnight (23:59:59.5, then
00:00:00.1); `Retry-After` exact for both reasons; key names, hash tags and expiries as specified.

**Integration, one gateway.** `429` in the platform shape with the headers; the downstream receives
nothing; allowed responses carry the headers; `401` and `403` carry none and never touch Redis; `acme`'s
users share one bucket; two clients do not.

**Two gateways, one Redis.** Two application contexts on random ports sharing the Redis and a WireMock
downstream. Requests alternate between them; the combined burst trips on whichever instance receives
request N+1, and the quota is shared the same way.

**Failing open.** One gateway pointed at a dead Redis port; another at a local socket that accepts and
never answers. Both answer `200` without rate-limit headers, the second within roughly the timeout
rather than hanging.

**Existing suites are kept out of the limiter's way.** Today's tests call as `tenant:acme` and a few
clients, and quota state lives for a day in the shared Redis, so repeated runs would accumulate counts
and fail at random. They run with a default plan of effectively unlimited rate and quota; rate-limit
tests use their own small plans and fresh tenant and client names per test.

**Mutation checks.** Each must make a named test fail.

| Mutation | Test that must fail |
|---|---|
| Remove the quota check | the quota tests |
| Check the quota before the bucket | the rate-refusal-spends-no-quota test |
| Key the bucket per instance instead of in Redis | the two-gateway test |
| Remove the fail-open path | the dead-Redis and silent-Redis tests |
| Fix `Retry-After` at a constant | the `Retry-After` tests |
| Ignore the tenant in the identity | the shared-tenant-bucket test |

**Run it.** Two GateKeeper processes on `8081` and `8083` with a tiny plan set on the command line;
real AuthCore tokens and the demo key sent alternately until either instance answers `429` with
`Retry-After`; a tiny daily quota exhausted the same way; Redis stopped, JWT callers still answered
`200`; Redis restarted, limits resumed.

---

## 12. Out of scope

- **Per-IP flood protection** before authentication (§5).
- **Audience validation** — needs AuthCore to name a resource server in `aud` (§4).
- **Plans managed at runtime** — M9, behind `PlanResolver` (§3).
- **Different limits per route within a plan.** Nothing asks for it.
- **The M4 follow-ups** — ledger-service scope enforcement, `Cookie` stripping, ID tokens on the
  authenticated-only rules. Independent of M5; recorded in the handoff.
- **Revocation** — M6, which will fail closed where this fails open (§7).
- **Metrics** for refusals and fail-open events — the warning log is the record until observability
  arrives.

---

## 13. Documentation changed alongside

- **README** — a rate-limiting section: plans, identity, the `429` and its headers, failing open and
  why; the audience rationale updated to say that `aud` is now read as client identity and why it is
  still not validated; the roadmap marks M5 done; the test count.
- **Handoff** — M5's state, and "Next: M6", including that M6 must fail closed where M5 fails open.

---

## 14. Definition of done

- A caller over its plan's per-second rate is refused `429` with a computed `Retry-After`, in the
  platform shape, and the downstream never sees the request.
- A caller over its daily quota is refused `429` until the next UTC midnight, with `Retry-After` saying
  so.
- `free` and `pro` callers receive different allowances; `acme`'s users share one.
- Two gateway instances sharing one Redis enforce one combined limit, proven by test and by the run.
- With Redis dead or silent, requests still succeed without rate-limit headers, within the timeout.
- Allowed responses carry the rate-limit and quota headers; `401`, `403` and health responses do not.
- Every mutation in §11 fails a test, and the run behaves as described.
- GateKeeper green, each task on its own `feature/m5-task-N` branch, reviewed and merged.
