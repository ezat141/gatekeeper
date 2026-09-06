package com.gatekeeper.apikey;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.BadCredentialsException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.time.Duration;
import java.time.Instant;
import java.util.HexFormat;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link ApiKeyReactiveAuthenticationManager} against fakes rather than mocks for both of
 * its collaborators.
 *
 * <p>{@link FakeApiKeyCache} is a {@link ConcurrentHashMap} that also records the TTL it was
 * last asked to store with — the TTL-clamp and negative-TTL assertions below read that field
 * directly, which is both simpler and more informative than a mock's {@code verify(cache)
 * .put(eq(hash), eq(result), argThat(...))}.
 *
 * <p>{@link IntrospectionClient} is a concrete class, not an interface, so faking it means
 * either subclassing it or introducing a seam (extracting an interface the manager would
 * depend on instead). This test subclasses it: {@link FakeIntrospectionClient} overrides
 * {@code introspect(String)} completely, so the {@code WebClient} and {@link ApiKeyProperties}
 * fields {@code IntrospectionClient} would otherwise use are never read — the fake still
 * passes real, if unused, instances to {@code super(...)} rather than {@code null}, so a
 * future {@code Objects.requireNonNull} in that constructor would not break every test in
 * this class at construction. Extracting an interface instead would mean
 * changing production code to serve a single test, for a class with a single implementation
 * and a single call site. That is speculative generality this milestone was not asked for,
 * so the subclass seam wins and {@link IntrospectionClient} is left exactly as Task 9 built it.
 */
class ApiKeyReactiveAuthenticationManagerTest {

    static final Duration CACHE_TTL = Duration.ofSeconds(60);
    static final Duration NEGATIVE_CACHE_TTL = Duration.ofSeconds(10);

    FakeApiKeyCache cache;
    FakeIntrospectionClient client;
    ApiKeyReactiveAuthenticationManager manager;

    @BeforeEach
    void setUp() {
        cache = new FakeApiKeyCache();
        client = new FakeIntrospectionClient();
        ApiKeyProperties properties = new ApiKeyProperties(
                "unused", "unused", CACHE_TTL, NEGATIVE_CACHE_TTL, Duration.ofSeconds(2));
        manager = new ApiKeyReactiveAuthenticationManager(cache, client, properties);
    }

    @Test
    void activeKeyAuthenticatesWithScopeAuthorities() {
        client.nextAnswer = new ApiKeyIntrospection(
                true, "reporting", Set.of("payments:read"), Instant.now().plusSeconds(3600));

        StepVerifier.create(authenticate("ak_good"))
                .assertNext(authentication -> {
                    assertThat(authentication.isAuthenticated()).isTrue();
                    assertThat(authentication.getName()).isEqualTo("reporting");
                    assertThat(authentication.getAuthorities())
                            .extracting(GrantedAuthority::getAuthority)
                            .containsExactly("SCOPE_payments:read");
                })
                .verifyComplete();
    }

    @Test
    void inactiveAnswerErrorsWithBadCredentials() {
        client.nextAnswer = ApiKeyIntrospection.inactive();

        StepVerifier.create(authenticate("ak_bad"))
                .expectError(BadCredentialsException.class)
                .verify();
    }

    /**
     * Not an {@link AuthenticationException}: {@code AuthenticationWebFilter} converts only
     * that hierarchy into a 401, so an unrelated exception type is what makes an AuthCore
     * outage answer 503 instead of wrongly telling the caller their key is bad. See {@link
     * IntrospectionUnavailableException}'s class comment.
     */
    @Test
    void introspectionUnavailablePropagatesRatherThanBecomingAnAuthenticationFailure() {
        client.nextError = new IntrospectionUnavailableException("AuthCore is down", null);

        StepVerifier.create(authenticate("ak_whatever"))
                .expectErrorSatisfies(ex -> assertThat(ex)
                        .isInstanceOf(IntrospectionUnavailableException.class)
                        .isNotInstanceOf(AuthenticationException.class))
                .verify();
    }

    @Test
    void cacheHitNeverCallsIntrospection() {
        String rawKey = "ak_cached";
        cache.store.put(ApiKeyReactiveAuthenticationManager.sha256(rawKey), new ApiKeyIntrospection(
                true, "reporting", Set.of("payments:read"), Instant.now().plusSeconds(3600)));

        StepVerifier.create(authenticate(rawKey))
                .assertNext(authentication -> assertThat(authentication.getName()).isEqualTo("reporting"))
                .verifyComplete();

        assertThat(client.callCount.get()).isZero();
    }

    @Test
    void cacheMissCallsIntrospectionExactlyOnceAndWritesTheAnswerBack() {
        ApiKeyIntrospection answer = new ApiKeyIntrospection(
                true, "reporting", Set.of("payments:read"), Instant.now().plusSeconds(3600));
        client.nextAnswer = answer;

        StepVerifier.create(authenticate("ak_miss"))
                .expectNextCount(1)
                .verifyComplete();

        assertThat(client.callCount.get()).isEqualTo(1);
        assertThat(cache.store).containsEntry(ApiKeyReactiveAuthenticationManager.sha256("ak_miss"), answer);
    }

    /**
     * Without the clamp, a key that dies in five seconds would keep authenticating out of
     * cache for the full fifty-five seconds after that — see {@code ttlFor}'s javadoc in the
     * manager. The bound below is deliberately loose (anywhere on (0s, 5s]) rather than
     * pinned to a single millisecond value: {@code ttlFor} calls {@code Instant.now()} a
     * fraction of a second after this test does, and asserting exact equality would make the
     * test flake on a slow CI box. A one-second-plus margin is nowhere near the boundary that
     * actually matters here, which is "5s, not the configured 60s".
     */
    @Test
    void clampsCacheTtlToTheKeysOwnExpiryWhenSoonerThanTheConfiguredTtl() {
        client.nextAnswer = new ApiKeyIntrospection(
                true, "reporting", Set.of("payments:read"), Instant.now().plusSeconds(5));

        StepVerifier.create(authenticate("ak_soon")).expectNextCount(1).verifyComplete();

        assertThat(cache.lastPutTtl)
                .isPositive()
                .isLessThanOrEqualTo(Duration.ofSeconds(5))
                .isLessThan(CACHE_TTL);
    }

    /**
     * The extreme case {@code ttlFor} clamps to {@link Duration#ZERO}: an answer that is
     * {@code active: true} but whose {@code expiresAt} has already elapsed by the time this
     * process sees it. That is a real race, not a theoretical one — AuthCore decides
     * {@code active} and stamps {@code expiresAt} before the response crosses the network,
     * and {@code ttlFor} computes {@code Duration.between(Instant.now(), expiresAt)} after
     * it lands, so any key expiring inside that round trip (or under ordinary clock skew
     * between the two hosts) arrives here already past due.
     *
     * <p>A zero {@link Duration} must never reach {@code cache.put}: Spring Data Redis maps
     * a zero TTL to a persistent {@code SET} with no expiry at all, not to "expire
     * immediately". Caching this answer would make an already-dead key authenticate from
     * cache forever, immune to revocation — the opposite of what the clamp exists to do.
     * The request that surfaced this must still be served; only the caching is wrong.
     */
    @Test
    void expiredButActiveAnswerIsNeverCached() {
        client.nextAnswer = new ApiKeyIntrospection(
                true, "reporting", Set.of("payments:read"), Instant.now().minusSeconds(1));

        StepVerifier.create(authenticate("ak_already_expired"))
                .assertNext(authentication -> assertThat(authentication.getName()).isEqualTo("reporting"))
                .verifyComplete();

        assertThat(cache.store).isEmpty();
        assertThat(cache.lastPutTtl).isNull();
    }

    @Test
    void inactiveAnswerIsCachedWithTheNegativeTtl() {
        client.nextAnswer = ApiKeyIntrospection.inactive();

        StepVerifier.create(authenticate("ak_bad"))
                .expectError(BadCredentialsException.class)
                .verify();

        assertThat(cache.lastPutTtl).isEqualTo(NEGATIVE_CACHE_TTL);
    }

    /**
     * The gateway's own introspection key is a real, active key — AuthCore has no reason to
     * say otherwise. It is identified purely by carrying {@code apikeys:introspect} among its
     * scopes, and must be refused all the same: accepting it would let anyone who obtained it
     * authenticate as the gateway by replaying the credential the gateway puts on the wire on
     * every introspection call. See {@code refuseSelfIntrospection}'s javadoc in the manager.
     */
    @Test
    void refusesAnAnswerCarryingTheIntrospectionScope() {
        client.nextAnswer = new ApiKeyIntrospection(
                true, "gatekeeper-gateway", Set.of("apikeys:introspect"), Instant.now().plusSeconds(3600));

        StepVerifier.create(authenticate("ak_gateway_key"))
                .expectError(BadCredentialsException.class)
                .verify();
    }

    /**
     * The hash below is computed independently of {@link ApiKeyReactiveAuthenticationManager
     * #sha256}, not by calling it, so a regression that changed or dropped that hashing would
     * still be caught here instead of the test silently agreeing with whatever the production
     * code now does. The raw key must never appear as a cache key at all — a Redis dump or a
     * {@code KEYS} scan must not yield anything usable, mirroring {@link RedisApiKeyCacheTest
     * #namesTheRedisKeyByHashAndNotByCredential}.
     */
    @Test
    void cacheIsKeyedByTheHashNeverTheRawKey() {
        String rawKey = "ak_hash_me";
        client.nextAnswer = new ApiKeyIntrospection(
                true, "reporting", Set.of("payments:read"), Instant.now().plusSeconds(3600));

        StepVerifier.create(authenticate(rawKey)).expectNextCount(1).verifyComplete();

        assertThat(cache.store).containsKey(independentSha256Hex(rawKey));
        assertThat(cache.store).doesNotContainKey(rawKey);
    }

    /**
     * Added after mutation-testing the trailing {@code switchIfEmpty} in {@code
     * authenticate()}: deleting it left all the tests above green, because none of them
     * can make the pipeline complete empty — {@link FakeIntrospectionClient} otherwise
     * always answers with a value or an error, same as the real, contractually
     * never-empty {@link IntrospectionClient}. That guard is deliberate defence in depth
     * (see its comment in the manager), so it needs a fake capable of violating the
     * contract on purpose to be exercised at all. Without this test, a regression deleting
     * the guard would ship unnoticed by every other test here, and would only be visible
     * downstream as a worse failure shape: today, {@code AuthenticationWebFilter} turns an
     * empty manager result into {@code IllegalStateException("No provider found for
     * ...")}, an unhandled exception that surfaces as a 500 instead of the clean {@link
     * IntrospectionUnavailableException} this guard produces — and the guard also does not
     * depend on that framework behavior continuing to fail closed if it ever changes.
     */
    @Test
    void introspectionCompletingEmptyErrorsRatherThanAuthenticatingNothing() {
        client.completesEmpty = true;

        StepVerifier.create(authenticate("ak_whatever"))
                .expectError(IntrospectionUnavailableException.class)
                .verify();
    }

    private Mono<Authentication> authenticate(String rawKey) {
        return manager.authenticate(new ApiKeyAuthenticationToken(rawKey));
    }

    private static String independentSha256Hex(String value) {
        try {
            byte[] digest = MessageDigest.getInstance("SHA-256").digest(value.getBytes(StandardCharsets.UTF_8));
            return HexFormat.of().formatHex(digest);
        } catch (NoSuchAlgorithmException e) {
            throw new IllegalStateException("SHA-256 is required but unavailable", e);
        }
    }

    /**
     * A {@link ConcurrentHashMap} standing in for Redis, plus the one extra field
     * {@code ApiKeyCache}'s real backend can't hand back as plainly: the TTL the last
     * {@code put} was asked to use.
     */
    static class FakeApiKeyCache implements ApiKeyCache {
        final Map<String, ApiKeyIntrospection> store = new ConcurrentHashMap<>();
        volatile Duration lastPutTtl;

        @Override
        public Mono<ApiKeyIntrospection> get(String keyHash) {
            ApiKeyIntrospection cached = store.get(keyHash);
            return cached == null ? Mono.empty() : Mono.just(cached);
        }

        @Override
        public Mono<Void> put(String keyHash, ApiKeyIntrospection introspection, Duration ttl) {
            store.put(keyHash, introspection);
            lastPutTtl = ttl;
            return Mono.empty();
        }
    }

    /**
     * Subclasses the real {@link IntrospectionClient} rather than mocking it — see this
     * class's javadoc for why — and overrides {@code introspect} entirely, so the {@code
     * WebClient} and {@link ApiKeyProperties} passed to {@code super(...)} below are never
     * read. Real, if unused, instances rather than {@code null}: safe today either way
     * since the constructor only assigns them, but a future {@code Objects.requireNonNull}
     * there would otherwise break every test in this class at construction, with a stack
     * trace pointing at this fake rather than at whatever actually changed.
     */
    static class FakeIntrospectionClient extends IntrospectionClient {
        private static final ApiKeyProperties UNUSED_PROPERTIES =
                new ApiKeyProperties("unused", "unused", Duration.ZERO, Duration.ZERO, Duration.ZERO);

        ApiKeyIntrospection nextAnswer;
        RuntimeException nextError;
        boolean completesEmpty;
        final AtomicInteger callCount = new AtomicInteger();

        FakeIntrospectionClient() {
            super(WebClient.create(), UNUSED_PROPERTIES);
        }

        @Override
        public Mono<ApiKeyIntrospection> introspect(String rawKey) {
            callCount.incrementAndGet();
            // The real IntrospectionClient can never actually do this — its introspect()
            // method is built specifically so it never completes empty, per the inline
            // comments there and IntrospectionClientTest — but this fake can, on purpose:
            // it is the only way to unit-test the manager's OWN redundant switchIfEmpty
            // guard (see introspectionCompletingEmptyErrorsRatherThanAuthenticatingNothing
            // below) without relying on the real client's contract holding.
            if (completesEmpty) {
                return Mono.empty();
            }
            if (nextError != null) {
                return Mono.error(nextError);
            }
            if (nextAnswer != null) {
                return Mono.just(nextAnswer);
            }
            return Mono.error(new IllegalStateException(
                    "FakeIntrospectionClient has no answer configured for this test"));
        }
    }
}
