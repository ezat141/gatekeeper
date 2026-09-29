package com.gatekeeper.ratelimit;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.gatekeeper.support.TestKey;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.anyRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * The limiter through the real chain, one gateway. The M5 design, sections 4, 5 and 8.
 *
 * <p>The default plan here is {@code burst3} (1/s, burst 3). Rate tests send the burst and one
 * more back to back; the fourth request lands well inside the second it would take one token to
 * refill. Quota tests use {@code quota3} (effectively unlimited rate, quota 3), which needs no
 * timing at all. Every test uses fresh tenants and clients, so neither the shared Redis nor
 * another test can have spent their allowance.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class RateLimitTest {

    static final String ISSUER = "http://localhost:8080";
    static final String QUOTA_TENANT = "q-" + UUID.randomUUID();
    static final String ROOMY_TENANT = "r-" + UUID.randomUUID();

    static WireMockServer downstream;
    static TestKey signingKey;

    @Autowired
    WebTestClient client;

    @Autowired
    ReactiveStringRedisTemplate redis;

    @BeforeAll
    static void start() {
        signingKey = TestKey.generate("k1");
        downstream = new WireMockServer(options().dynamicPort());
        downstream.start();
        downstream.stubFor(get(urlEqualTo("/oauth2/jwks")).willReturn(okJson(TestKey.jwksDocument(signingKey))));
        downstream.stubFor(any(anyUrl()).atPriority(20).willReturn(okJson("{}")));
    }

    @AfterAll
    static void stop() {
        downstream.stop();
    }

    @BeforeEach
    void clearRequestLog() {
        downstream.resetRequests();
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("gatekeeper.auth.jwk-set-uri", () -> downstream.baseUrl() + "/oauth2/jwks");
        registry.add("gatekeeper.auth.issuer", () -> ISSUER);
        registry.add("gatekeeper.downstream.ledger", () -> downstream.baseUrl());
        registry.add("gatekeeper.downstream.authcore", () -> downstream.baseUrl());
        registry.add("gatekeeper.rate-limit.default-plan", () -> "burst3");
        registry.add("gatekeeper.rate-limit.plans.burst3.requests-per-second", () -> "1");
        registry.add("gatekeeper.rate-limit.plans.burst3.burst", () -> "3");
        registry.add("gatekeeper.rate-limit.plans.burst3.daily-quota", () -> "1000");
        registry.add("gatekeeper.rate-limit.plans.quota3.requests-per-second", () -> "1000");
        registry.add("gatekeeper.rate-limit.plans.quota3.burst", () -> "1000");
        registry.add("gatekeeper.rate-limit.plans.quota3.daily-quota", () -> "3");
        registry.add("gatekeeper.rate-limit.plans.roomy.requests-per-second", () -> "1");
        registry.add("gatekeeper.rate-limit.plans.roomy.burst", () -> "6");
        registry.add("gatekeeper.rate-limit.plans.roomy.daily-quota", () -> "1000");
        registry.add("gatekeeper.rate-limit.assignments.tenants." + QUOTA_TENANT, () -> "quota3");
        registry.add("gatekeeper.rate-limit.assignments.tenants." + ROOMY_TENANT, () -> "roomy");
    }

    @Test
    void refusesTheRequestAfterTheBurstWith429() {
        String token = userToken(freshTenant(), "ezzat");
        for (int i = 0; i < 3; i++) {
            ledger(token).expectStatus().isOk();
        }

        ledger(token)
                .expectStatus().isEqualTo(429)
                .expectHeader().valueEquals(HttpHeaders.RETRY_AFTER, "1")
                .expectHeader().valueEquals("X-RateLimit-Remaining", "0")
                .expectHeader().doesNotExist(HttpHeaders.WWW_AUTHENTICATE)
                .expectBody()
                .jsonPath("$.error").isEqualTo("too_many_requests")
                .jsonPath("$.status").isEqualTo(429)
                .jsonPath("$.path").isEqualTo("/api/ledger/entries")
                .jsonPath("$.detail").isEqualTo(RateLimitReason.RATE_LIMITED.detail());

        assertThat(downstream.findAll(anyRequestedFor(urlPathEqualTo("/ledger/entries")))).hasSize(3);
    }

    @Test
    void refusesOnceTheDailyQuotaIsUsedUp() {
        String token = userToken(QUOTA_TENANT, "ezzat");
        for (int i = 0; i < 3; i++) {
            ledger(token).expectStatus().isOk();
        }

        long retryAfter = Long.parseLong(ledger(token)
                .expectStatus().isEqualTo(429)
                .expectBody().jsonPath("$.detail").isEqualTo(RateLimitReason.QUOTA_EXCEEDED.detail())
                .returnResult().getResponseHeaders().getFirst(HttpHeaders.RETRY_AFTER));

        long untilMidnight = 86_400 - Instant.now().getEpochSecond() % 86_400;
        assertThat(retryAfter).isBetween(untilMidnight - 5, untilMidnight + 5);
        assertThat(downstream.findAll(anyRequestedFor(urlPathEqualTo("/ledger/entries")))).hasSize(3);
    }

    @Test
    void allowedResponsesCarryTheHeaders() {
        ledger(userToken(freshTenant(), "ezzat"))
                .expectStatus().isOk()
                .expectHeader().valueEquals("X-RateLimit-Remaining", "2")
                .expectHeader().valueEquals("X-RateLimit-Replenish-Rate", "1")
                .expectHeader().valueEquals("X-RateLimit-Burst-Capacity", "3")
                .expectHeader().valueEquals("X-Quota-Limit", "1000")
                .expectHeader().valueEquals("X-Quota-Remaining", "999")
                .expectHeader().exists("X-Quota-Reset")
                .expectHeader().doesNotExist(HttpHeaders.RETRY_AFTER);
    }

    @Test
    void differentPlansGetDifferentAllowances() {
        ledger(userToken(ROOMY_TENANT, "ezzat")).expectHeader().valueEquals("X-RateLimit-Burst-Capacity", "6");
        ledger(userToken(freshTenant(), "ezzat")).expectHeader().valueEquals("X-RateLimit-Burst-Capacity", "3");
    }

    /**
     * Every request comes through a fresh client, so the only thing the four share is the
     * tenant: were the limiter keyed by client, each request would get a fresh bucket and the
     * fourth would still be allowed.
     */
    @Test
    void usersOfOneTenantShareABucket() {
        String tenant = freshTenant();
        ledger(userToken(tenant, "alice", "c-" + UUID.randomUUID())).expectStatus().isOk();
        ledger(userToken(tenant, "alice", "c-" + UUID.randomUUID())).expectStatus().isOk();
        ledger(userToken(tenant, "bob", "c-" + UUID.randomUUID())).expectStatus().isOk();

        ledger(userToken(tenant, "bob", "c-" + UUID.randomUUID())).expectStatus().isEqualTo(429);
    }

    @Test
    void twoClientsDoNotShareABucket() {
        String first = clientToken("c-" + UUID.randomUUID());
        String second = clientToken("c-" + UUID.randomUUID());
        for (int i = 0; i < 3; i++) {
            ledger(first).expectStatus().isOk();
        }

        ledger(second).expectStatus().isOk().expectHeader().valueEquals("X-RateLimit-Remaining", "2");
    }

    /** Authentication and the rule table run first: their refusals are never counted. */
    @Test
    void refusalsBeforeTheLimiterCarryNoHeadersAndTouchNoRedis() {
        String tenant = freshTenant();

        client.get().uri("/api/ledger/entries").exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().doesNotExist("X-RateLimit-Remaining");
        client.get().uri("/api/unknown")
                .header(HttpHeaders.AUTHORIZATION, userToken(tenant, "ezzat"))
                .exchange()
                .expectStatus().isForbidden()
                .expectHeader().doesNotExist("X-RateLimit-Remaining");

        RateLimitIdentity identity = new RateLimitIdentity(RateLimitIdentity.Kind.TENANT, tenant);
        assertThat(redis.hasKey(RedisRateLimitStore.bucketKey(identity)).block()).isFalse();
        assertThat(redis.hasKey(RedisRateLimitStore.quotaKey(identity)).block()).isFalse();
    }

    /**
     * The health probe is not a gateway route, so the limiter never runs against it. Authenticated
     * on purpose: an anonymous request carries no headers anyway, since it has no identity for the
     * limiter to key on, so it could not tell "not a gateway route" from "no identity". A valid
     * bearer rules that out — health is {@code permitAll}, so it is still 200.
     */
    @Test
    void theHealthProbeCarriesNoRateLimitHeaders() {
        client.get().uri("/actuator/health")
                .header(HttpHeaders.AUTHORIZATION, userToken(freshTenant(), "ezzat"))
                .exchange()
                .expectStatus().isOk()
                .expectHeader().doesNotExist("X-RateLimit-Remaining");
    }

    private WebTestClient.ResponseSpec ledger(String bearer) {
        return client.get().uri("/api/ledger/entries").header(HttpHeaders.AUTHORIZATION, bearer).exchange();
    }

    private static String freshTenant() {
        return "t-" + UUID.randomUUID();
    }

    private static String userToken(String tenant, String subject) {
        return userToken(tenant, subject, "authcore-spa");
    }

    private static String userToken(String tenant, String subject, String clientId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("scope", List.of("payments:read"));
        claims.put("tenant", tenant);
        claims.put("aud", List.of(clientId));
        return "Bearer " + signingKey.mint(ISSUER, subject, Instant.now().plus(5, ChronoUnit.MINUTES), claims);
    }

    private static String clientToken(String clientId) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("scope", List.of("payments:read"));
        claims.put("aud", List.of(clientId));
        return "Bearer " + signingKey.mint(ISSUER, clientId, Instant.now().plus(5, ChronoUnit.MINUTES), claims);
    }
}
