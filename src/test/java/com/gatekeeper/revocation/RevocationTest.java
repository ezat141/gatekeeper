package com.gatekeeper.revocation;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.gatekeeper.support.TestKey;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.atomic.AtomicInteger;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * A revoked token, end to end, against the real Redis: refused with the ordinary 401 before
 * authorization, rate limiting or routing. The M6 design, sections 3, 6, 8 and 11.
 *
 * <p>The real store is wrapped in one that counts its calls, so "never asked" is an assertion,
 * not an assumption: an API-key caller and a token the inner decoder rejects must not reach it.
 *
 * <p>Every test uses a fresh tenant and a fresh {@code jti}, and deletes the deny-list entries it
 * writes: this Redis is shared with AuthCore and every other test.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class RevocationTest {

    static final String ISSUER = "http://localhost:8080";
    static final String INTROSPECT_PATH = "/api/internal/api-keys/introspect";
    static final AtomicInteger storeCalls = new AtomicInteger();

    static WireMockServer downstream;
    static TestKey signingKey;

    @Autowired
    WebTestClient client;

    @Autowired
    ReactiveStringRedisTemplate redis;

    private final List<String> written = new ArrayList<>();

    @TestConfiguration
    static class CountingStore {

        @Bean
        @Primary
        RevocationStore countingRevocationStore(@Qualifier("revocationStore") RevocationStore real) {
            return jti -> {
                storeCalls.incrementAndGet();
                return real.isRevoked(jti);
            };
        }
    }

    @BeforeAll
    static void start() {
        signingKey = TestKey.generate("k1");
        downstream = new WireMockServer(options().dynamicPort());
        downstream.start();
        downstream.stubFor(get(urlEqualTo("/oauth2/jwks")).willReturn(okJson(TestKey.jwksDocument(signingKey))));
        downstream.stubFor(get(urlEqualTo("/ledger/entries")).willReturn(okJson("[]")));
        downstream.stubFor(get(urlEqualTo("/api/machine/payments")).willReturn(aResponse().withStatus(200).withBody("[]")));
        downstream.stubFor(post(urlEqualTo(INTROSPECT_PATH)).atPriority(10).willReturn(okJson("""
                {"active":false}""")));
    }

    @AfterAll
    static void stop() {
        downstream.stop();
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("gatekeeper.auth.jwk-set-uri", () -> downstream.baseUrl() + "/oauth2/jwks");
        registry.add("gatekeeper.auth.issuer", () -> ISSUER);
        registry.add("gatekeeper.downstream.ledger", () -> downstream.baseUrl());
        registry.add("gatekeeper.downstream.authcore", () -> downstream.baseUrl());
        registry.add("gatekeeper.api-key.introspection-uri", () -> downstream.baseUrl() + INTROSPECT_PATH);
    }

    @BeforeEach
    void reset() {
        storeCalls.set(0);
        downstream.resetRequests();
    }

    @AfterEach
    void deleteKeys() {
        written.forEach(key -> redis.delete(key).block());
    }

    @Test
    void refusesARevokedTokenWithTheOrdinary401() {
        String tenant = freshTenant();
        String token = userToken(tenant);
        revoke(token);

        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().valueEquals(HttpHeaders.WWW_AUTHENTICATE, "Bearer")
                .expectBody()
                .jsonPath("$.error").isEqualTo("unauthorized")
                .jsonPath("$.status").isEqualTo(401)
                .jsonPath("$.path").isEqualTo("/api/ledger/entries")
                .jsonPath("$.detail").doesNotExist();

        assertThat(storeCalls).hasValue(1);
        downstream.verify(0, getRequestedFor(urlEqualTo("/ledger/entries")));
        // Refused before the limiter: nothing was counted against the tenant.
        assertThat(redis.keys("gatekeeper:*" + tenant + "*").collectList().block()).isEmpty();
    }

    @Test
    void servesATokenThatIsNotRevoked() {
        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + userToken(freshTenant()))
                .exchange()
                .expectStatus().isOk();

        assertThat(storeCalls).hasValue(1);
    }

    @Test
    void refusesATokenWithNoJti() {
        String token = signingKey.mintWithJwtId(null, ISSUER, "ezzat", Instant.now().plus(5, ChronoUnit.MINUTES),
                Map.of("tenant", freshTenant(), "scope", List.of("payments:read")));

        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().valueEquals(HttpHeaders.WWW_AUTHENTICATE, "Bearer");

        assertThat(storeCalls).hasValue(0);
    }

    @Test
    void refusesATokenWithABlankJti() {
        String token = signingKey.mintWithJwtId("", ISSUER, "ezzat", Instant.now().plus(5, ChronoUnit.MINUTES),
                Map.of("tenant", freshTenant(), "scope", List.of("payments:read")));

        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isUnauthorized();

        assertThat(storeCalls).hasValue(0);
    }

    /** An expired token fails in the inner decoder and never reaches Redis (section 3). */
    @Test
    void anExpiredTokenNeverReachesTheStore() {
        String token = signingKey.mint(ISSUER, "ezzat", Instant.now().minus(5, ChronoUnit.MINUTES),
                Map.of("tenant", freshTenant(), "scope", List.of("payments:read")));

        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isUnauthorized();

        assertThat(storeCalls).hasValue(0);
    }

    /** API keys are not deny-listed; they revoke through AuthCore's enabled flag (section 12). */
    @Test
    void anApiKeyCallerIsNotChecked() {
        String rawKey = "ak_test_" + UUID.randomUUID();
        downstream.stubFor(post(urlEqualTo(INTROSPECT_PATH))
                .atPriority(1)
                .withRequestBody(equalToJson("{\"key\":\"" + rawKey + "\"}"))
                .willReturn(okJson("""
                        {"active":true,"name":"reporting","scopes":["payments:read"],"expiresAt":"%s"}"""
                        .formatted(Instant.now().plus(1, ChronoUnit.HOURS)))));

        client.get().uri("/api/machine/payments")
                .header("X-API-Key", rawKey)
                .exchange()
                .expectStatus().isOk();

        assertThat(storeCalls).hasValue(0);
    }

    private void revoke(String token) {
        String key = "authcore:revoked:jti:" + TestKey.jwtIdOf(token);
        written.add(key);
        redis.opsForValue().set(key, "revoked", Duration.ofMinutes(5)).block();
    }

    private static String freshTenant() {
        return "rv-" + UUID.randomUUID();
    }

    private static String userToken(String tenant) {
        return signingKey.mint(ISSUER, "ezzat", Instant.now().plus(5, ChronoUnit.MINUTES),
                Map.of("tenant", tenant, "scope", List.of("payments:read")));
    }
}
