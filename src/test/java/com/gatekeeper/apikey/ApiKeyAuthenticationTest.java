package com.gatekeeper.apikey;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.gatekeeper.support.TestKey;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * M3 adds a second credential; this file pins what happens on the one request-shape M2
 * never had to consider: both an {@code X-API-Key} and an {@code Authorization} header on
 * the same request. See the precedence table in {@code GatewaySecurityConfig}'s Javadoc on
 * {@code apiKeyAuthenticationWebFilter}.
 *
 * <p>Every proxied ("OK") case below reaches the same WireMock stub that answers 200
 * unconditionally — route-level authorization is still M4 — so a 200 here means only "the
 * gateway's own security chain let the request through," never "the credential was
 * appropriate for the route."
 *
 * <p>Every test that touches introspection uses a freshly random key from {@link #newKey()}
 * rather than a fixed literal. Redis is the same instance AuthCore uses and persists between
 * test methods (and between separate runs of this class within the positive TTL), so a fixed
 * key would let an earlier test's cached answer decide a later test's outcome — the exact
 * trap {@link #introspectsOnceForTwoRequestsInsideTheTtl()} would otherwise fall into
 * silently.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class ApiKeyAuthenticationTest {

    static final String ISSUER = "http://localhost:8080";
    static final String INTROSPECT_PATH = "/api/internal/api-keys/introspect";
    static final String LEDGER_PATH = "/api/ledger/entries";

    static WireMockServer authCore;
    static TestKey activeKey;

    @Autowired
    WebTestClient client;

    @BeforeAll
    static void startFakeAuthCore() {
        activeKey = TestKey.generate("k1");
        authCore = new WireMockServer(options().dynamicPort());
        authCore.start();
        authCore.stubFor(get(urlEqualTo("/oauth2/jwks"))
                .willReturn(okJson(TestKey.jwksDocument(activeKey))));
        authCore.stubFor(get(urlEqualTo("/ledger/entries"))
                .willReturn(aResponse().withStatus(200).withBody("[]")));
        // Catch-all, lower priority than the per-test stubs stubActiveKey() registers below:
        // any key this class never explicitly marked active reads as inactive, exactly how
        // AuthCore answers for unknown, disabled and expired keys alike (design doc section 3).
        authCore.stubFor(post(urlEqualTo(INTROSPECT_PATH))
                .atPriority(10)
                .willReturn(okJson("""
                        {"active":false}""")));
    }

    @AfterAll
    static void stop() {
        authCore.stop();
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("gatekeeper.auth.jwk-set-uri", () -> authCore.baseUrl() + "/oauth2/jwks");
        registry.add("gatekeeper.auth.issuer", () -> ISSUER);
        registry.add("gatekeeper.downstream.ledger", () -> authCore.baseUrl());
        registry.add("gatekeeper.downstream.authcore", () -> authCore.baseUrl());
        registry.add("gatekeeper.api-key.introspection-uri", () -> authCore.baseUrl() + INTROSPECT_PATH);
    }

    // --- Precedence table -------------------------------------------------------------

    @Test
    void refusesARequestWithNeitherCredential() {
        client.get().uri(LEDGER_PATH)
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().valueMatches(HttpHeaders.WWW_AUTHENTICATE, "Bearer.*")
                .expectBody()
                .jsonPath("$.error").isEqualTo("unauthorized")
                .jsonPath("$.status").isEqualTo(401)
                .jsonPath("$.path").isEqualTo(LEDGER_PATH);
    }

    /** No {@code X-API-Key} at all: the converter returns empty, so this must behave exactly
     * as it did in M2. */
    @Test
    void proxiesARequestWithOnlyAValidToken() {
        String token = activeKey.mint(ISSUER, "ezzat",
                Instant.now().plus(5, ChronoUnit.MINUTES),
                Map.of("tenant", "acme", "permissions", List.of("payments:read")));

        client.get().uri(LEDGER_PATH)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void proxiesARequestWithOnlyAValidKey() {
        String rawKey = stubActiveKey("reporting");

        client.get().uri(LEDGER_PATH)
                .header(ApiKeyAuthenticationConverter.HEADER_NAME, rawKey)
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void authenticatesAsTheKeyWhenAValidTokenIsAlsoPresent() {
        String rawKey = stubActiveKey("reporting");
        String token = activeKey.mint(ISSUER, "ezzat",
                Instant.now().plus(5, ChronoUnit.MINUTES), Map.of("tenant", "acme"));

        client.get().uri(LEDGER_PATH)
                .header(ApiKeyAuthenticationConverter.HEADER_NAME, rawKey)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isOk();
    }

    /**
     * The row that matters: without this, a caller could smuggle a bad key past the gateway
     * by also attaching a good token. The key must decide before the bearer is ever
     * consulted, so this must stay 401 despite the attached token being perfectly valid.
     */
    @Test
    void refusesAnInvalidKeyEvenWithAValidTokenAttached() {
        String badKey = newKey();
        String token = activeKey.mint(ISSUER, "ezzat",
                Instant.now().plus(5, ChronoUnit.MINUTES), Map.of("tenant", "acme"));

        client.get().uri(LEDGER_PATH)
                .header(ApiKeyAuthenticationConverter.HEADER_NAME, badKey)
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody()
                .jsonPath("$.error").isEqualTo("unauthorized")
                .jsonPath("$.status").isEqualTo(401)
                .jsonPath("$.path").isEqualTo(LEDGER_PATH);
    }

    @Test
    void refusesAnInvalidKeyWithNoTokenAttached() {
        String badKey = newKey();

        client.get().uri(LEDGER_PATH)
                .header(ApiKeyAuthenticationConverter.HEADER_NAME, badKey)
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody()
                .jsonPath("$.error").isEqualTo("unauthorized")
                .jsonPath("$.status").isEqualTo(401)
                .jsonPath("$.path").isEqualTo(LEDGER_PATH);
    }

    // --- Caching ------------------------------------------------------------------------

    /**
     * Counting requests to AuthCore is the assertion that actually proves caching. A test
     * that merely calls twice and expects 200 both times would pass exactly as well with no
     * cache at all — only the request count on the fake AuthCore distinguishes the two.
     *
     * <p>{@code resetRequests()} clears WireMock's log immediately before the two calls this
     * test cares about; the unique key from {@link #newKey()} is what keeps Redis itself
     * cache-cold, since resetting the request log does nothing to a previously-cached answer.
     */
    @Test
    void introspectsOnceForTwoRequestsInsideTheTtl() {
        String rawKey = stubActiveKey("cache-test-caller");
        authCore.resetRequests();

        for (int i = 0; i < 2; i++) {
            client.get().uri(LEDGER_PATH)
                    .header(ApiKeyAuthenticationConverter.HEADER_NAME, rawKey)
                    .exchange()
                    .expectStatus().isOk();
        }

        assertThat(authCore.findAll(postRequestedFor(urlEqualTo(INTROSPECT_PATH)))).hasSize(1);
    }

    // --- Helpers --------------------------------------------------------------------------

    /** A fresh key per call. Never reused across tests, so Redis's cross-test persistence
     * can never make one test's cached answer the reason another test passes. */
    private static String newKey() {
        return "ak_test_" + UUID.randomUUID();
    }

    /** Registers a higher-priority stub answering active for one freshly generated key, and
     * returns that key. */
    private static String stubActiveKey(String name) {
        String rawKey = newKey();
        authCore.stubFor(post(urlEqualTo(INTROSPECT_PATH))
                .atPriority(1)
                .withRequestBody(equalToJson("{\"key\":\"" + rawKey + "\"}"))
                .willReturn(okJson("""
                        {"active":true,"name":"%s","scopes":["payments:read"]}"""
                        .formatted(name))));
        return rawKey;
    }
}
