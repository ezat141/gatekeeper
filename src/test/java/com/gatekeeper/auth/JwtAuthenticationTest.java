package com.gatekeeper.auth;

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

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;

/**
 * M2 answers exactly one question: is this a valid, unexpired token from AuthCore. Whether
 * the caller may reach a particular route is M4 — keeping them apart means the route rules
 * stay visible in the security config later rather than being tangled into authentication.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class JwtAuthenticationTest {

    static final String ISSUER = "http://localhost:8080";

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
    }

    @Test
    void refusesARequestWithNoToken() {
        client.get().uri("/api/ledger/entries")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().valueMatches(HttpHeaders.WWW_AUTHENTICATE, "Bearer.*");
    }

    @Test
    void proxiesARequestWithAValidToken() {
        String token = activeKey.mint(ISSUER, "ezzat",
                Instant.now().plus(5, ChronoUnit.MINUTES),
                Map.of("tenant", "acme", "permissions", List.of("payments:read")));

        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isOk();
    }

    @Test
    void refusesAnExpiredToken() {
        String token = activeKey.mint(ISSUER, "ezzat",
                Instant.now().minus(1, ChronoUnit.MINUTES), Map.of());

        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    /**
     * The trap this decoder's issuer pinning exists to catch. AuthCore derives its issuer
     * from the request host, so a token obtained at 127.0.0.1:8080 carries a different
     * {@code iss} than one obtained at localhost:8080 — same key, same signature, same
     * expiry, still refused. Failing closed is correct; this test is what stops someone
     * "fixing" the resulting 401 by removing the validator.
     */
    @Test
    void refusesATokenFromAnUnexpectedIssuer() {
        String token = activeKey.mint("http://127.0.0.1:8080", "ezzat",
                Instant.now().plus(5, ChronoUnit.MINUTES),
                Map.of("tenant", "acme"));

        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    /**
     * Signed by a key that was never published, but advertising a {@code kid} that was.
     * The decoder finds k1, attempts verification, and the signature does not match — so
     * this exercises verification failure rather than key lookup failure.
     */
    @Test
    void refusesATokenWithAnInvalidSignature() {
        TestKey foreignKey = TestKey.generate("k1");
        String token = foreignKey.mint(ISSUER, "attacker",
                Instant.now().plus(5, ChronoUnit.MINUTES), Map.of());

        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    /**
     * Advertises a {@code kid} absent from the JWKS. The decoder cannot resolve the key,
     * refetches the key set, and only then gives up — a different path from a signature
     * mismatch, and the one key rotation depends on.
     */
    @Test
    void refusesATokenWithAnUnknownKeyId() {
        String token = activeKey.mintAdvertisingKeyId("k-does-not-exist", ISSUER, "ezzat",
                Instant.now().plus(5, ChronoUnit.MINUTES), Map.of());

        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isUnauthorized();
    }

    /** Health has to stay reachable without a credential or nothing can probe liveness. */
    @Test
    void permitsHealthWithoutAToken() {
        client.get().uri("/actuator/health").exchange().expectStatus().isOk();
    }
}
