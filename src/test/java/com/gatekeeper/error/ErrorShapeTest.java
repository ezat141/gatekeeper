package com.gatekeeper.error;

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
 * One JSON error shape ({@code error}, {@code status}, {@code path}) regardless of which
 * layer refused the request. The second test here is one of two paths that used to
 * misreport as a 500 — see the class Javadoc on {@link GlobalErrorWebExceptionHandler} for
 * why it is actually a 401 in disguise. The unreachable-JWKS case is the other one, and it
 * lives in {@link UnreachableJwksErrorShapeTest} because it needs a {@code
 * gatekeeper.auth.jwk-set-uri} that cannot coexist with this class's live WireMock JWKS in
 * the same {@code @DynamicPropertySource}.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class ErrorShapeTest {

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
    void rendersUnauthorizedAsJson() {
        client.get().uri("/api/ledger/entries")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().valueMatches(HttpHeaders.WWW_AUTHENTICATE, "Bearer.*")
                .expectBody()
                .jsonPath("$.error").isEqualTo("unauthorized")
                .jsonPath("$.status").isEqualTo(401)
                .jsonPath("$.path").isEqualTo("/api/ledger/entries");
    }

    /**
     * The claim carries a bare CR/LF pair — a header-injection probe. {@code
     * IdentityStampFilter} does not validate the value it stamps; Spring's reactive {@code
     * HttpHeaders.set()} stores it without complaint, so the failure does not surface until
     * {@code NettyRoutingFilter} copies the header onto the outbound Netty request and
     * Netty's own header validation refuses it. That refusal must not read as a server
     * fault: the gateway derived the identity correctly but cannot forward it, which is as
     * much a failure to establish who the caller is as a bad signature would be.
     */
    @Test
    void rendersAClaimWithAControlCharacterAsUnauthorizedNotServerError() {
        String token = activeKey.mint(ISSUER, "ezzat",
                Instant.now().plus(5, ChronoUnit.MINUTES),
                Map.of("tenant", "acme", "permissions", List.of("evil\r\nX-Injected: yes")));

        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isUnauthorized()
                .expectBody()
                .jsonPath("$.error").isEqualTo("unauthorized")
                .jsonPath("$.status").isEqualTo(401)
                .jsonPath("$.path").isEqualTo("/api/ledger/entries");
    }
}
