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
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;

/**
 * AuthCore publishes the retiring key alongside the new active one when it rotates, so
 * tokens minted before the rotation keep validating until they expire. This asserts the
 * gateway honours that, which is the property making rotation zero-downtime.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class KeyRotationTest {

    static final String ISSUER = "http://localhost:8080";

    static WireMockServer authCore;
    static TestKey retiringKey;
    static TestKey activeKey;
    static TestKey futureKey;

    @Autowired
    WebTestClient client;

    @BeforeAll
    static void start() {
        retiringKey = TestKey.generate("k0");
        activeKey = TestKey.generate("k1");
        futureKey = TestKey.generate("k2");

        authCore = new WireMockServer(options().dynamicPort());
        authCore.start();
        // Both the active and the retiring key, as AuthCore serves them mid-rotation.
        authCore.stubFor(get(urlEqualTo("/oauth2/jwks"))
                .willReturn(okJson(TestKey.jwksDocument(activeKey, retiringKey))));
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

    private WebTestClient.ResponseSpec callWith(TestKey key) {
        String token = key.mint(ISSUER, "ezzat",
                Instant.now().plus(5, ChronoUnit.MINUTES), Map.of("tenant", "acme"));
        return client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange();
    }

    @Test
    void acceptsATokenSignedWithTheActiveKey() {
        callWith(activeKey).expectStatus().isOk();
    }

    /**
     * The zero-downtime half. A token minted before the rotation is still in a user's hands
     * and must keep working until it expires — otherwise every rotation logs everyone out.
     */
    @Test
    void stillAcceptsATokenSignedWithTheRetiringKey() {
        callWith(retiringKey).expectStatus().isOk();
    }

    /**
     * Rotation proper, and the only test here that could not pass with a decoder that
     * fetched the key set once and cached it forever. The gateway has never seen k2. It is
     * refused, AuthCore then publishes it, and the very same kind of token is accepted —
     * without a restart, and without the gateway holding any key material of its own.
     */
    @Test
    void picksUpANewlyPublishedKeyWithoutARestart() {
        callWith(futureKey).expectStatus().isUnauthorized();

        authCore.stubFor(get(urlEqualTo("/oauth2/jwks"))
                .willReturn(okJson(TestKey.jwksDocument(futureKey, activeKey, retiringKey))));

        callWith(futureKey).expectStatus().isOk();
    }
}
