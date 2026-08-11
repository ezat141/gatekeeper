package com.gatekeeper.routing;

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
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;

/**
 * The gateway authenticates every request now (Task 9), so these assertions carry a valid
 * bearer token throughout and are purely about whether an authenticated request reaches the
 * right downstream at the right path.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class RoutingTest {

    static WireMockServer downstream;
    static TestKey key;

    @Autowired
    WebTestClient client;

    @BeforeAll
    static void startDownstream() {
        key = TestKey.generate("k1");
        downstream = new WireMockServer(options().dynamicPort());
        downstream.start();
        downstream.stubFor(get(urlEqualTo("/ledger/entries"))
                .willReturn(aResponse().withStatus(200).withBody("[]")));
        downstream.stubFor(get(urlEqualTo("/api/accounts/me"))
                .willReturn(aResponse().withStatus(200).withBody("{}")));
        downstream.stubFor(get(urlEqualTo("/api/machine/payments"))
                .willReturn(aResponse().withStatus(200).withBody("[]")));
        downstream.stubFor(get(urlEqualTo("/oauth2/jwks"))
                .willReturn(okJson(TestKey.jwksDocument(key))));
    }

    @AfterAll
    static void stopDownstream() {
        downstream.stop();
    }

    @DynamicPropertySource
    static void downstreamUris(DynamicPropertyRegistry registry) {
        registry.add("gatekeeper.downstream.ledger", () -> downstream.baseUrl());
        registry.add("gatekeeper.downstream.authcore", () -> downstream.baseUrl());
        registry.add("gatekeeper.auth.jwk-set-uri", () -> downstream.baseUrl() + "/oauth2/jwks");
        registry.add("gatekeeper.auth.issuer", () -> "http://localhost:8080");
    }

    private static String bearerToken() {
        return "Bearer " + key.mint("http://localhost:8080", "ezzat",
                Instant.now().plus(5, ChronoUnit.MINUTES), Map.of("tenant", "acme"));
    }

    /**
     * StripPrefix=1 must remove /api before ledger-service sees the path — that service
     * serves /ledger/**, not /api/ledger/**.
     */
    @Test
    void stripsTheApiPrefixOnTheLedgerRoute() {
        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, bearerToken())
                .exchange().expectStatus().isOk();
        downstream.verify(getRequestedFor(urlEqualTo("/ledger/entries")));
    }

    /** AuthCore serves /api/accounts verbatim, so this route must NOT be stripped. */
    @Test
    void preservesTheFullPathOnTheAuthCoreAccountsRoute() {
        client.get().uri("/api/accounts/me")
                .header(HttpHeaders.AUTHORIZATION, bearerToken())
                .exchange().expectStatus().isOk();
        downstream.verify(getRequestedFor(urlEqualTo("/api/accounts/me")));
    }

    /** The machine route is equally unstripped. */
    @Test
    void preservesTheFullPathOnTheAuthCoreMachineRoute() {
        client.get().uri("/api/machine/payments")
                .header(HttpHeaders.AUTHORIZATION, bearerToken())
                .exchange().expectStatus().isOk();
        downstream.verify(getRequestedFor(urlEqualTo("/api/machine/payments")));
    }

    /** A path matching no route predicate must not reach any downstream. */
    @Test
    void doesNotRouteAnUnmatchedPath() {
        client.get().uri("/api/unknown/thing")
                .header(HttpHeaders.AUTHORIZATION, bearerToken())
                .exchange().expectStatus().isNotFound();
    }
}
