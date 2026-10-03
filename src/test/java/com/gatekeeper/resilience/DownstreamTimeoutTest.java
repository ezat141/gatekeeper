package com.gatekeeper.resilience;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.gatekeeper.support.TestKey;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * A downstream that answers too slowly is answered 504 DOWNSTREAM_TIMEOUT within the route's own
 * timeout. The global timeout is set long here and the ledger route's short, so a pass proves the
 * per-route value is the one in force. The M7 design, section 5.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class DownstreamTimeoutTest {

    static final String ISSUER = "http://localhost:8080";
    static WireMockServer downstream;
    static TestKey signingKey;

    @Autowired
    WebTestClient client;

    @BeforeAll
    static void start() {
        signingKey = TestKey.generate("k1");
        downstream = new WireMockServer(options().dynamicPort());
        downstream.start();
        downstream.stubFor(get(urlEqualTo("/oauth2/jwks")).willReturn(okJson(TestKey.jwksDocument(signingKey))));
        downstream.stubFor(get(urlEqualTo("/ledger/slow")).willReturn(aResponse().withFixedDelay(1500).withStatus(200)));
        downstream.stubFor(post(urlEqualTo("/ledger/slow")).willReturn(aResponse().withFixedDelay(1500).withStatus(200)));
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
        registry.add("spring.cloud.gateway.server.webflux.httpclient.response-timeout", () -> "10s");
        registry.add("gatekeeper.resilience.response-timeout-millis.ledger", () -> "300");
    }

    @Test
    void aSlowGetIsAnsweredGatewayTimeoutWithinTheRouteTimeout() {
        long started = System.nanoTime();

        client.get().uri("/api/ledger/slow")
                .header(HttpHeaders.AUTHORIZATION, token())
                .exchange()
                .expectStatus().isEqualTo(504)
                .expectHeader().doesNotExist(HttpHeaders.RETRY_AFTER)
                .expectHeader().doesNotExist(HttpHeaders.WWW_AUTHENTICATE)
                .expectBody()
                .jsonPath("$.error").isEqualTo("gateway_timeout")
                .jsonPath("$.status").isEqualTo(504)
                .jsonPath("$.path").isEqualTo("/api/ledger/slow")
                .jsonPath("$.detail").isEqualTo("DOWNSTREAM_TIMEOUT");

        assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofMillis(1200));
    }

    /** For a POST the outcome is unknown — the downstream may have processed it — and 504 says so. */
    @Test
    void aSlowPostIsAnsweredGatewayTimeout() {
        client.post().uri("/api/ledger/slow")
                .header(HttpHeaders.AUTHORIZATION, token())
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{}")
                .exchange()
                .expectStatus().isEqualTo(504)
                .expectBody().jsonPath("$.detail").isEqualTo("DOWNSTREAM_TIMEOUT");
    }

    private static String token() {
        return "Bearer " + signingKey.mint(ISSUER, "ezzat", Instant.now().plus(5, ChronoUnit.MINUTES),
                Map.of("tenant", "acme", "scope", List.of("payments:read", "payments:write")));
    }
}
