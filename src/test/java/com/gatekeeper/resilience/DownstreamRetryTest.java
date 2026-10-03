package com.gatekeeper.resilience;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.stubbing.Scenario;
import com.gatekeeper.support.TestKey;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.cloud.circuitbreaker.resilience4j.ReactiveResilience4JCircuitBreakerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * One retry, for GET only, after 100 ms, on 502, 503 and connect errors; never a POST, a timeout or a
 * 500. Inside the breaker: it sees one outcome per client request. And a retry spends no extra
 * rate-limit token. The M7 design, section 9.
 *
 * <p>Each test calls as a fresh tenant on a small plan, so its rate-limit count starts full.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class DownstreamRetryTest {

    static final String ISSUER = "http://localhost:8080";
    static WireMockServer downstream;
    static TestKey signingKey;

    @Autowired
    WebTestClient client;

    @Autowired
    ReactiveResilience4JCircuitBreakerFactory breakers;

    String tenant;

    @BeforeAll
    static void start() {
        signingKey = TestKey.generate("k1");
        downstream = new WireMockServer(options().dynamicPort());
        downstream.start();
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
        registry.add("gatekeeper.resilience.response-timeout-millis.ledger", () -> "300");
        registry.add("gatekeeper.rate-limit.default-plan", () -> "retry10");
        registry.add("gatekeeper.rate-limit.plans.retry10.requests-per-second", () -> "1");
        registry.add("gatekeeper.rate-limit.plans.retry10.burst", () -> "10");
        registry.add("gatekeeper.rate-limit.plans.retry10.daily-quota", () -> "1000");
    }

    @BeforeEach
    void reset() {
        tenant = "retry-" + UUID.randomUUID();
        downstream.resetAll();
        downstream.stubFor(get(urlEqualTo("/oauth2/jwks")).willReturn(okJson(TestKey.jwksDocument(signingKey))));
        breakers.getCircuitBreakerRegistry().getAllCircuitBreakers().forEach(CircuitBreaker::reset);
    }

    @Test
    void aGetIsRetriedOnceOnServiceUnavailableAndSucceeds() {
        flakyOnce(503);

        getEntries().expectStatus().isOk();

        downstream.verify(2, getRequestedFor(urlEqualTo("/ledger/entries")));
    }

    @Test
    void aGetIsRetriedOnceOnBadGatewayAndSucceeds() {
        flakyOnce(502);

        getEntries().expectStatus().isOk();

        downstream.verify(2, getRequestedFor(urlEqualTo("/ledger/entries")));
    }

    @Test
    void onlyOnce() {
        downstream.stubFor(get(urlEqualTo("/ledger/entries")).willReturn(aResponse().withStatus(503)));

        getEntries().expectStatus().isEqualTo(503).expectBody().jsonPath("$.detail").isEqualTo("DOWNSTREAM_ERROR");

        downstream.verify(2, getRequestedFor(urlEqualTo("/ledger/entries")));
    }

    @Test
    void aPostIsNeverRetried() {
        downstream.stubFor(post(urlEqualTo("/ledger/entries")).willReturn(aResponse().withStatus(503)));

        client.post().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, token())
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{}")
                .exchange()
                .expectStatus().isEqualTo(503);

        downstream.verify(1, postRequestedFor(urlEqualTo("/ledger/entries")));
    }

    @Test
    void aTimeoutIsNotRetried() {
        downstream.stubFor(get(urlEqualTo("/ledger/entries")).willReturn(aResponse().withFixedDelay(800).withStatus(200)));

        getEntries().expectStatus().isEqualTo(504);

        downstream.verify(1, getRequestedFor(urlEqualTo("/ledger/entries")));
    }

    @Test
    void aFiveHundredIsNotRetried() {
        downstream.stubFor(get(urlEqualTo("/ledger/entries")).willReturn(aResponse().withStatus(500).withBody("own")));

        getEntries().expectStatus().isEqualTo(500).expectBody(String.class).isEqualTo("own");

        downstream.verify(1, getRequestedFor(urlEqualTo("/ledger/entries")));
    }

    /** Inside the breaker: a request that succeeds on its retry is one success, not a failure and a success. */
    @Test
    void theBreakerSeesOneOutcomePerRequest() {
        flakyOnce(503);

        getEntries().expectStatus().isOk();

        CircuitBreaker.Metrics metrics = breakers.getCircuitBreakerRegistry().find("ledger").orElseThrow().getMetrics();
        assertThat(metrics.getNumberOfFailedCalls()).isZero();
        assertThat(metrics.getNumberOfSuccessfulCalls()).isEqualTo(1);
    }

    /** The rate limiter runs before the route's filters, so a retried request costs one token. */
    @Test
    void aRetriedRequestCostsOneRateLimitToken() {
        flakyOnce(503);

        getEntries().expectStatus().isOk().expectHeader().valueEquals("X-RateLimit-Remaining", "9");
    }

    private void flakyOnce(int status) {
        downstream.stubFor(get(urlEqualTo("/ledger/entries")).inScenario("flaky")
                .whenScenarioStateIs(Scenario.STARTED)
                .willReturn(aResponse().withStatus(status))
                .willSetStateTo("recovered"));
        downstream.stubFor(get(urlEqualTo("/ledger/entries")).inScenario("flaky")
                .whenScenarioStateIs("recovered")
                .willReturn(okJson("[]")));
    }

    private WebTestClient.ResponseSpec getEntries() {
        return client.get().uri("/api/ledger/entries").header(HttpHeaders.AUTHORIZATION, token()).exchange();
    }

    private String token() {
        return "Bearer " + signingKey.mint(ISSUER, "ezzat", Instant.now().plus(5, ChronoUnit.MINUTES),
                Map.of("tenant", tenant, "scope", List.of("payments:read", "payments:write")));
    }
}
