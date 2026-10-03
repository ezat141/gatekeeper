package com.gatekeeper.resilience;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.gatekeeper.support.TestKey;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
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

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * One breaker per downstream: what opens it, what it answers while open, how it recovers, and what it
 * never counts. The M7 design, sections 6 to 8. Small values (a window of 4, open for 1 s) keep it fast;
 * {@code ProductionValuesTest} pins the real ones.
 *
 * <p>POST throughout, so the GET-only retry (the M7 design, section 9) never changes how many calls the downstream sees.
 * Breakers are reset before each test: they live for the whole context.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@ExtendWith(OutputCaptureExtension.class)
class DownstreamCircuitBreakerTest {

    static final String ISSUER = "http://localhost:8080";
    static WireMockServer downstream;
    static TestKey signingKey;

    @Autowired
    WebTestClient client;

    @Autowired
    ReactiveResilience4JCircuitBreakerFactory breakers;

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
        registry.add("gatekeeper.resilience.breaker.sliding-window-size", () -> "4");
        registry.add("gatekeeper.resilience.breaker.minimum-calls", () -> "4");
        registry.add("gatekeeper.resilience.breaker.open-for", () -> "1s");
        registry.add("gatekeeper.resilience.breaker.trial-calls", () -> "1");
        registry.add("gatekeeper.resilience.response-timeout-millis.ledger", () -> "300");
    }

    @BeforeEach
    void reset() {
        downstream.resetAll();
        downstream.stubFor(get(urlEqualTo("/oauth2/jwks")).willReturn(okJson(TestKey.jwksDocument(signingKey))));
        downstream.stubFor(get(urlEqualTo("/api/machine/payments")).willReturn(okJson("[]")));
        // find, never circuitBreaker(name): creating one here would bypass the gateway's configuration.
        breakers.getCircuitBreakerRegistry().getAllCircuitBreakers().forEach(CircuitBreaker::reset);
    }

    @Test
    void repeatedServiceUnavailableOpensItAndThenNothingReachesTheDownstream(CapturedOutput output) {
        downstream.stubFor(post(urlEqualTo("/ledger/entries")).willReturn(aResponse().withStatus(503)));
        for (int i = 0; i < 4; i++) {
            postEntry().expectStatus().isEqualTo(503).expectBody().jsonPath("$.detail").isEqualTo("DOWNSTREAM_ERROR");
        }

        for (int i = 0; i < 3; i++) {
            postEntry()
                    .expectStatus().isEqualTo(503)
                    .expectHeader().valueEquals(HttpHeaders.RETRY_AFTER, "1")
                    .expectHeader().doesNotExist(HttpHeaders.WWW_AUTHENTICATE)
                    .expectBody()
                    .jsonPath("$.error").isEqualTo("service_unavailable")
                    .jsonPath("$.detail").isEqualTo("DOWNSTREAM_UNAVAILABLE");
        }

        downstream.verify(4, postRequestedFor(urlEqualTo("/ledger/entries")));
        assertThat(state("ledger")).isEqualTo(CircuitBreaker.State.OPEN);
        // Logged once, not once per request: the listener is registered once per breaker.
        assertThat(output.getOut().split("Downstream ledger: circuit breaker opened", -1)).hasSize(2);
    }

    /**
     * 502, 503 and 504 are availability signals: they count, and their bodies and headers are replaced
     * by the gateway's shape, keeping the status. The M7 design, section 7.
     */
    @Test
    void countedStatusesAreReplacedByTheGatewaysShapeHeadersIncluded() {
        for (int status : new int[] {502, 503, 504}) {
            downstream.stubFor(post(urlEqualTo("/ledger/entries")).willReturn(aResponse().withStatus(status)
                    .withHeader("X-Upstream", "yes")
                    .withHeader("Set-Cookie", "session=downstream")
                    .withHeader("Content-Type", "text/html")
                    .withBody("<html>downstream page</html>")));

            postEntry()
                    .expectStatus().isEqualTo(status)
                    .expectHeader().contentType(MediaType.APPLICATION_JSON)
                    .expectHeader().doesNotExist("X-Upstream")
                    .expectHeader().doesNotExist(HttpHeaders.SET_COOKIE)
                    .expectBody()
                    .jsonPath("$.status").isEqualTo(status)
                    .jsonPath("$.path").isEqualTo("/api/ledger/entries")
                    .jsonPath("$.detail").isEqualTo("DOWNSTREAM_ERROR");
            breakers.getCircuitBreakerRegistry().getAllCircuitBreakers().forEach(CircuitBreaker::reset);
        }
    }

    /**
     * A 500 is the downstream's own answer: it passes through untouched — status, headers and body,
     * byte for byte — and never counts, however many there are. The M7 design, section 7.
     */
    @Test
    void fiveHundredsPassThroughUntouchedAndNeverOpenIt() {
        String body = "{\"error\":\"internal_server_error\",\"downstream\":\"own diagnostics\"}";
        downstream.stubFor(post(urlEqualTo("/ledger/entries")).willReturn(aResponse().withStatus(500)
                .withHeader("Content-Type", "application/json")
                .withHeader("X-Upstream", "yes")
                .withBody(body)));

        for (int i = 0; i < 10; i++) {
            byte[] received = postEntry()
                    .expectStatus().isEqualTo(500)
                    .expectHeader().valueEquals("X-Upstream", "yes")
                    .expectBody().returnResult().getResponseBody();
            assertThat(new String(received)).isEqualTo(body);
        }

        downstream.verify(10, postRequestedFor(urlEqualTo("/ledger/entries")));
        assertThat(state("ledger")).isEqualTo(CircuitBreaker.State.CLOSED);
        assertThat(breakers.getCircuitBreakerRegistry().find("ledger").orElseThrow().getMetrics().getNumberOfFailedCalls())
                .isZero();
    }

    @Test
    void timeoutsCountAsFailures() {
        downstream.stubFor(post(urlEqualTo("/ledger/entries")).willReturn(aResponse().withFixedDelay(800).withStatus(200)));
        for (int i = 0; i < 4; i++) {
            postEntry().expectStatus().isEqualTo(504);
        }

        postEntry().expectStatus().isEqualTo(503).expectBody().jsonPath("$.detail").isEqualTo("DOWNSTREAM_UNAVAILABLE");
    }

    @Test
    void oneSuccessfulTrialAfterTheOpenWindowClosesIt() throws InterruptedException {
        downstream.stubFor(post(urlEqualTo("/ledger/entries")).willReturn(aResponse().withStatus(503)));
        for (int i = 0; i < 4; i++) {
            postEntry().expectStatus().isEqualTo(503);
        }
        assertThat(state("ledger")).isEqualTo(CircuitBreaker.State.OPEN);
        downstream.stubFor(post(urlEqualTo("/ledger/entries")).willReturn(okJson("{}")));

        Thread.sleep(1200);

        postEntry().expectStatus().isOk();
        assertThat(state("ledger")).isEqualTo(CircuitBreaker.State.CLOSED);
    }

    /** Each downstream has its own breaker: ledger's being open does not cut AuthCore off. */
    @Test
    void onlyTheSickDownstreamIsCutOff() {
        downstream.stubFor(post(urlEqualTo("/ledger/entries")).willReturn(aResponse().withStatus(503)));
        for (int i = 0; i < 4; i++) {
            postEntry().expectStatus().isEqualTo(503);
        }

        client.get().uri("/api/machine/payments")
                .header(HttpHeaders.AUTHORIZATION, token())
                .exchange()
                .expectStatus().isOk();
        assertThat(state("ledger")).isEqualTo(CircuitBreaker.State.OPEN);
        assertThat(state("authcore")).isEqualTo(CircuitBreaker.State.CLOSED);
    }

    /**
     * A caller's own failure is not the downstream's: a claim that Netty refuses to forward fails inside
     * the routing filter, the caller gets 401, and the breaker must count it neither for nor against the
     * downstream. Otherwise one caller could cut the downstream off for everyone, or pad its success
     * count. The M7 design, sections 6 and 7.
     */
    @Test
    void aCallersBadRequestNeverCountsAgainstTheDownstream() {
        downstream.stubFor(post(urlEqualTo("/ledger/entries")).willReturn(okJson("{}")));
        String badToken = "Bearer " + signingKey.mint(ISSUER, "ezzat", Instant.now().plus(5, ChronoUnit.MINUTES),
                Map.of("tenant", "acme", "scope", List.of("payments:read", "payments:write"),
                        "permissions", List.of("evil\r\nX-Injected: yes")));

        for (int i = 0; i < 6; i++) {
            client.post().uri("/api/ledger/entries")
                    .header(HttpHeaders.AUTHORIZATION, badToken)
                    .contentType(MediaType.APPLICATION_JSON)
                    .bodyValue("{}")
                    .exchange()
                    .expectStatus().isUnauthorized();
        }

        assertThat(state("ledger")).isEqualTo(CircuitBreaker.State.CLOSED);
        // The six requests went through the breaker filter, so the breaker exists by now. Neutral: not
        // failures, and not successes either, which in half-open could close it unreached.
        CircuitBreaker.Metrics metrics = breakers.getCircuitBreakerRegistry().find("ledger").orElseThrow().getMetrics();
        assertThat(metrics.getNumberOfFailedCalls()).isZero();
        assertThat(metrics.getNumberOfSuccessfulCalls()).isZero();
        postEntry().expectStatus().isOk();
    }

    private WebTestClient.ResponseSpec postEntry() {
        return client.post().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, token())
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue("{}")
                .exchange();
    }

    private CircuitBreaker.State state(String name) {
        return breakers.getCircuitBreakerRegistry().find(name).orElseThrow().getState();
    }

    private static String token() {
        return "Bearer " + signingKey.mint(ISSUER, "ezzat", Instant.now().plus(5, ChronoUnit.MINUTES),
                Map.of("tenant", "acme", "scope", List.of("payments:read", "payments:write")));
    }
}
