package com.gatekeeper.resilience;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.gatekeeper.support.TestKey;
import io.github.resilience4j.circuitbreaker.CircuitBreaker;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.cloud.circuitbreaker.resilience4j.ReactiveResilience4JCircuitBreakerFactory;
import org.springframework.http.HttpHeaders;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.TimeUnit;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * With a limit of 2: two slow requests in flight to ledger, and the next is refused at once 503
 * DOWNSTREAM_BUSY. Refusals count neither as breaker failures nor as successes, and AuthCore is
 * unaffected. The M7 design, section 10. The breaker's window is small here so that, were refusals
 * counted as failures, it would open.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class DownstreamBulkheadTest {

    static final String ISSUER = "http://localhost:8080";
    static WireMockServer downstream;
    static TestKey signingKey;

    @Autowired
    WebTestClient client;

    @Autowired
    ReactiveResilience4JCircuitBreakerFactory breakers;

    @LocalServerPort
    int port;

    @BeforeAll
    static void start() {
        signingKey = TestKey.generate("k1");
        downstream = new WireMockServer(options().dynamicPort().containerThreads(20));
        downstream.start();
        downstream.stubFor(get(urlEqualTo("/oauth2/jwks")).willReturn(okJson(TestKey.jwksDocument(signingKey))));
        downstream.stubFor(get(urlEqualTo("/ledger/slow")).willReturn(aResponse().withFixedDelay(1500).withStatus(200)));
        downstream.stubFor(get(urlEqualTo("/api/machine/payments")).willReturn(okJson("[]")));
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
        registry.add("gatekeeper.resilience.bulkhead.max-concurrent-calls", () -> "2");
        registry.add("gatekeeper.resilience.breaker.sliding-window-size", () -> "4");
        registry.add("gatekeeper.resilience.breaker.minimum-calls", () -> "4");
    }

    @Test
    void aFullBulkheadRefusesAtOnceWithoutCountingAgainstTheBreaker() throws Exception {
        WebClient direct = WebClient.create("http://localhost:" + port);
        List<CompletableFuture<Integer>> held = new ArrayList<>();
        for (int i = 0; i < 2; i++) {
            held.add(direct.get().uri("/api/ledger/slow").header(HttpHeaders.AUTHORIZATION, token())
                    .exchangeToMono(response -> Mono.just(response.statusCode().value()))
                    .toFuture());
        }
        // Both are now in flight, waiting on the slow downstream: wait for the downstream to have both,
        // not for a fixed time. The first requests of a cold context take over a second to arrive.
        long deadline = System.nanoTime() + Duration.ofSeconds(10).toNanos();
        while (downstream.countRequestsMatching(getRequestedFor(urlEqualTo("/ledger/slow")).build()).getCount() < 2) {
            assertThat(System.nanoTime()).as("both slow requests reach the downstream").isLessThan(deadline);
            Thread.sleep(20);
        }

        for (int i = 0; i < 6; i++) {
            long started = System.nanoTime();
            client.get().uri("/api/ledger/slow")
                    .header(HttpHeaders.AUTHORIZATION, token())
                    .exchange()
                    .expectStatus().isEqualTo(503)
                    .expectHeader().valueEquals(HttpHeaders.RETRY_AFTER, "1")
                    .expectBody()
                    .jsonPath("$.error").isEqualTo("service_unavailable")
                    .jsonPath("$.detail").isEqualTo("DOWNSTREAM_BUSY");
            // At once, not after the 1.5 s the slow downstream takes: a wait for a permit would exceed this.
            assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofMillis(1000));
        }

        // AuthCore has its own bulkhead: unaffected while ledger's is full.
        client.get().uri("/api/machine/payments").header(HttpHeaders.AUTHORIZATION, token())
                .exchange().expectStatus().isOk();

        for (CompletableFuture<Integer> request : held) {
            assertThat(request.get(5, TimeUnit.SECONDS)).isEqualTo(200);
        }
        downstream.verify(2, getRequestedFor(urlEqualTo("/ledger/slow")));
        CircuitBreaker ledger = breakers.getCircuitBreakerRegistry().find("ledger").orElseThrow();
        assertThat(ledger.getState()).isEqualTo(CircuitBreaker.State.CLOSED);
        assertThat(ledger.getMetrics().getNumberOfFailedCalls()).isZero();
        // The two held requests are the only successes: the refusals are neutral, neither failures nor
        // successes, so a burst of them cannot pad the window either.
        assertThat(ledger.getMetrics().getNumberOfSuccessfulCalls()).isEqualTo(2);
    }

    private static String token() {
        return "Bearer " + signingKey.mint(ISSUER, "ezzat", Instant.now().plus(5, ChronoUnit.MINUTES),
                Map.of("tenant", "acme", "scope", List.of("payments:read")));
    }
}
