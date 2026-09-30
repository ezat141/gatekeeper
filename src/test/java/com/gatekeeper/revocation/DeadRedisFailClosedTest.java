package com.gatekeeper.revocation;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.gatekeeper.redis.RedisCircuitBreaker;
import com.gatekeeper.redis.RedisCircuitBreaker.Permit;
import com.gatekeeper.support.TestKey;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.http.HttpHeaders;
import org.springframework.test.annotation.DirtiesContext;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.io.IOException;
import java.net.ServerSocket;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.anyRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * Nothing listens on the Redis port. A bearer token cannot be checked, so it is refused — 503,
 * promptly — and never forwarded, including once the breaker is open. The M6 design, sections 4, 7
 * and 8.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class DeadRedisFailClosedTest {

    static final String ISSUER = "http://localhost:8080";
    static WireMockServer downstream;
    static TestKey signingKey;
    static int deadPort;

    @Autowired
    WebTestClient client;

    @Autowired
    @Qualifier("revocationBreaker")
    RedisCircuitBreaker breaker;

    @BeforeAll
    static void start() throws IOException {
        signingKey = TestKey.generate("k1");
        downstream = new WireMockServer(options().dynamicPort());
        downstream.start();
        downstream.stubFor(get(urlEqualTo("/oauth2/jwks")).willReturn(okJson(TestKey.jwksDocument(signingKey))));
        downstream.stubFor(any(anyUrl()).atPriority(20).willReturn(okJson("{}")));
        try (ServerSocket probe = new ServerSocket(0)) {
            deadPort = probe.getLocalPort();
        }
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
        registry.add("spring.data.redis.port", () -> deadPort);
    }

    /**
     * Starts from a fresh context, so a fresh, closed breaker: after the test below, which opens it,
     * every request here would be refused by the open breaker without touching Redis, and the dead-Redis
     * path itself would never be timed. JUnit does not promise an order between methods.
     */
    @Test
    @DirtiesContext(methodMode = DirtiesContext.MethodMode.BEFORE_METHOD)
    void refusesEveryBearerTokenWith503Promptly() {
        String token = userToken();

        for (int i = 0; i < 5; i++) {
            long started = System.nanoTime();

            client.get().uri("/api/ledger/entries")
                    .header(HttpHeaders.AUTHORIZATION, token)
                    .exchange()
                    .expectStatus().isEqualTo(503)
                    .expectHeader().valueEquals(HttpHeaders.RETRY_AFTER, "5")
                    .expectHeader().doesNotExist(HttpHeaders.WWW_AUTHENTICATE)
                    .expectBody()
                    .jsonPath("$.error").isEqualTo("service_unavailable")
                    .jsonPath("$.status").isEqualTo(503)
                    .jsonPath("$.path").isEqualTo("/api/ledger/entries")
                    .jsonPath("$.detail").isEqualTo(RevocationUnavailableException.DETAIL);

            // The first request also pays for the cold path (the JWKS fetch) on a cold JVM.
            Duration bound = i == 0 ? Duration.ofSeconds(5) : Duration.ofSeconds(1);
            assertThat(Duration.ofNanos(System.nanoTime() - started)).as("request %d", i).isLessThan(bound);
        }

        downstream.verify(0, anyRequestedFor(urlPathMatching("/ledger/.*")));
    }

    /** The handoff's warning: an open breaker must refuse, not skip the check and forward. */
    @Test
    void stillRefusesOnceTheBreakerIsOpen() {
        String token = userToken();
        for (int i = 0; i < RedisCircuitBreaker.FAILURES_TO_OPEN; i++) {
            client.get().uri("/api/ledger/entries").header(HttpHeaders.AUTHORIZATION, token).exchange()
                    .expectStatus().isEqualTo(503);
        }
        assertThat(breaker.allowCall()).isEqualTo(Permit.DENIED);

        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, token)
                .exchange()
                .expectStatus().isEqualTo(503)
                .expectBody().jsonPath("$.detail").isEqualTo(RevocationUnavailableException.DETAIL);

        downstream.verify(0, anyRequestedFor(urlPathMatching("/ledger/.*")));
    }

    private static String userToken() {
        return "Bearer " + signingKey.mint(ISSUER, "ezzat", Instant.now().plus(5, ChronoUnit.MINUTES),
                Map.of("tenant", "acme", "scope", List.of("payments:read")));
    }
}
