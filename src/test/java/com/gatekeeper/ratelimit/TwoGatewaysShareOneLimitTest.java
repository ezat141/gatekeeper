package com.gatekeeper.ratelimit;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.gatekeeper.GateKeeperApplication;
import com.gatekeeper.support.TestKey;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.http.HttpHeaders;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * The proof that the limit is distributed: two gateway instances, as separate application
 * contexts on their own ports, sharing one Redis and one downstream. Requests alternate between
 * them and the combined count trips the limit on whichever instance receives the next one. The
 * M5 design, section 11.
 *
 * <p>The quota test needs no timing and is the unconditional proof. The burst test relies on
 * four requests landing within the second one token takes to refill.
 */
class TwoGatewaysShareOneLimitTest {

    static final String ISSUER = "http://localhost:8080";
    static final String QUOTA_TENANT = "q-" + UUID.randomUUID();

    static WireMockServer downstream;
    static TestKey signingKey;
    static ConfigurableApplicationContext first;
    static ConfigurableApplicationContext second;
    static WebTestClient toFirst;
    static WebTestClient toSecond;

    @BeforeAll
    static void start() {
        signingKey = TestKey.generate("k1");
        downstream = new WireMockServer(options().dynamicPort());
        downstream.start();
        downstream.stubFor(get(urlEqualTo("/oauth2/jwks")).willReturn(okJson(TestKey.jwksDocument(signingKey))));
        downstream.stubFor(any(anyUrl()).atPriority(20).willReturn(okJson("{}")));

        first = gateway();
        second = gateway();
        toFirst = clientFor(first);
        toSecond = clientFor(second);
    }

    @AfterAll
    static void stop() {
        if (first != null) {
            first.close();
        }
        if (second != null) {
            second.close();
        }
        downstream.stop();
    }

    @Test
    void theTwoInstancesAreDistinct() {
        assertThat(port(first)).isNotEqualTo(port(second));
    }

    @Test
    void shareOneDailyQuota() {
        String token = userToken(QUOTA_TENANT);
        toFirst.get().uri("/api/ledger/entries").header(HttpHeaders.AUTHORIZATION, token).exchange().expectStatus().isOk();
        toSecond.get().uri("/api/ledger/entries").header(HttpHeaders.AUTHORIZATION, token).exchange().expectStatus().isOk();
        toFirst.get().uri("/api/ledger/entries").header(HttpHeaders.AUTHORIZATION, token).exchange().expectStatus().isOk();

        toSecond.get().uri("/api/ledger/entries").header(HttpHeaders.AUTHORIZATION, token).exchange()
                .expectStatus().isEqualTo(429)
                .expectBody().jsonPath("$.detail").isEqualTo(RateLimitReason.QUOTA_EXCEEDED.detail());
    }

    @Test
    void shareOneBurst() {
        String token = userToken("t-" + UUID.randomUUID());
        toFirst.get().uri("/api/ledger/entries").header(HttpHeaders.AUTHORIZATION, token).exchange().expectStatus().isOk();
        toSecond.get().uri("/api/ledger/entries").header(HttpHeaders.AUTHORIZATION, token).exchange().expectStatus().isOk();
        toFirst.get().uri("/api/ledger/entries").header(HttpHeaders.AUTHORIZATION, token).exchange().expectStatus().isOk();

        toSecond.get().uri("/api/ledger/entries").header(HttpHeaders.AUTHORIZATION, token).exchange()
                .expectStatus().isEqualTo(429)
                .expectBody().jsonPath("$.detail").isEqualTo(RateLimitReason.RATE_LIMITED.detail());
    }

    /**
     * Command-line arguments, not {@code SpringApplicationBuilder.properties(...)}: those set
     * default properties, the lowest-priority source, so {@code application.yml} would win —
     * {@code server.port: 8081} would put both instances on one port, and {@code default-plan:
     * free} would give every fresh tenant the test override's unlimited plan. Arguments outrank
     * every configuration file.
     */
    private static ConfigurableApplicationContext gateway() {
        return new SpringApplicationBuilder(GateKeeperApplication.class).run(
                "--server.port=0",
                "--gatekeeper.auth.jwk-set-uri=" + downstream.baseUrl() + "/oauth2/jwks",
                "--gatekeeper.auth.issuer=" + ISSUER,
                "--gatekeeper.downstream.ledger=" + downstream.baseUrl(),
                "--gatekeeper.downstream.authcore=" + downstream.baseUrl(),
                "--gatekeeper.rate-limit.default-plan=burst3",
                "--gatekeeper.rate-limit.plans.burst3.requests-per-second=1",
                "--gatekeeper.rate-limit.plans.burst3.burst=3",
                "--gatekeeper.rate-limit.plans.burst3.daily-quota=1000",
                "--gatekeeper.rate-limit.plans.quota3.requests-per-second=1000",
                "--gatekeeper.rate-limit.plans.quota3.burst=1000",
                "--gatekeeper.rate-limit.plans.quota3.daily-quota=3",
                "--gatekeeper.rate-limit.assignments.tenants." + QUOTA_TENANT + "=quota3");
    }

    private static int port(ConfigurableApplicationContext context) {
        return context.getEnvironment().getRequiredProperty("local.server.port", Integer.class);
    }

    private static WebTestClient clientFor(ConfigurableApplicationContext context) {
        return WebTestClient.bindToServer().baseUrl("http://localhost:" + port(context)).build();
    }

    private static String userToken(String tenant) {
        return "Bearer " + signingKey.mint(ISSUER, "ezzat", Instant.now().plus(5, ChronoUnit.MINUTES),
                Map.of("tenant", tenant, "scope", List.of("payments:read")));
    }
}
