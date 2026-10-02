package com.gatekeeper.ratelimit;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.gatekeeper.GateKeeperApplication;
import com.gatekeeper.support.TestKey;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.boot.builder.SpringApplicationBuilder;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.support.GenericApplicationContext;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.http.HttpHeaders;
import org.springframework.http.client.ReactorResourceFactory;
import org.springframework.test.web.reactive.server.WebTestClient;

import java.time.Duration;
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
 * The proof that the limit — and, since M6, a revocation — is distributed: two gateway
 * instances, as separate application contexts on their own ports, sharing one Redis and one
 * downstream. Requests alternate between them and the combined count trips the limit on whichever
 * instance receives the next one. The M5 design, section 11.
 *
 * <p>The quota test needs no timing and is the unconditional proof. The burst test relies on
 * four requests landing within the second one token takes to refill; both instances are warmed
 * with one request each in {@link #start()} first, so neither test pays a cold-start cost that
 * a real deployment would already have absorbed.
 *
 * <p>Each instance is also given its own {@link ReactorResourceFactory} (see {@link #gateway()}):
 * Boot's default one sets {@code useGlobalResources(true)}, so it shares Reactor Netty's event
 * loops and connection pools with every other Spring context in the JVM. Left at the default,
 * {@link #stop()} closing one gateway would dispose those pools out from under every other test
 * class running in the same suite — not just this one's — surfacing as {@code
 * PrematureCloseException} in unrelated tests' teardown.
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
        warmUp(toFirst);
        warmUp(toSecond);
    }

    @AfterAll
    static void stop() {
        if (first != null) {
            first.close();
        }
        if (second != null) {
            second.close();
        }
        if (downstream != null) {
            downstream.stop();
        }
    }

    @Test
    void theTwoInstancesAreDistinct() {
        int firstPort = port(first);
        int secondPort = port(second);
        assertThat(firstPort).isNotEqualTo(secondPort);
        assertThat(firstPort).isNotEqualTo(8081);
        assertThat(secondPort).isNotEqualTo(8081);

        assertThat(first.getBeansOfType(ReactorResourceFactory.class)).hasSize(1);
        assertThat(second.getBeansOfType(ReactorResourceFactory.class)).hasSize(1);
        assertThat(first.getBean(ReactorResourceFactory.class).isUseGlobalResources()).isFalse();
        assertThat(second.getBean(ReactorResourceFactory.class).isUseGlobalResources()).isFalse();
    }

    @Test
    void shareOneDailyQuota() {
        String token = userToken(QUOTA_TENANT);
        ledger(toFirst, token).expectStatus().isOk().expectHeader().valueEquals("X-Quota-Remaining", "2");
        ledger(toSecond, token).expectStatus().isOk().expectHeader().valueEquals("X-Quota-Remaining", "1");
        ledger(toFirst, token).expectStatus().isOk().expectHeader().valueEquals("X-Quota-Remaining", "0");

        ledger(toSecond, token)
                .expectStatus().isEqualTo(429)
                .expectBody().jsonPath("$.detail").isEqualTo(RateLimitReason.QUOTA_EXCEEDED.detail());
    }

    @Test
    void shareOneBurst() {
        String token = userToken("t-" + UUID.randomUUID());
        ledger(toFirst, token).expectStatus().isOk().expectHeader().valueEquals("X-RateLimit-Remaining", "2");
        ledger(toSecond, token).expectStatus().isOk().expectHeader().valueEquals("X-RateLimit-Remaining", "1");
        ledger(toFirst, token).expectStatus().isOk().expectHeader().valueEquals("X-RateLimit-Remaining", "0");

        ledger(toSecond, token)
                .expectStatus().isEqualTo(429)
                .expectBody().jsonPath("$.detail").isEqualTo(RateLimitReason.RATE_LIMITED.detail());
    }

    /**
     * A revocation reaches every instance on its next call: no instance remembers "not revoked"
     * (the M6 design, section 5). Both are asked once before the revocation, so an in-process cache
     * of that answer — the one the design rejected — would serve the next call a 200 and fail this.
     */
    @Test
    void bothRefuseARevokedTokenOnTheNextCall() {
        String token = userToken("r-" + UUID.randomUUID());
        ledger(toFirst, token).expectStatus().isOk();
        ledger(toSecond, token).expectStatus().isOk();

        ReactiveStringRedisTemplate redis = first.getBean(ReactiveStringRedisTemplate.class);
        String key = "authcore:revoked:jti:" + TestKey.jwtIdOf(token.substring("Bearer ".length()));
        redis.opsForValue().set(key, "revoked", Duration.ofMinutes(5)).block();
        try {
            ledger(toFirst, token).expectStatus().isUnauthorized();
            ledger(toSecond, token).expectStatus().isUnauthorized();
        } finally {
            redis.delete(key).block();
        }
    }

    /**
     * One request per instance before the timed tests run, so a cold circuit breaker probe or a
     * cold connection pool never counts against {@link #shareOneBurst()}'s one-second budget. A
     * fresh, unrelated tenant so it spends none of the timed tests' own allowance; the response
     * must already carry the limiter's headers, so a breaker trip here fails fast with a clear
     * cause instead of surfacing later as a mysterious timing failure.
     */
    private static void warmUp(WebTestClient client) {
        ledger(client, userToken("warm-" + UUID.randomUUID()))
                .expectStatus().isOk()
                .expectHeader().exists("X-RateLimit-Remaining");
    }

    private static WebTestClient.ResponseSpec ledger(WebTestClient client, String token) {
        return client.get().uri("/api/ledger/entries").header(HttpHeaders.AUTHORIZATION, token).exchange();
    }

    /**
     * Command-line arguments, not {@code SpringApplicationBuilder.properties(...)}: those set
     * default properties, the lowest-priority source, so {@code application.yml} would win —
     * {@code server.port: 8081} would put both instances on one port, and {@code default-plan:
     * free} would give every fresh tenant the test override's unlimited plan. Arguments outrank
     * every configuration file.
     *
     * <p>The initializer registers a private {@link ReactorResourceFactory} before Boot's own
     * {@code @ConditionalOnMissingBean} one would apply, so each context keeps its Reactor Netty
     * resources to itself — see the class Javadoc.
     */
    private static ConfigurableApplicationContext gateway() {
        return new SpringApplicationBuilder(GateKeeperApplication.class)
                .initializers(context -> ((GenericApplicationContext) context).registerBean(
                        ReactorResourceFactory.class, TwoGatewaysShareOneLimitTest::privateReactorResources))
                .run(
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

    private static ReactorResourceFactory privateReactorResources() {
        ReactorResourceFactory factory = new ReactorResourceFactory();
        factory.setUseGlobalResources(false);
        return factory;
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
