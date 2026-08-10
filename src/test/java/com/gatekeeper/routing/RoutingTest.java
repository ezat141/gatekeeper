package com.gatekeeper.routing;

import com.github.tomakehurst.wiremock.WireMockServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.webtestclient.autoconfigure.AutoConfigureWebTestClient;
import org.springframework.context.annotation.Bean;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.web.reactive.server.WebTestClient;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;

/**
 * The gateway has no authentication yet — that is Task 9 — so these assertions are purely
 * about whether a request reaches the right downstream at the right path.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class RoutingTest {

    static WireMockServer downstream;

    @Autowired
    WebTestClient client;

    @BeforeAll
    static void startDownstream() {
        downstream = new WireMockServer(options().dynamicPort());
        downstream.start();
        downstream.stubFor(get(urlEqualTo("/ledger/entries"))
                .willReturn(aResponse().withStatus(200).withBody("[]")));
        downstream.stubFor(get(urlEqualTo("/api/accounts/me"))
                .willReturn(aResponse().withStatus(200).withBody("{}")));
        downstream.stubFor(get(urlEqualTo("/api/machine/payments"))
                .willReturn(aResponse().withStatus(200).withBody("[]")));
    }

    @AfterAll
    static void stopDownstream() {
        downstream.stop();
    }

    @DynamicPropertySource
    static void downstreamUris(DynamicPropertyRegistry registry) {
        registry.add("gatekeeper.downstream.ledger", () -> downstream.baseUrl());
        registry.add("gatekeeper.downstream.authcore", () -> downstream.baseUrl());
    }

    /**
     * StripPrefix=1 must remove /api before ledger-service sees the path — that service
     * serves /ledger/**, not /api/ledger/**.
     */
    @Test
    void stripsTheApiPrefixOnTheLedgerRoute() {
        client.get().uri("/api/ledger/entries").exchange().expectStatus().isOk();
        downstream.verify(getRequestedFor(urlEqualTo("/ledger/entries")));
    }

    /** AuthCore serves /api/accounts verbatim, so this route must NOT be stripped. */
    @Test
    void preservesTheFullPathOnTheAuthCoreAccountsRoute() {
        client.get().uri("/api/accounts/me").exchange().expectStatus().isOk();
        downstream.verify(getRequestedFor(urlEqualTo("/api/accounts/me")));
    }

    /** The machine route is equally unstripped. */
    @Test
    void preservesTheFullPathOnTheAuthCoreMachineRoute() {
        client.get().uri("/api/machine/payments").exchange().expectStatus().isOk();
        downstream.verify(getRequestedFor(urlEqualTo("/api/machine/payments")));
    }

    /** A path matching no route predicate must not reach any downstream. */
    @Test
    void doesNotRouteAnUnmatchedPath() {
        client.get().uri("/api/unknown/thing").exchange().expectStatus().isNotFound();
    }

    /**
     * Task 7 put the OAuth2 resource-server starter on the classpath before any code used
     * it, and Boot responds by installing a deny-all chain over every path — so without
     * this, every assertion below would fail on 401 before routing was ever consulted.
     *
     * <p>Scaffolding, deliberately scoped to this class. Task 9 replaces the default chain
     * with a real one and rewrites these expectations to carry a token; this configuration
     * goes away then. Routing is exercised through the genuine security chain in Tasks 9
     * and 11 — nothing here is claiming routes work when authentication is switched on.
     */
    @TestConfiguration
    static class PermitAllSecurity {

        @Bean
        SecurityWebFilterChain permitEverything(ServerHttpSecurity http) {
            return http
                    .csrf(ServerHttpSecurity.CsrfSpec::disable)
                    .authorizeExchange(exchange -> exchange.anyExchange().permitAll())
                    .build();
        }
    }
}
