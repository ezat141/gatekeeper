package com.gatekeeper.identity;

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
import java.util.List;
import java.util.Map;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class IdentityPropagationTest {

    static final String ISSUER = "http://localhost:8080";

    static WireMockServer downstream;
    static TestKey activeKey;

    @Autowired
    WebTestClient client;

    @BeforeAll
    static void start() {
        activeKey = TestKey.generate("k1");
        downstream = new WireMockServer(options().dynamicPort());
        downstream.start();
        downstream.stubFor(get(urlEqualTo("/oauth2/jwks"))
                .willReturn(okJson(TestKey.jwksDocument(activeKey))));
        downstream.stubFor(get(urlEqualTo("/ledger/entries"))
                .willReturn(aResponse().withStatus(200).withBody("[]")));
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
    }

    private static String tokenFor(String subject, String tenant, List<String> permissions) {
        return activeKey.mint(ISSUER, subject, Instant.now().plus(5, ChronoUnit.MINUTES),
                Map.of("tenant", tenant, "permissions", permissions));
    }

    /** The ordinary case: verified claims arrive downstream as headers. */
    @Test
    void stampsVerifiedIdentityOntoTheOutboundRequest() {
        downstream.resetRequests();

        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION,
                        "Bearer " + tokenFor("ezzat", "acme", List.of("payments:read")))
                .exchange()
                .expectStatus().isOk();

        downstream.verify(getRequestedFor(urlEqualTo("/ledger/entries"))
                .withHeader("X-GK-Subject", equalTo("ezzat"))
                .withHeader("X-GK-Tenant", equalTo("acme"))
                .withHeader("X-GK-Permissions", equalTo("payments:read")));
    }

    /**
     * The attack this exists to stop. The caller asserts a tenant and permissions it has
     * no claim to; the gateway must overwrite both with the verified values. If a forged
     * header survived, any downstream trusting it would grant cross-tenant access.
     */
    @Test
    void overwritesClientSuppliedIdentityHeaders() {
        downstream.resetRequests();

        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION,
                        "Bearer " + tokenFor("ezzat", "acme", List.of("payments:read")))
                .header("X-GK-Subject", "admin")
                .header("X-GK-Tenant", "default")
                .header("X-GK-Permissions", "payments:write,admin:all")
                .exchange()
                .expectStatus().isOk();

        downstream.verify(getRequestedFor(urlEqualTo("/ledger/entries"))
                .withHeader("X-GK-Subject", equalTo("ezzat"))
                .withHeader("X-GK-Tenant", equalTo("acme"))
                .withHeader("X-GK-Permissions", equalTo("payments:read")));
    }

    /**
     * Prefix matching is case-insensitive, and the strip must not depend on the exact
     * casing a client happens to send. HTTP header names are case-insensitive, so a
     * filter matching only the canonical form would be trivially bypassed.
     */
    @Test
    void stripsSpoofedHeadersRegardlessOfCasing() {
        downstream.resetRequests();

        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION,
                        "Bearer " + tokenFor("ezzat", "acme", List.of("payments:read")))
                .header("x-gk-tenant", "default")
                .header("X-Gk-Subject", "admin")
                .exchange()
                .expectStatus().isOk();

        downstream.verify(getRequestedFor(urlEqualTo("/ledger/entries"))
                .withHeader("X-GK-Tenant", equalTo("acme"))
                .withHeader("X-GK-Subject", equalTo("ezzat")));
    }

    /**
     * A claim AuthCore omits — every client-credentials token lacks tenant and
     * permissions — must produce no header at all rather than an empty or literal-null
     * one, which a downstream could misread as a real value.
     */
    @Test
    void omitsHeadersForClaimsTheTokenDoesNotCarry() {
        downstream.resetRequests();

        String machineToken = activeKey.mint(ISSUER, "authcore-machine",
                Instant.now().plus(5, ChronoUnit.MINUTES), Map.of());

        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + machineToken)
                .exchange()
                .expectStatus().isOk();

        downstream.verify(getRequestedFor(urlEqualTo("/ledger/entries"))
                .withHeader("X-GK-Subject", equalTo("authcore-machine"))
                .withoutHeader("X-GK-Tenant")
                .withoutHeader("X-GK-Permissions"));
    }

    /**
     * The case the other tests cannot catch, and the only one where spoofing would work.
     *
     * <p>A client-credentials token carries no {@code tenant} claim, so {@link
     * IdentityStampFilter} skips that header entirely rather than overwriting it — its
     * {@code if (tenant != null)} guard sees to that. Every other test here passes even
     * with the strip filter deleted, because stamping happens to overwrite the forged
     * value anyway. Here nothing overwrites it, so if the strip did not run the client's
     * {@code X-GK-Tenant} would reach the downstream intact.
     */
    @Test
    void stripsASpoofedHeaderTheStampFilterWouldNotOverwrite() {
        downstream.resetRequests();

        String machineToken = activeKey.mint(ISSUER, "authcore-machine",
                Instant.now().plus(5, ChronoUnit.MINUTES), Map.of());

        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + machineToken)
                .header("X-GK-Tenant", "default")
                .header("X-GK-Permissions", "admin:all")
                .exchange()
                .expectStatus().isOk();

        downstream.verify(getRequestedFor(urlEqualTo("/ledger/entries"))
                .withHeader("X-GK-Subject", equalTo("authcore-machine"))
                .withoutHeader("X-GK-Tenant")
                .withoutHeader("X-GK-Permissions"));
    }
}
