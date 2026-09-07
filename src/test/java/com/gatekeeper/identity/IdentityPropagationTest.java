package com.gatekeeper.identity;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.gatekeeper.apikey.ApiKeyAuthenticationConverter;
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
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class IdentityPropagationTest {

    static final String ISSUER = "http://localhost:8080";
    static final String INTROSPECT_PATH = "/api/internal/api-keys/introspect";

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
        // Catch-all, lower priority than the per-test stubActiveKey() stubs below: any key
        // this class never explicitly marked active reads as inactive, matching how AuthCore
        // answers for unknown, disabled and expired keys alike.
        downstream.stubFor(post(urlEqualTo(INTROSPECT_PATH))
                .atPriority(10)
                .willReturn(okJson("""
                        {"active":false}""")));
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
        registry.add("gatekeeper.api-key.introspection-uri", () -> downstream.baseUrl() + INTROSPECT_PATH);
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

    /** An API-key caller is not a JWT principal, but must still be attributable downstream. */
    @Test
    void stampsTheSubjectForAnApiKeyCaller() {
        downstream.resetRequests();
        String rawKey = stubActiveKey("reporting");

        client.get().uri("/api/ledger/entries")
                .header(ApiKeyAuthenticationConverter.HEADER_NAME, rawKey)
                .exchange()
                .expectStatus().isOk();

        downstream.verify(getRequestedFor(urlEqualTo("/ledger/entries"))
                .withHeader("X-GK-Subject", equalTo("apikey:reporting")));
    }

    /** No tenant exists for a key, so no header — not a blank one a downstream might misread. */
    @Test
    void stampsNoTenantForAnApiKeyCaller() {
        downstream.resetRequests();
        String rawKey = stubActiveKey("reporting");

        client.get().uri("/api/ledger/entries")
                .header(ApiKeyAuthenticationConverter.HEADER_NAME, rawKey)
                .exchange()
                .expectStatus().isOk();

        downstream.verify(getRequestedFor(urlEqualTo("/ledger/entries"))
                .withoutHeader("X-GK-Tenant"));
    }

    // --- Helpers --------------------------------------------------------------------------

    /** A fresh key per call. Never reused across tests, so Redis's cross-test persistence
     * can never make one test's cached answer the reason another test passes. */
    private static String newKey() {
        return "ak_test_" + UUID.randomUUID();
    }

    /** Registers a higher-priority stub answering active for one freshly generated key, and
     * returns that key.
     *
     * <p>Carries a non-null {@code expiresAt}, matching the shape AuthCore actually sends for
     * an ordinary key — only the gateway's own introspection key gets {@code expiresAt: null}.
     * See {@code ApiKeyAuthenticationTest.stubActiveKey}, which this mirrors.
     */
    private static String stubActiveKey(String name) {
        String rawKey = newKey();
        downstream.stubFor(post(urlEqualTo(INTROSPECT_PATH))
                .atPriority(1)
                .withRequestBody(equalToJson("{\"key\":\"" + rawKey + "\"}"))
                .willReturn(okJson("""
                        {"active":true,"name":"%s","scopes":["payments:read"],"expiresAt":"%s"}"""
                        .formatted(name, Instant.now().plus(1, ChronoUnit.HOURS)))));
        return rawKey;
    }
}
