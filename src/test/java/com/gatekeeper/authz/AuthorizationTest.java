package com.gatekeeper.authz;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.gatekeeper.apikey.ApiKeyAuthenticationConverter;
import com.gatekeeper.support.TestKey;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.any;
import static com.github.tomakehurst.wiremock.client.WireMock.anyRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.anyUrl;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.equalToJson;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.getRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathEqualTo;
import static com.github.tomakehurst.wiremock.client.WireMock.urlPathMatching;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * The M4 allow/deny matrix through the real chain: the rule table, the tenant check, the 403
 * handler, and the ledger route's header filter.
 *
 * <p><strong>Every 403 here also asserts the downstream received nothing.</strong> A 403 that
 * forwarded the request anyway would be worse than no check at all. The catch-all stub answers
 * 200 for every downstream path, so a request that leaked would show up twice: as the wrong
 * status, and in the request log.
 *
 * <p>API keys are fresh per test, for the reason {@code ApiKeyAuthenticationTest} gives:
 * Redis persists between tests, so a fixed key would let one test's cached answer decide
 * another's outcome.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class AuthorizationTest {

    static final String ISSUER = "http://localhost:8080";
    static final String INTROSPECT_PATH = "/api/internal/api-keys/introspect";

    static WireMockServer downstream;
    static TestKey signingKey;

    @Autowired
    WebTestClient client;

    @BeforeAll
    static void start() {
        signingKey = TestKey.generate("k1");
        downstream = new WireMockServer(options().dynamicPort());
        downstream.start();
        downstream.stubFor(get(urlEqualTo("/oauth2/jwks"))
                .willReturn(okJson(TestKey.jwksDocument(signingKey))));
        // Any key this class never marked active reads as inactive.
        downstream.stubFor(post(urlEqualTo(INTROSPECT_PATH))
                .atPriority(10)
                .willReturn(okJson("""
                        {"active":false}""")));
        // Every other downstream path, any method: 200. Lowest priority.
        downstream.stubFor(any(anyUrl())
                .atPriority(20)
                .willReturn(okJson("{}")));
    }

    @AfterAll
    static void stop() {
        downstream.stop();
    }

    @BeforeEach
    void clearRequestLog() {
        downstream.resetRequests();
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("gatekeeper.auth.jwk-set-uri", () -> downstream.baseUrl() + "/oauth2/jwks");
        registry.add("gatekeeper.auth.issuer", () -> ISSUER);
        registry.add("gatekeeper.downstream.ledger", () -> downstream.baseUrl());
        registry.add("gatekeeper.downstream.authcore", () -> downstream.baseUrl());
        registry.add("gatekeeper.api-key.introspection-uri", () -> downstream.baseUrl() + INTROSPECT_PATH);
    }

    // --- The plan's acceptance criteria -------------------------------------------------

    @Test
    void refusesALedgerWriteWithoutTheWriteScope() {
        expectForbidden(client.post().uri("/api/ledger/entries")
                        .header(HttpHeaders.AUTHORIZATION, bearer("acme", "payments:read"))
                        .exchange(),
                "/api/ledger/entries", Reason.MISSING_SCOPE);

        assertThat(downstream.findAll(anyRequestedFor(urlPathEqualTo("/ledger/entries")))).isEmpty();
    }

    @Test
    void proxiesALedgerWriteWithTheWriteScope() {
        client.post().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, bearer("acme", "payments:write"))
                .exchange()
                .expectStatus().isOk();

        assertThat(downstream.findAll(postRequestedFor(urlEqualTo("/ledger/entries")))).hasSize(1);
    }

    @Test
    void refusesARequestNamingAnotherTenantInTheHeader() {
        expectForbidden(client.get().uri("/api/accounts/me")
                        .header(HttpHeaders.AUTHORIZATION, bearer("acme"))
                        .header("X-Tenant", "default")
                        .exchange(),
                "/api/accounts/me", Reason.TENANT_MISMATCH);

        assertThat(downstream.findAll(anyRequestedFor(urlPathEqualTo("/api/accounts/me")))).isEmpty();
    }

    @Test
    void refusesARequestNamingAnotherTenantInTheQuery() {
        expectForbidden(client.get().uri("/api/accounts/me?tenant=default")
                        .header(HttpHeaders.AUTHORIZATION, bearer("acme"))
                        .exchange(),
                "/api/accounts/me", Reason.TENANT_MISMATCH);

        assertThat(downstream.findAll(anyRequestedFor(urlPathEqualTo("/api/accounts/me")))).isEmpty();
    }

    @Test
    void proxiesARequestNamingTheTokensOwnTenant() {
        client.get().uri("/api/accounts/me")
                .header(HttpHeaders.AUTHORIZATION, bearer("acme"))
                .header("X-Tenant", "acme")
                .exchange()
                .expectStatus().isOk();

        assertThat(downstream.findAll(getRequestedFor(urlEqualTo("/api/accounts/me")))).hasSize(1);
    }

    /** A client-credentials token has no tenant claim, so naming one is not checked. */
    @Test
    void proxiesATenantlessTokenWhateverTenantItNames() {
        client.get().uri("/api/machine/payments")
                .header(HttpHeaders.AUTHORIZATION, bearer(null, "payments:read"))
                .header("X-Tenant", "default")
                .exchange()
                .expectStatus().isOk();
    }

    // --- API keys --------------------------------------------------------------------------

    /** The 403 shape for a key caller — the same single wiring as for a bearer caller. */
    @Test
    void refusesAnApiKeyOnTheLedgerRoute() {
        String rawKey = stubActiveKey("payments:read");

        expectForbidden(client.get().uri("/api/ledger/entries")
                        .header(ApiKeyAuthenticationConverter.HEADER_NAME, rawKey)
                        .exchange(),
                "/api/ledger/entries", Reason.API_KEY_NOT_ACCEPTED);

        assertThat(downstream.findAll(anyRequestedFor(urlPathEqualTo("/ledger/entries")))).isEmpty();
    }

    @Test
    void refusesAnApiKeyWithoutTheWriteScopeOnAMachineWrite() {
        String rawKey = stubActiveKey("payments:read");

        expectForbidden(client.post().uri("/api/machine/payments")
                        .header(ApiKeyAuthenticationConverter.HEADER_NAME, rawKey)
                        .exchange(),
                "/api/machine/payments", Reason.MISSING_SCOPE);

        assertThat(downstream.findAll(anyRequestedFor(urlPathEqualTo("/api/machine/payments")))).isEmpty();
    }

    /**
     * The machine route is where a key works end to end — and AuthCore re-authenticates the
     * key itself, so the header must still reach it. Guards against the ledger route's
     * header filter being applied more widely than the one route.
     */
    @Test
    void proxiesAnApiKeyOnTheMachineRouteWithTheKeyStillAttached() {
        String rawKey = stubActiveKey("payments:read");

        client.get().uri("/api/machine/payments")
                .header(ApiKeyAuthenticationConverter.HEADER_NAME, rawKey)
                .exchange()
                .expectStatus().isOk();

        downstream.verify(getRequestedFor(urlEqualTo("/api/machine/payments"))
                .withHeader(ApiKeyAuthenticationConverter.HEADER_NAME, equalTo(rawKey)));
    }

    /**
     * A blank X-API-Key rides the JWT path (M3's precedence rules), so it would otherwise be
     * forwarded to a service that can do nothing with it. The M3 item deferred to M4.
     */
    @Test
    void doesNotForwardAnApiKeyHeaderToTheLedger() {
        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, bearer("acme", "payments:read"))
                .header(ApiKeyAuthenticationConverter.HEADER_NAME, "")
                .exchange()
                .expectStatus().isOk();

        downstream.verify(getRequestedFor(urlEqualTo("/ledger/entries"))
                .withoutHeader(ApiKeyAuthenticationConverter.HEADER_NAME));
    }

    // --- Deny by default -------------------------------------------------------------------

    @Test
    void refusesAnAuthenticatedCallerOnAPathNoRuleCovers() {
        expectForbidden(client.get().uri("/api/unknown/thing")
                        .header(HttpHeaders.AUTHORIZATION, bearer("acme", "payments:read", "payments:write"))
                        .exchange(),
                "/api/unknown/thing", Reason.NO_RULE);
    }

    @Test
    void refusesAMethodTheLedgerDoesNotServe() {
        expectForbidden(client.delete().uri("/api/ledger/entries")
                        .header(HttpHeaders.AUTHORIZATION, bearer("acme", "payments:read", "payments:write"))
                        .exchange(),
                "/api/ledger/entries", Reason.NO_RULE);

        assertThat(downstream.findAll(anyRequestedFor(urlPathEqualTo("/ledger/entries")))).isEmpty();
    }

    /**
     * The rule table and the gateway's routes must see the same path. Spring Security's
     * default StrictServerWebExchangeFirewall guarantees it by refusing a non-normalized path
     * before either matches. Without it, this request would be authorized as the accounts
     * route — authenticated only — and forwarded as the machine route, which requires a scope
     * this caller lacks.
     */
    @Test
    void refusesATraversalPathBeforeAnyRuleSeesIt() {
        client.get().uri("/api/accounts/../machine/payments")
                .header(HttpHeaders.AUTHORIZATION, bearer("acme"))
                .exchange()
                .expectStatus().isBadRequest();

        assertThat(downstream.findAll(anyRequestedFor(urlPathMatching("/api/.*")))).isEmpty();
    }

    /** No credential is still 401, not 403 — whichever rule the path matches. */
    @Test
    void stillAnswersAnAnonymousCallerWith401() {
        client.get().uri("/api/unknown/thing")
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().valueMatches(HttpHeaders.WWW_AUTHENTICATE, "Bearer.*")
                .expectBody()
                .jsonPath("$.error").isEqualTo("unauthorized")
                .jsonPath("$.detail").doesNotExist();
    }

    // --- Helpers ---------------------------------------------------------------------------

    private static void expectForbidden(WebTestClient.ResponseSpec response, String path, Reason reason) {
        response.expectStatus().isForbidden()
                .expectHeader().doesNotExist(HttpHeaders.WWW_AUTHENTICATE)
                .expectBody()
                .jsonPath("$.error").isEqualTo("forbidden")
                .jsonPath("$.status").isEqualTo(403)
                .jsonPath("$.path").isEqualTo(path)
                .jsonPath("$.detail").isEqualTo(reason.detail());
    }

    /** A bearer token in {@code tenant}, or with no tenant claim when {@code tenant} is null. */
    private static String bearer(String tenant, String... scopes) {
        Map<String, Object> claims = new HashMap<>();
        claims.put("scope", List.of(scopes));
        if (tenant != null) {
            claims.put("tenant", tenant);
        }
        return "Bearer " + signingKey.mint(ISSUER, "ezzat", Instant.now().plus(5, ChronoUnit.MINUTES), claims);
    }

    /** Registers a fresh key as active with the given scopes, and returns it. */
    private static String stubActiveKey(String... scopes) {
        String rawKey = "ak_test_" + UUID.randomUUID();
        String scopeList = String.join("\",\"", scopes);
        downstream.stubFor(post(urlEqualTo(INTROSPECT_PATH))
                .atPriority(1)
                .withRequestBody(equalToJson("{\"key\":\"" + rawKey + "\"}"))
                .willReturn(okJson("""
                        {"active":true,"name":"reporting","scopes":["%s"],"expiresAt":"%s"}"""
                        .formatted(scopeList, Instant.now().plus(1, ChronoUnit.HOURS)))));
        return rawKey;
    }
}
