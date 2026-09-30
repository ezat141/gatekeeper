package com.gatekeeper.apikey;

import com.github.tomakehurst.wiremock.WireMockServer;
import com.github.tomakehurst.wiremock.http.Fault;
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

import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.get;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;

/**
 * When AuthCore cannot answer an introspection call at all, {@link IntrospectionClient}
 * raises {@link IntrospectionUnavailableException} — deliberately not an {@code
 * AuthenticationException}, so {@code AuthenticationWebFilter} never converts it into a 401
 * and it reaches {@code GlobalErrorWebExceptionHandler} instead. This class pins what that
 * handler does with it: 503, carrying {@code Retry-After} and never {@code WWW-Authenticate},
 * for every shape "AuthCore cannot answer" actually takes — erroring, refusing the gateway's
 * own credential, and being unreachable outright.
 *
 * <p>Every test uses a freshly random key from {@link #newKey()}. Redis is shared with
 * AuthCore and persists between test methods, so a fixed key would let one test's cached
 * answer decide another's outcome — see the identical reasoning in {@link
 * ApiKeyAuthenticationTest}. It matters even more here: a cache hit would skip {@link
 * IntrospectionClient} entirely, and the request would never fail the way each test means to
 * provoke, so it would pass (or hang) for the wrong reason.
 *
 * <p>Unlike {@link ApiKeyAuthenticationTest}, nothing here stubs {@code /ledger/entries} or a
 * catch-all "inactive" introspection answer: every request in this class is refused before
 * Spring Cloud Gateway ever routes it downstream, so both would sit unused. The JWKS stub is
 * kept only because {@link #properties} must point {@code gatekeeper.auth.jwk-set-uri}
 * somewhere; it is never actually fetched, since no test here presents a bearer token.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class IntrospectionUnavailableTest {

    static final String ISSUER = "http://localhost:8080";
    static final String INTROSPECT_PATH = "/api/internal/api-keys/introspect";

    static WireMockServer authCore;
    static TestKey activeKey;

    @Autowired
    WebTestClient client;

    @BeforeAll
    static void startFakeAuthCore() {
        activeKey = TestKey.generate("k1");
        authCore = new WireMockServer(options().dynamicPort());
        authCore.start();
        authCore.stubFor(get(urlEqualTo("/oauth2/jwks"))
                .willReturn(okJson(TestKey.jwksDocument(activeKey))));
    }

    @AfterAll
    static void stop() {
        authCore.stop();
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("gatekeeper.auth.jwk-set-uri", () -> authCore.baseUrl() + "/oauth2/jwks");
        registry.add("gatekeeper.auth.issuer", () -> ISSUER);
        registry.add("gatekeeper.downstream.ledger", () -> authCore.baseUrl());
        registry.add("gatekeeper.downstream.authcore", () -> authCore.baseUrl());
        registry.add("gatekeeper.api-key.introspection-uri", () -> authCore.baseUrl() + INTROSPECT_PATH);
    }

    @Test
    void answers503WhenAuthCoreCannotBeAsked() {
        authCore.stubFor(post(urlEqualTo(INTROSPECT_PATH)).willReturn(aResponse().withStatus(500)));

        client.get().uri("/api/machine/payments")
                .header(ApiKeyAuthenticationConverter.HEADER_NAME, newKey())
                .exchange()
                .expectStatus().isEqualTo(503)
                .expectHeader().exists("Retry-After")
                .expectBody()
                .jsonPath("$.error").isEqualTo("service_unavailable")
                .jsonPath("$.status").isEqualTo(503)
                // Only the revocation 503 carries a detail; M3's body is unchanged (M6 design, section 4).
                .jsonPath("$.detail").doesNotExist();
    }

    /**
     * A 401 from introspection means the GATEWAY's own credential was refused — our
     * misconfiguration, not the caller's error. It must never be relayed as their 401.
     */
    @Test
    void answers503WhenTheGatewaysOwnCredentialIsRefused() {
        authCore.stubFor(post(urlEqualTo(INTROSPECT_PATH)).willReturn(aResponse().withStatus(401)));

        client.get().uri("/api/machine/payments")
                .header(ApiKeyAuthenticationConverter.HEADER_NAME, newKey())
                .exchange()
                .expectStatus().isEqualTo(503)
                .expectHeader().exists("Retry-After")
                .expectBody()
                .jsonPath("$.error").isEqualTo("service_unavailable")
                .jsonPath("$.status").isEqualTo(503);
    }

    /**
     * "Unreachable", not merely erroring: a connection-level fault rather than any HTTP
     * status, so {@code retrieve()}'s {@code onStatus} handler — exercised by the two tests
     * above — never runs at all. This instead exercises the {@code onErrorMap} branch in
     * {@code IntrospectionClient.introspect}, the same branch a DNS failure, a refused
     * connection, or a timeout would take.
     *
     * <p>A closed port would exercise the identical branch, but the introspection URI is
     * fixed for the whole life of this class's Spring context (bound once, at context
     * startup, from {@link #properties}) — no single {@code @Test} method can point it
     * elsewhere the way {@code UnreachableJwksErrorShapeTest} does for the JWKS URI in its
     * own, separate context. A WireMock fault achieves the same failure mode — the caller
     * gets no valid HTTP response — while staying on the one shared server and context every
     * other test in this class also uses.
     */
    @Test
    void answers503WhenAuthCoreIsUnreachable() {
        authCore.stubFor(post(urlEqualTo(INTROSPECT_PATH))
                .willReturn(aResponse().withFault(Fault.CONNECTION_RESET_BY_PEER)));

        client.get().uri("/api/machine/payments")
                .header(ApiKeyAuthenticationConverter.HEADER_NAME, newKey())
                .exchange()
                .expectStatus().isEqualTo(503)
                .expectHeader().exists("Retry-After")
                .expectBody()
                .jsonPath("$.error").isEqualTo("service_unavailable")
                .jsonPath("$.status").isEqualTo(503);
    }

    /**
     * {@code GlobalErrorWebExceptionHandler}'s {@code WWW-Authenticate} branch is deliberately
     * conditional on {@code HttpStatus.UNAUTHORIZED}, per that class's own comment: a 503
     * carrying it "would be wrong and confusing" — telling a caller to retry and to
     * re-authenticate at the same time is a contradiction. This is that claim's one live test
     * case.
     */
    @Test
    void a503DoesNotCarryWwwAuthenticate() {
        authCore.stubFor(post(urlEqualTo(INTROSPECT_PATH)).willReturn(aResponse().withStatus(500)));

        client.get().uri("/api/machine/payments")
                .header(ApiKeyAuthenticationConverter.HEADER_NAME, newKey())
                .exchange()
                .expectStatus().isEqualTo(503)
                .expectHeader().doesNotExist(HttpHeaders.WWW_AUTHENTICATE);
    }

    /** A fresh key per call. Never reused across tests, so Redis's cross-test persistence
     * can never make one test's cached answer the reason another test passes — and, more
     * importantly here, can never let a cache hit skip {@link IntrospectionClient} entirely
     * and quietly defeat the test. */
    private static String newKey() {
        return "ak_test_" + UUID.randomUUID();
    }
}
