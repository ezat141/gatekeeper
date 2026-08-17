package com.gatekeeper.error;

import com.gatekeeper.support.TestKey;
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
import java.util.Map;

/**
 * Kept separate from {@link ErrorShapeTest} because that class points {@code
 * gatekeeper.auth.jwk-set-uri} at a live WireMock JWKS via its own {@code
 * @DynamicPropertySource}, and a single test class cannot register two different values for
 * the same property. This class needs the opposite: a URI nothing answers.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class UnreachableJwksErrorShapeTest {

    static final String ISSUER = "http://localhost:8080";

    static TestKey key;

    @Autowired
    WebTestClient client;

    @BeforeAll
    static void generateKey() {
        key = TestKey.generate("k1");
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        // Port 9 is the standard "discard" service: nothing listens on a normal machine, and
        // a loopback connection to a closed port is refused immediately rather than timing
        // out, so this stays fast and deterministic.
        registry.add("gatekeeper.auth.jwk-set-uri", () -> "http://localhost:9/oauth2/jwks");
        registry.add("gatekeeper.auth.issuer", () -> ISSUER);
        registry.add("gatekeeper.downstream.ledger", () -> "http://localhost:9");
        registry.add("gatekeeper.downstream.authcore", () -> "http://localhost:9");
    }

    /**
     * The token is well-formed and would verify if the key set were reachable, but it never
     * gets that far. {@code ReactiveRemoteJWKSource.getJWKSet()} fails to connect, {@code
     * NimbusReactiveJwtDecoder} wraps that as {@code IllegalStateException("Could not obtain
     * the keys", ...)}, and {@code JwtReactiveAuthenticationManager.authenticate()} maps
     * only {@code JwtException} to a 401 — so this exception passes through unmapped unless
     * something downstream catches it. It must still read as a refused credential rather
     * than a server fault: the gateway cannot verify who the caller is either way, and a 500
     * would additionally advertise that the identity provider is unreachable.
     */
    @Test
    void rendersAnUnreachableJwksAsUnauthorizedNotServerError() {
        String token = key.mint(ISSUER, "ezzat",
                Instant.now().plus(5, ChronoUnit.MINUTES), Map.of("tenant", "acme"));

        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isUnauthorized()
                .expectHeader().valueMatches(HttpHeaders.WWW_AUTHENTICATE, "Bearer.*")
                .expectBody()
                .jsonPath("$.error").isEqualTo("unauthorized")
                .jsonPath("$.status").isEqualTo(401)
                .jsonPath("$.path").isEqualTo("/api/ledger/entries");
    }
}
