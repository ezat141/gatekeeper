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
     * The token is well-formed and would verify if the key set were reachable, but it never gets
     * that far: the fetch is refused, and {@code NimbusReactiveJwtDecoder} wraps that as {@code
     * IllegalStateException("Could not obtain the keys", ...)}. Since M7 that is a 503 with {@code
     * KEYS_UNAVAILABLE}, not a 401: the token is very likely valid, and a 401 would send the caller
     * to refresh it against the AuthCore that is unreachable (the M7 design, section 4).
     */
    @Test
    void rendersAnUnreachableJwksAsServiceUnavailable() {
        String token = key.mint(ISSUER, "ezzat",
                Instant.now().plus(5, ChronoUnit.MINUTES), Map.of("tenant", "acme"));

        client.get().uri("/api/ledger/entries")
                .header(HttpHeaders.AUTHORIZATION, "Bearer " + token)
                .exchange()
                .expectStatus().isEqualTo(503)
                .expectHeader().valueEquals(HttpHeaders.RETRY_AFTER, "5")
                .expectHeader().doesNotExist(HttpHeaders.WWW_AUTHENTICATE)
                .expectBody()
                .jsonPath("$.error").isEqualTo("service_unavailable")
                .jsonPath("$.status").isEqualTo(503)
                .jsonPath("$.path").isEqualTo("/api/ledger/entries")
                .jsonPath("$.detail").isEqualTo("KEYS_UNAVAILABLE");
    }
}
