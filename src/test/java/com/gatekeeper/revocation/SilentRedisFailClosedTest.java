package com.gatekeeper.revocation;

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

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.atomic.AtomicInteger;

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
 * A Redis that accepts the connection and never answers. A bearer token is refused 503 within about
 * the revocation timeout — not after Lettuce's own 60-second handshake, which is how AuthCore
 * behaves — and the gateway makes one connection attempt, whoever gives up waiting on it. The M6
 * design, sections 7 and 11.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
class SilentRedisFailClosedTest {

    static final String ISSUER = "http://localhost:8080";
    static final List<Socket> held = new CopyOnWriteArrayList<>();
    static final AtomicInteger accepted = new AtomicInteger();
    static WireMockServer downstream;
    static TestKey signingKey;
    static ServerSocket silent;

    @Autowired
    WebTestClient client;

    @BeforeAll
    static void start() throws IOException {
        signingKey = TestKey.generate("k1");
        downstream = new WireMockServer(options().dynamicPort());
        downstream.start();
        downstream.stubFor(get(urlEqualTo("/oauth2/jwks")).willReturn(okJson(TestKey.jwksDocument(signingKey))));
        downstream.stubFor(any(anyUrl()).atPriority(20).willReturn(okJson("{}")));
        silent = new ServerSocket(0);
        Thread acceptor = new Thread(() -> {
            while (!silent.isClosed()) {
                try {
                    held.add(silent.accept());
                    accepted.incrementAndGet();
                } catch (IOException closed) {
                    return;
                }
            }
        });
        acceptor.setDaemon(true);
        acceptor.start();
    }

    @AfterAll
    static void stop() throws IOException {
        downstream.stop();
        silent.close();
        for (Socket socket : held) {
            socket.close();
        }
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("gatekeeper.auth.jwk-set-uri", () -> downstream.baseUrl() + "/oauth2/jwks");
        registry.add("gatekeeper.auth.issuer", () -> ISSUER);
        registry.add("gatekeeper.downstream.ledger", () -> downstream.baseUrl());
        registry.add("gatekeeper.downstream.authcore", () -> downstream.baseUrl());
        registry.add("spring.data.redis.port", () -> silent.getLocalPort());
    }

    @Test
    void refusesEveryRequestWithinTheTimeoutAndConnectsOnce() {
        String token = "Bearer " + signingKey.mint(ISSUER, "ezzat", Instant.now().plus(5, ChronoUnit.MINUTES),
                Map.of("tenant", "acme", "scope", List.of("payments:read")));

        for (int i = 0; i < 10; i++) {
            long started = System.nanoTime();

            client.get().uri("/api/ledger/entries")
                    .header(HttpHeaders.AUTHORIZATION, token)
                    .exchange()
                    .expectStatus().isEqualTo(503)
                    .expectHeader().valueEquals(HttpHeaders.RETRY_AFTER, "5")
                    .expectBody().jsonPath("$.detail").isEqualTo(RevocationUnavailableException.DETAIL);

            // The first request also pays for the cold path; the check's own share is its timeout.
            Duration bound = i == 0 ? Duration.ofSeconds(5) : Duration.ofSeconds(1);
            assertThat(Duration.ofNanos(System.nanoTime() - started)).as("request %d", i).isLessThan(bound);
        }

        // Exactly one: the warm-up's attempt, which every later caller shares rather than repeats. It stays
        // pending for the whole run, well under the 60 s handshake timeout (the TCP connect succeeds, so
        // Lettuce's bound is RedisURI's timeout); a longer run could see a second attempt.
        assertThat(accepted).as("connections accepted by the silent Redis").hasValue(1);

        downstream.verify(0, anyRequestedFor(urlPathMatching("/ledger/.*")));
    }
}
