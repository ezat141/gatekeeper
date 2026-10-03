package com.gatekeeper.config;

import com.gatekeeper.support.TestKey;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
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

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A key set that accepts the connection and never answers. Before M7 the request hung; now it is
 * refused 503 KEYS_UNAVAILABLE within about the JWKS timeout. The M7 design, section 4.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureWebTestClient
@ExtendWith(OutputCaptureExtension.class)
class JwksTimeoutTest {

    static final String ISSUER = "http://localhost:8080";
    static final List<Socket> held = new CopyOnWriteArrayList<>();
    static ServerSocket silent;
    static TestKey key;

    @Autowired
    WebTestClient client;

    @BeforeAll
    static void start() throws IOException {
        key = TestKey.generate("k1");
        silent = new ServerSocket(0);
        Thread acceptor = new Thread(() -> {
            while (!silent.isClosed()) {
                try {
                    held.add(silent.accept());
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
        silent.close();
        for (Socket socket : held) {
            socket.close();
        }
    }

    @DynamicPropertySource
    static void properties(DynamicPropertyRegistry registry) {
        registry.add("gatekeeper.auth.jwk-set-uri", () -> "http://localhost:" + silent.getLocalPort() + "/oauth2/jwks");
        registry.add("gatekeeper.auth.issuer", () -> ISSUER);
        registry.add("gatekeeper.resilience.jwks-timeout", () -> "300ms");
    }

    @Test
    void refusesWith503WithinTheTimeoutInsteadOfHanging(CapturedOutput output) {
        String token = key.mint(ISSUER, "ezzat", Instant.now().plus(5, ChronoUnit.MINUTES),
                Map.of("tenant", "acme", "scope", List.of("payments:read")));
        long started = System.nanoTime();

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

        assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(3));
        // Proves the logging filter is wired into the decoder's WebClient: the failed fetch is logged once.
        String warning = "AuthCore's key set could not be fetched";
        assertThat(output.getOut().split(java.util.regex.Pattern.quote(warning), -1).length - 1).isEqualTo(1);
    }
}
