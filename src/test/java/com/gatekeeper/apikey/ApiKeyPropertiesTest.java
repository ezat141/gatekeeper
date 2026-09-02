package com.gatekeeper.apikey;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import java.time.Duration;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * Confirms {@code gatekeeper.api-key.*} in {@code application.yml} actually reaches {@link
 * ApiKeyProperties} with the right types. Relaxed binding accepts a mistyped key silently — the
 * field is just left {@code null} — so {@link com.gatekeeper.GateKeeperApplicationTests} proving
 * the context starts does not prove these values bound correctly; only reading them back does.
 */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class ApiKeyPropertiesTest {

    @Autowired
    ApiKeyProperties properties;

    @Test
    void bindsFromApplicationYml() {
        assertThat(properties.introspectionUri())
                .isEqualTo("http://localhost:8080/api/internal/api-keys/introspect");
        assertThat(properties.gatewayKey()).isEqualTo("ak_gatekeeper_introspection_local_only_00000");
        assertThat(properties.cacheTtl()).isEqualTo(Duration.ofSeconds(60));
        assertThat(properties.negativeCacheTtl()).isEqualTo(Duration.ofSeconds(10));
        assertThat(properties.timeout()).isEqualTo(Duration.ofSeconds(2));
    }
}
