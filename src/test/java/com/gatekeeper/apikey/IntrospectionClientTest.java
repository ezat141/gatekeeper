package com.gatekeeper.apikey;

import com.github.tomakehurst.wiremock.WireMockServer;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.time.Instant;
import java.time.temporal.ChronoUnit;

import static com.github.tomakehurst.wiremock.client.WireMock.aResponse;
import static com.github.tomakehurst.wiremock.client.WireMock.equalTo;
import static com.github.tomakehurst.wiremock.client.WireMock.okJson;
import static com.github.tomakehurst.wiremock.client.WireMock.post;
import static com.github.tomakehurst.wiremock.client.WireMock.postRequestedFor;
import static com.github.tomakehurst.wiremock.client.WireMock.urlEqualTo;
import static com.github.tomakehurst.wiremock.core.WireMockConfiguration.options;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * {@link IntrospectionClient} against a fake AuthCore. Each test builds its own client via
 * {@link #client(Duration)} so it can vary the timeout, and resets the server's stubs and
 * request log first so tests cannot see each other's state.
 */
class IntrospectionClientTest {

    static final String PATH = "/api/internal/api-keys/introspect";

    static WireMockServer authCore;

    @BeforeAll
    static void start() {
        authCore = new WireMockServer(options().dynamicPort());
        authCore.start();
    }

    @AfterAll
    static void stop() {
        authCore.stop();
    }

    @Test
    void returnsTheActiveAnswer() {
        authCore.resetAll();
        // A non-null expiresAt, matching the shape AuthCore actually sends for an ordinary
        // key (only the gateway's own introspection key gets expiresAt: null). A stub without
        // it would never prove this client can parse the field at all.
        Instant expiresAt = Instant.now().plus(1, ChronoUnit.HOURS);
        authCore.stubFor(post(urlEqualTo(PATH)).willReturn(okJson("""
                {"active":true,"name":"reporting","scopes":["payments:read"],"expiresAt":"%s"}"""
                .formatted(expiresAt))));

        StepVerifier.create(client(Duration.ofSeconds(2)).introspect("ak_good"))
                .assertNext(result -> {
                    assertThat(result.active()).isTrue();
                    assertThat(result.scopes()).containsExactly("payments:read");
                    assertThat(result.expiresAt()).isEqualTo(expiresAt);
                })
                .verifyComplete();
    }

    /**
     * Without this, the gateway would be anonymous to AuthCore's introspection endpoint and
     * refused outright — it is guarded by {@code SCOPE_apikeys:introspect}, which only the
     * gateway's own key carries.
     */
    @Test
    void presentsTheGatewaysOwnKey() {
        authCore.resetAll();
        authCore.stubFor(post(urlEqualTo(PATH)).willReturn(okJson("""
                {"active":false}""")));

        client(Duration.ofSeconds(2)).introspect("ak_whatever").block();

        authCore.verify(postRequestedFor(urlEqualTo(PATH))
                .withHeader("X-API-Key", equalTo("ak_gateway_test_key")));
    }

    /**
     * A 3xx is not an error to {@code retrieve()}, and a redirect carries no body — so
     * without explicit status handling, {@code bodyToMono} would complete EMPTY rather than
     * fail. Not hypothetical: measured against the real AuthCore before it grew a 400
     * handler, a malformed body produced a 302 to {@code /login} for a client accepting
     * {@code text/html}, and a 401 for a JSON client.
     *
     * <p>An empty completion does not become a JWT fallthrough, as an earlier version of
     * this comment claimed. {@code AuthenticationWebFilter} guards its own manager call with
     * {@code switchIfEmpty(error(IllegalStateException("No provider found for ...")))}, so
     * an empty manager result fails closed as a 500 — verified against Spring Security
     * 7.0.6, not assumed. Failing here instead makes the error say what actually went wrong
     * rather than leaning on the framework to keep failing closed. The genuine fallthrough
     * risk lives one level up, on the converter's empty, and is pinned separately.
     */
    @Test
    void failsOnARedirectRatherThanCompletingEmpty() {
        authCore.resetAll();
        authCore.stubFor(post(urlEqualTo(PATH)).willReturn(
                aResponse().withStatus(302).withHeader("Location", "/login")));

        StepVerifier.create(client(Duration.ofSeconds(2)).introspect("ak_good"))
                .expectError(IntrospectionUnavailableException.class)
                .verify();
    }

    /**
     * The one case only {@code onStatus} can catch: a 3xx carrying a real, decodable body.
     * This is not about redirects being unusual — it is that without the status guard, a 3xx
     * with a body is indistinguishable from a genuine answer. {@code retrieve()} does not
     * error on a 3xx, the stubbed body below decodes to {@code active=true} without incident,
     * and {@code switchIfEmpty} never fires because the pipeline never goes empty. Anything
     * able to interpose a redirect between the gateway and AuthCore — a misconfigured proxy,
     * a captive portal, a compromised load balancer — could mint an affirmative introspection
     * result for a key it never validated.
     *
     * <p>{@link #failsOnARedirectRatherThanCompletingEmpty()} above cannot catch a regression
     * here: its redirect has no body, so {@code switchIfEmpty} raises the same exception
     * independently of {@code onStatus} and masks whether the status guard ran at all.
     */
    @Test
    void failsOnARedirectCarryingABodyRatherThanAcceptingIt() {
        authCore.resetAll();
        authCore.stubFor(post(urlEqualTo(PATH)).willReturn(okJson("""
                {"active":true,"name":"reporting","scopes":["payments:read"]}""")
                .withStatus(302)
                .withHeader("Location", "/login")));

        StepVerifier.create(client(Duration.ofSeconds(2)).introspect("ak_good"))
                .expectError(IntrospectionUnavailableException.class)
                .verify();
    }

    /** A 200 with no body must fail outright too, for the same completes-empty reason. */
    @Test
    void failsOnAnEmptyBodyRatherThanCompletingEmpty() {
        authCore.resetAll();
        authCore.stubFor(post(urlEqualTo(PATH)).willReturn(aResponse().withStatus(200)));

        StepVerifier.create(client(Duration.ofSeconds(2)).introspect("ak_good"))
                .expectError(IntrospectionUnavailableException.class)
                .verify();
    }

    @Test
    void failsWhenAuthCoreErrors() {
        authCore.resetAll();
        authCore.stubFor(post(urlEqualTo(PATH)).willReturn(aResponse().withStatus(500)));

        StepVerifier.create(client(Duration.ofSeconds(2)).introspect("ak_good"))
                .expectError(IntrospectionUnavailableException.class)
                .verify();
    }

    /**
     * A host that accepts the connection and never answers in time must fail, not hang — the
     * JWKS fetch has exactly this gap and it is filed as an M7 defect; see {@link
     * IntrospectionClient}'s class Javadoc. The delay is well above the client's configured
     * timeout, and the overall assertion is bounded by {@code verify(Duration)} so a
     * regression that removed the timeout would fail this test instead of hanging the build.
     */
    @Test
    void failsWhenAuthCoreIsTooSlowRatherThanHanging() {
        authCore.resetAll();
        authCore.stubFor(post(urlEqualTo(PATH)).willReturn(okJson("""
                {"active":true}""").withFixedDelay(1500)));

        StepVerifier.create(client(Duration.ofMillis(200)).introspect("ak_good"))
                .expectError(IntrospectionUnavailableException.class)
                .verify(Duration.ofSeconds(5));
    }

    private static IntrospectionClient client(Duration timeout) {
        ApiKeyProperties properties = new ApiKeyProperties(
                authCore.baseUrl() + PATH, "ak_gateway_test_key",
                Duration.ofSeconds(60), Duration.ofSeconds(10), timeout);
        return new IntrospectionClient(WebClient.builder().build(), properties);
    }
}
