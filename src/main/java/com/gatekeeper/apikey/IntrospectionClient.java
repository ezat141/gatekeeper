package com.gatekeeper.apikey;

import org.springframework.http.MediaType;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Asks AuthCore about a key, presenting the gateway's own key as identification.
 *
 * <p>Carries an explicit response timeout. Spring Security's ReactiveRemoteJWKSource does
 * not, which is why an unreachable-but-listening JWKS host hangs the request instead of
 * failing closed; that is recorded as an M7 defect. Building a second outbound call with
 * the same gap would be repeating a known bug deliberately.
 */
public class IntrospectionClient {

    private final WebClient webClient;
    private final ApiKeyProperties properties;

    public IntrospectionClient(WebClient webClient, ApiKeyProperties properties) {
        this.webClient = webClient;
        this.properties = properties;
    }

    public Mono<ApiKeyIntrospection> introspect(String rawKey) {
        return webClient.post()
                .uri(properties.introspectionUri())
                .header(ApiKeyAuthenticationConverter.HEADER_NAME, properties.gatewayKey())
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(Map.of("key", rawKey))
                .retrieve()
                // retrieve() errors on 4xx and 5xx but NOT on 3xx, and a redirect carries no
                // body — so without this, bodyToMono would complete EMPTY rather than fail.
                // An empty completion propagates through the manager and reaches
                // AuthenticationWebFilter as "no authentication", which CONTINUES the filter
                // chain — turning a failed introspection into the JWT fallthrough that the
                // precedence rule forbids.
                .onStatus(status -> !status.is2xxSuccessful(),
                        response -> Mono.error(new IntrospectionUnavailableException(
                                "Introspection answered " + response.statusCode(), null)))
                .bodyToMono(ApiKeyIntrospection.class)
                // A 200 with a genuinely empty body completes empty the same way a bodyless
                // 3xx does — confirmed separately from the unparseable case below, since a
                // non-empty-but-invalid body doesn't land here at all: bodyToMono raises a
                // DecodingException instead, which onErrorMap below still wraps.
                .switchIfEmpty(Mono.error(new IntrospectionUnavailableException(
                        "Introspection returned no body", null)))
                .timeout(properties.timeout())
                .onErrorMap(error -> !(error instanceof IntrospectionUnavailableException),
                        error -> new IntrospectionUnavailableException(
                                "API key introspection failed", error));
    }
}
