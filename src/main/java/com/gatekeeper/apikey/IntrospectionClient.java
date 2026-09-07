package com.gatekeeper.apikey;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
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
 *
 * <p>A failed call is never cached, unlike a definitive "active" or "inactive" answer.
 * Caching "AuthCore could not be reached" would need a policy for how long to keep
 * believing an outage once AuthCore actually recovers — that is a circuit breaker's job,
 * not something to improvise here. Until M7 adds one, every request made while AuthCore is
 * down independently pays this class's own timeout: an outage's request rate against
 * AuthCore is not dampened the way a bad key's is by {@link
 * ApiKeyReactiveAuthenticationManager}'s cache.
 */
public class IntrospectionClient {

    private static final Logger log = LoggerFactory.getLogger(IntrospectionClient.class);

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
                // body — so without this, bodyToMono would complete EMPTY rather than fail,
                // and worse, a 3xx that DOES carry a body would decode as a real answer: a
                // redirect accepted as proof the key is active. Both are pinned by tests.
                //
                // An empty completion does not reach the caller as a fallthrough, as an
                // earlier version of this comment claimed. AuthenticationWebFilter guards
                // its own manager call with switchIfEmpty(error(IllegalStateException("No
                // provider found for ..."))), so an empty manager result fails closed as a
                // 500. Failing here instead makes the error say what actually went wrong,
                // and does not lean on the framework continuing to fail closed.
                .onStatus(status -> !status.is2xxSuccessful(),
                        response -> {
                            if (HttpStatus.UNAUTHORIZED.equals(response.statusCode())) {
                                // AuthCore refused the GATEWAY's own introspection credential,
                                // not the caller's. The caller sees the same 503 as any other
                                // introspection failure (GlobalErrorWebExceptionHandler does
                                // not distinguish why AuthCore could not be asked), so this
                                // line is the only record of which failure this actually was;
                                // never the gateway's key itself, since that is a credential
                                // and a log is not where it belongs.
                                log.warn("AuthCore refused the gateway's own introspection "
                                        + "credential (401); check gatekeeper.api-key.gateway-key");
                            }
                            return Mono.error(new IntrospectionUnavailableException(
                                    "Introspection answered " + response.statusCode(), null));
                        })
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
