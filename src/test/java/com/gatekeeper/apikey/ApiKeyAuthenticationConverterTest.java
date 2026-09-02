package com.gatekeeper.apikey;

import org.junit.jupiter.api.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;

import static org.assertj.core.api.Assertions.assertThat;

class ApiKeyAuthenticationConverterTest {

    final ApiKeyAuthenticationConverter converter = new ApiKeyAuthenticationConverter();

    @Test
    void producesAnUnauthenticatedTokenWhenTheHeaderIsPresent() {
        StepVerifier.create(convert("ak_something"))
                .assertNext(authentication -> {
                    assertThat(authentication.getCredentials()).isEqualTo("ak_something");
                    assertThat(authentication.isAuthenticated()).isFalse();
                })
                .verifyComplete();
    }

    /**
     * Empty, not an error. A request with no key must fall through to the JWT path
     * untouched — this converter is additive, not a replacement.
     */
    @Test
    void producesNothingWhenTheHeaderIsAbsent() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/ledger/entries").build();
        StepVerifier.create(converter.convert(MockServerWebExchange.from(request)))
                .verifyComplete();
    }

    @Test
    void producesNothingWhenTheHeaderIsBlank() {
        StepVerifier.create(convert("   ")).verifyComplete();
    }

    private Mono<Authentication> convert(String headerValue) {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/ledger/entries")
                .header(ApiKeyAuthenticationConverter.HEADER_NAME, headerValue)
                .build();
        return converter.convert(MockServerWebExchange.from(request));
    }
}
