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

    /**
     * {@code getHeaders().getFirst(HEADER_NAME)} silently takes the first value of a
     * duplicated header and ignores the rest. That is not pinned here because "first wins"
     * is obviously the right default — it is pinned because a proxy and an application
     * disagreeing about which duplicate is authoritative is exactly the kind of header
     * handling that has produced auth-bypass bugs elsewhere. This must not change silently.
     */
    @Test
    void usesTheFirstValueWhenTheHeaderIsDuplicated() {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/ledger/entries")
                .header(ApiKeyAuthenticationConverter.HEADER_NAME, "ak_first", "ak_second")
                .build();
        StepVerifier.create(converter.convert(MockServerWebExchange.from(request)))
                .assertNext(authentication -> assertThat(authentication.getCredentials()).isEqualTo("ak_first"))
                .verifyComplete();
    }

    /**
     * {@code StringUtils.hasText(" ak_x ")} is true, so a padded value counts as present and
     * is forwarded exactly as received, whitespace included. The pass-through is deliberate,
     * not an oversight: bearer tokens aren't trimmed either, and quietly repairing a padded
     * credential would mask a deployment mistake instead of surfacing it. A padded key is a
     * caller error and should fail introspection as one, not be silently corrected here.
     */
    @Test
    void passesThroughAPaddedValueUntrimmed() {
        StepVerifier.create(convert(" ak_x "))
                .assertNext(authentication -> assertThat(authentication.getCredentials()).isEqualTo(" ak_x "))
                .verifyComplete();
    }

    private Mono<Authentication> convert(String headerValue) {
        MockServerHttpRequest request = MockServerHttpRequest.get("/api/ledger/entries")
                .header(ApiKeyAuthenticationConverter.HEADER_NAME, headerValue)
                .build();
        return converter.convert(MockServerWebExchange.from(request));
    }
}
