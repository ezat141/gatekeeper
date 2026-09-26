package com.gatekeeper.error;

import com.gatekeeper.authz.GatewayAccessDeniedException;
import com.gatekeeper.authz.Reason;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpResponse;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.access.AccessDeniedException;

import java.util.Arrays;

import static org.assertj.core.api.Assertions.assertThat;

class JsonServerAccessDeniedHandlerTest {

    private final JsonServerAccessDeniedHandler handler =
            new JsonServerAccessDeniedHandler(ServerCodecConfigurer.create());

    @ParameterizedTest
    @EnumSource(Reason.class)
    void rendersEachReasonAsItsOwnDetail(Reason reason) {
        MockServerWebExchange exchange = exchangeFor("/api/ledger/entries");

        handler.handle(exchange, new GatewayAccessDeniedException(reason)).block();

        assertForbiddenWithDetail(exchange, "/api/ledger/entries", reason.detail());
    }

    /**
     * A denial that did not come from the gateway's own managers carries no {@link Reason}.
     * Its message is a framework string never meant for a wire contract, so it must not be
     * echoed — the generic detail stands in for it.
     */
    @Test
    void rendersAPlainDenialWithTheGenericDetailRatherThanItsMessage() {
        MockServerWebExchange exchange = exchangeFor("/api/machine/payments");

        handler.handle(exchange, new AccessDeniedException("Access Denied (internal)")).block();

        assertForbiddenWithDetail(exchange, "/api/machine/payments",
                JsonServerAccessDeniedHandler.GENERIC_DETAIL);
    }

    /** Two reasons sharing a detail would make a caller unable to tell them apart. */
    @Test
    void everyReasonHasADistinctDetail() {
        assertThat(Arrays.stream(Reason.values()).map(Reason::detail).distinct())
                .hasSize(Reason.values().length);
    }

    private static MockServerWebExchange exchangeFor(String path) {
        return MockServerWebExchange.from(MockServerHttpRequest.get(path));
    }

    private static void assertForbiddenWithDetail(
            MockServerWebExchange exchange, String path, String detail) {
        MockServerHttpResponse response = exchange.getResponse();
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.FORBIDDEN);
        assertThat(response.getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_JSON);
        // The platform rule, stated in ledger-service's handler too: a 403 carries no challenge.
        assertThat(response.getHeaders().get(HttpHeaders.WWW_AUTHENTICATE)).isNull();
        assertThat(response.getBodyAsString().block()).isEqualTo(
                "{\"error\":\"forbidden\",\"status\":403,\"path\":\"%s\",\"detail\":\"%s\"}"
                        .formatted(path, detail));
    }
}
