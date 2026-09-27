package com.gatekeeper.error;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.http.server.reactive.MockServerHttpResponse;
import org.springframework.mock.web.server.MockServerWebExchange;

import java.util.LinkedHashMap;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class TooManyRequestsWriterTest {

    private final TooManyRequestsWriter writer = new TooManyRequestsWriter(ServerCodecConfigurer.create());

    @Test
    void writesThePlatformShapeWithTheGivenDetailAndHeaders() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/api/ledger/entries"));
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put(HttpHeaders.RETRY_AFTER, "7");
        headers.put("X-RateLimit-Remaining", "0");

        writer.write(exchange, "the request rate exceeds the caller's plan", headers).block();

        MockServerHttpResponse response = exchange.getResponse();
        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(response.getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_JSON);
        assertThat(response.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("7");
        assertThat(response.getHeaders().getFirst("X-RateLimit-Remaining")).isEqualTo("0");
        assertThat(response.getBodyAsString().block()).isEqualTo(
                "{\"error\":\"too_many_requests\",\"status\":429,\"path\":\"/api/ledger/entries\","
                        + "\"detail\":\"the request rate exceeds the caller's plan\"}");
    }

    /** The caller is authenticated; the answer is to wait, not to re-authenticate. */
    @Test
    void setsNoChallenge() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/x"));

        writer.write(exchange, "the caller's daily quota is used up", Map.of()).block();

        assertThat(exchange.getResponse().getHeaders().get(HttpHeaders.WWW_AUTHENTICATE)).isNull();
    }

    @Test
    void keepsTheJsonContentTypeWhateverTheCallerPasses() {
        MockServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/x"));
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put(HttpHeaders.CONTENT_TYPE, "text/plain");
        headers.put(HttpHeaders.RETRY_AFTER, "3");

        writer.write(exchange, "the caller's daily quota is used up", headers).block();

        MockServerHttpResponse response = exchange.getResponse();
        assertThat(response.getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_JSON);
        assertThat(response.getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("3");
        assertThat(response.getBodyAsString().block()).startsWith("{\"error\":\"too_many_requests\"");
    }
}
