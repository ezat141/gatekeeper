package com.gatekeeper.error;

import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * Writes the 429 the rate limiter refuses with, in the platform's {@link ErrorBody} shape, through
 * the same writers as the 401 entry point and the 403 handler. The limiter completes the response
 * itself with this rather than throwing, so the 429 shape is written in exactly one place. The
 * M5 design, section 8.
 *
 * <p>The caller supplies the {@code detail} and every header, {@code Retry-After} included: this
 * class knows the shape of a refusal, not the rules of rate limiting. No {@code WWW-Authenticate}
 * — the caller is authenticated. The content type is always JSON; a caller cannot override it.
 */
@Component
public class TooManyRequestsWriter {

    private final ServerCodecConfigurer codecConfigurer;

    public TooManyRequestsWriter(ServerCodecConfigurer codecConfigurer) {
        this.codecConfigurer = codecConfigurer;
    }

    public Mono<Void> write(ServerWebExchange exchange, String detail, Map<String, String> headers) {
        String path = exchange.getRequest().getPath().value();
        return ServerResponse.status(HttpStatus.TOO_MANY_REQUESTS)
                .headers(outgoing -> outgoing.setAll(headers))
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(ErrorBody.of(HttpStatus.TOO_MANY_REQUESTS, path, detail))
                .flatMap(response -> response.writeTo(exchange, new CodecWriterContext(codecConfigurer)));
    }
}
