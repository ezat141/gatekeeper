package com.gatekeeper.error;

import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.codec.HttpMessageWriter;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.reactive.result.view.ViewResolver;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Map;

/**
 * The 401 for a missing or rejected bearer token does not go through {@link
 * GlobalErrorWebExceptionHandler}. Spring Security's reactive resource-server support
 * invokes this entry point directly from inside its own filter and commits the response
 * itself — it never throws, so no exception ever reaches the WebFlux error-handling layer
 * that class hooks into. Left at Spring Security's default, that path would be the one gap
 * in an otherwise uniform error shape: an empty body where every other failure carries the
 * {@link ErrorBody} JSON envelope.
 *
 * <p>Writes the identical shape using the same {@link ServerCodecConfigurer} writers {@link
 * GlobalErrorWebExceptionHandler} uses, rather than serialising independently (a directly
 * injected {@code ObjectMapper}, say) — one write path for one shape, so the two cannot
 * drift apart.
 *
 * <p>{@code WWW-Authenticate: Bearer} is set explicitly and must survive here: RFC 6750
 * requires it on a 401 from a bearer-token resource, and losing it while adding the JSON
 * body would trade one gap for another.
 */
@Component
public class JsonServerAuthenticationEntryPoint implements ServerAuthenticationEntryPoint {

    private final ServerCodecConfigurer codecConfigurer;

    public JsonServerAuthenticationEntryPoint(ServerCodecConfigurer codecConfigurer) {
        this.codecConfigurer = codecConfigurer;
    }

    @Override
    public Mono<Void> commence(ServerWebExchange exchange, AuthenticationException ex) {
        String path = exchange.getRequest().getPath().value();
        Map<String, Object> body = ErrorBody.of(HttpStatus.UNAUTHORIZED, path);

        return ServerResponse.status(HttpStatus.UNAUTHORIZED)
                .header(HttpHeaders.WWW_AUTHENTICATE, "Bearer")
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .flatMap(response -> response.writeTo(exchange, new WriterContext()));
    }

    /**
     * {@link ServerResponse#writeTo} needs a {@link ServerResponse.Context} to know which
     * writers are available; {@code AbstractErrorWebExceptionHandler} satisfies the same
     * requirement for itself the same way, by supplying its configured writers and no view
     * resolvers.
     */
    private final class WriterContext implements ServerResponse.Context {
        @Override
        public List<HttpMessageWriter<?>> messageWriters() {
            return codecConfigurer.getWriters();
        }

        @Override
        public List<ViewResolver> viewResolvers() {
            return List.of();
        }
    }
}
