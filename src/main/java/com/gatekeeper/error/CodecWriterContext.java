package com.gatekeeper.error;

import org.springframework.http.codec.HttpMessageWriter;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.reactive.result.view.ViewResolver;

import java.util.List;

/**
 * {@link ServerResponse#writeTo} needs a {@link ServerResponse.Context} to know which writers
 * are available. Both handlers that commit a response outside the WebFlux error-handling
 * layer — {@link JsonServerAuthenticationEntryPoint} and {@link
 * JsonServerAccessDeniedHandler} — supply the application's configured writers and no view
 * resolvers, which is how {@code AbstractErrorWebExceptionHandler} satisfies the same
 * requirement for itself. One class, so the two use the same writers; the shape itself is
 * {@link ErrorBody}'s.
 */
final class CodecWriterContext implements ServerResponse.Context {

    private final ServerCodecConfigurer codecConfigurer;

    CodecWriterContext(ServerCodecConfigurer codecConfigurer) {
        this.codecConfigurer = codecConfigurer;
    }

    @Override
    public List<HttpMessageWriter<?>> messageWriters() {
        return codecConfigurer.getWriters();
    }

    @Override
    public List<ViewResolver> viewResolvers() {
        return List.of();
    }
}
