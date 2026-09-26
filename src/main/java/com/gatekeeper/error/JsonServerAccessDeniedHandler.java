package com.gatekeeper.error;

import com.gatekeeper.authz.GatewayAccessDeniedException;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.ServerResponse;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.Map;

/**
 * The 403 counterpart of {@link JsonServerAuthenticationEntryPoint}, needed for the same
 * reason: {@code ExceptionTranslationWebFilter} hands an access denial straight to this
 * handler, which commits the response itself, so nothing reaches {@link
 * GlobalErrorWebExceptionHandler}. Left at the default, a 403 would be the one refusal with an
 * empty body. For a bearer caller it would be worse: the resource server's default handler
 * stamps {@code WWW-Authenticate: Bearer error="insufficient_scope"} on every denial,
 * including a tenant mismatch that no scope could ever fix.
 *
 * <p>{@code detail} is always a string the gateway authored — the denial's {@code Reason}, or
 * {@link #GENERIC_DETAIL} for a denial that carries none. It never echoes {@link
 * AccessDeniedException#getMessage()}.
 *
 * <p>No {@code WWW-Authenticate}. The caller is authenticated, and no challenge would help
 * them. ledger-service's handler states the same rule, and the two services must agree.
 */
@Component
public class JsonServerAccessDeniedHandler implements ServerAccessDeniedHandler {

    static final String GENERIC_DETAIL = "the credential does not permit this request";

    private final ServerCodecConfigurer codecConfigurer;

    public JsonServerAccessDeniedHandler(ServerCodecConfigurer codecConfigurer) {
        this.codecConfigurer = codecConfigurer;
    }

    @Override
    public Mono<Void> handle(ServerWebExchange exchange, AccessDeniedException denied) {
        String detail = denied instanceof GatewayAccessDeniedException gatewayDenial
                ? gatewayDenial.reason().detail()
                : GENERIC_DETAIL;
        String path = exchange.getRequest().getPath().value();
        Map<String, Object> body = ErrorBody.of(HttpStatus.FORBIDDEN, path, detail);

        return ServerResponse.status(HttpStatus.FORBIDDEN)
                .contentType(MediaType.APPLICATION_JSON)
                .bodyValue(body)
                .flatMap(response -> response.writeTo(exchange, new CodecWriterContext(codecConfigurer)));
    }
}
