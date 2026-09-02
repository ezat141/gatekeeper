package com.gatekeeper.apikey;

import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

/**
 * Turns an {@code X-API-Key} header into an unauthenticated token for the manager to
 * verify. Returns empty when the header is absent or blank, so a bearer-token request
 * passes through to the JWT path exactly as it did before M3.
 */
public class ApiKeyAuthenticationConverter implements ServerAuthenticationConverter {

    public static final String HEADER_NAME = "X-API-Key";

    @Override
    public Mono<Authentication> convert(ServerWebExchange exchange) {
        String rawKey = exchange.getRequest().getHeaders().getFirst(HEADER_NAME);
        if (!StringUtils.hasText(rawKey)) {
            return Mono.empty();
        }
        return Mono.just(new ApiKeyAuthenticationToken(rawKey));
    }
}
