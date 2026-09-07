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
        if (!carriesKey(exchange)) {
            return Mono.empty();
        }
        String rawKey = exchange.getRequest().getHeaders().getFirst(HEADER_NAME);
        return Mono.just(new ApiKeyAuthenticationToken(rawKey));
    }

    /**
     * Whether this request carries an API key at all. Shared so the resource server's
     * deferral in GatewaySecurityConfig cannot drift from what this converter actually
     * accepts — if the two disagree, a request can be declined by both paths.
     */
    public static boolean carriesKey(ServerWebExchange exchange) {
        return StringUtils.hasText(exchange.getRequest().getHeaders().getFirst(HEADER_NAME));
    }
}
