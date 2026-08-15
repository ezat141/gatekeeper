package com.gatekeeper.identity;

import org.springframework.core.Ordered;
import org.springframework.core.annotation.Order;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebFilter;
import org.springframework.web.server.WebFilterChain;
import reactor.core.publisher.Mono;

/**
 * Removes every inbound {@code X-GK-*} header before anything else runs.
 *
 * <p>Ordered ahead of Spring Security deliberately. Stripping after authentication would
 * leave the error paths exposed: a request that fails authentication still gets a response
 * rendered, and a header surviving that far could be laundered by anything downstream. The
 * strip is therefore unconditional and applies to permitted routes such as health too.
 *
 * <p>Matched by prefix rather than an enumerated list, so a fourth header added later
 * cannot silently become spoofable.
 */
@Component
@Order(Ordered.HIGHEST_PRECEDENCE)
public class InboundHeaderStripFilter implements WebFilter {

    static final String PREFIX = "X-GK-";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, WebFilterChain chain) {
        boolean carriesGatewayHeaders = exchange.getRequest().getHeaders().headerNames().stream()
                .anyMatch(InboundHeaderStripFilter::isGatewayHeader);

        if (!carriesGatewayHeaders) {
            return chain.filter(exchange);
        }

        ServerWebExchange stripped = exchange.mutate()
                .request(request -> request.headers(headers -> headers.headerNames().stream()
                        .filter(InboundHeaderStripFilter::isGatewayHeader)
                        .toList()
                        .forEach(headers::remove)))
                .build();

        return chain.filter(stripped);
    }

    /**
     * Case-insensitive prefix match. {@code regionMatches} rather than lower-casing avoids
     * both an allocation per header and the Turkish-dotless-i class of locale surprise.
     */
    private static boolean isGatewayHeader(String name) {
        return name.regionMatches(true, 0, PREFIX, 0, PREFIX.length());
    }
}
