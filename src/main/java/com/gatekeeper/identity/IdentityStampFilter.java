package com.gatekeeper.identity;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.util.List;

/**
 * Stamps the verified caller identity onto the outbound request.
 *
 * <p>Runs as a gateway filter, which is to say after Spring Security has authenticated —
 * the verified {@link Jwt} does not exist any earlier. Its counterpart
 * {@link InboundHeaderStripFilter} runs before security. The pair straddles the security
 * filter because one half needs the request untouched and the other needs the
 * authentication result.
 *
 * <p>These headers are a convenience for downstreams that are not themselves resource
 * servers. They are never authoritative: ledger-service re-verifies the bearer token,
 * which is forwarded unchanged.
 */
@Component
public class IdentityStampFilter implements GlobalFilter, Ordered {

    static final String SUBJECT = "X-GK-Subject";
    static final String TENANT = "X-GK-Tenant";
    static final String PERMISSIONS = "X-GK-Permissions";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .filter(JwtAuthenticationToken.class::isInstance)
                .map(authentication -> ((JwtAuthenticationToken) authentication).getToken())
                .map(jwt -> stamp(exchange, jwt))
                .defaultIfEmpty(exchange)
                .flatMap(chain::filter);
    }

    private static ServerWebExchange stamp(ServerWebExchange exchange, Jwt jwt) {
        String tenant = jwt.getClaimAsString("tenant");
        List<String> permissions = jwt.getClaimAsStringList("permissions");

        return exchange.mutate()
                .request(request -> request.headers(headers -> {
                    headers.set(SUBJECT, jwt.getSubject());
                    // Absent on client-credentials tokens — AuthCore omits the claim rather
                    // than emitting an empty one, so omit the header rather than sending a
                    // blank a downstream might misread as a value.
                    if (tenant != null) {
                        headers.set(TENANT, tenant);
                    }
                    if (permissions != null && !permissions.isEmpty()) {
                        headers.set(PERMISSIONS, String.join(",", permissions));
                    }
                }))
                .build();
    }

    /**
     * Ahead of the routing filters, which forward the request as it then stands. Leaving
     * this to the default would race {@code NettyRoutingFilter}, which sits at
     * {@code LOWEST_PRECEDENCE}.
     */
    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE;
    }
}
