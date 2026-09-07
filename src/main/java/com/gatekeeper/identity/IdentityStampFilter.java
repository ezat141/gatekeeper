package com.gatekeeper.identity;

import com.gatekeeper.apikey.ApiKeyAuthenticationToken;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.security.core.Authentication;
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
 * the verified {@link Authentication} does not exist any earlier. Its counterpart
 * {@link InboundHeaderStripFilter} runs before security. The pair straddles the security
 * filter because one half needs the request untouched and the other needs the
 * authentication result.
 *
 * <p>These headers are a convenience for downstreams that are not themselves resource
 * servers. For a JWT caller they are never authoritative: ledger-service re-verifies the
 * bearer token, which is forwarded unchanged. An API-key caller has no such independent
 * check to fall back on — introspection needs the {@code apikeys:introspect} scope, which
 * only the gateway's own key carries — so {@code X-GK-Subject} is the only attribution a
 * downstream gets for that caller.
 */
@Component
public class IdentityStampFilter implements GlobalFilter, Ordered {

    static final String SUBJECT = "X-GK-Subject";
    static final String TENANT = "X-GK-Tenant";
    static final String PERMISSIONS = "X-GK-Permissions";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        // A SecurityContext whose own authentication is null — distinct from no
        // SecurityContext at all, which defaultIfEmpty below already covers — would NPE
        // right here: Mono::map rejects a null return before stamp() ever sees it (confirmed
        // by driving this method directly with such a context). Unreached today: Spring
        // Security's own filters never publish one (an anonymous caller gets a concrete
        // token, never a null), and every route this filter sees requires
        // anyExchange().authenticated(), which rejects an anonymous caller before routing
        // runs. Pre-existing and unchanged from the JWT-only pipeline this replaces.
        return ReactiveSecurityContextHolder.getContext()
                .map(SecurityContext::getAuthentication)
                .map(authentication -> stamp(exchange, authentication))
                .defaultIfEmpty(exchange)
                .flatMap(chain::filter);
    }

    /**
     * Dispatches on principal type, purely by {@code instanceof}. That check is null-safe
     * on its own — the JLS defines {@code null instanceof T} as {@code false} for any
     * {@code T} — so any {@link Authentication} this method is actually handed that is
     * neither of the two types below, anonymous included, falls through to the last line
     * rather than throwing.
     */
    private static ServerWebExchange stamp(ServerWebExchange exchange, Authentication authentication) {
        if (authentication instanceof JwtAuthenticationToken jwtAuthentication) {
            return stampJwt(exchange, jwtAuthentication.getToken());
        }
        if (authentication instanceof ApiKeyAuthenticationToken apiKeyAuthentication) {
            return stampApiKey(exchange, apiKeyAuthentication);
        }
        return exchange;
    }

    private static ServerWebExchange stampJwt(ServerWebExchange exchange, Jwt jwt) {
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
     * Subject only. A key has no tenant — api_keys has no such column, and M4 writes one
     * rule for tenant-less principals covering both keys and client-credentials tokens.
     * Scopes are not stamped either: scopes and permissions are different vocabularies, and
     * the only downstream that acts on a key's scopes is AuthCore, which re-derives them
     * from the key.
     */
    private static ServerWebExchange stampApiKey(
            ServerWebExchange exchange, ApiKeyAuthenticationToken authentication) {
        return exchange.mutate()
                .request(request -> request.headers(headers ->
                        headers.set(SUBJECT, "apikey:" + authentication.getName())))
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
