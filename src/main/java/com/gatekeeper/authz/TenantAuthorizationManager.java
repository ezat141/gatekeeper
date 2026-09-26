package com.gatekeeper.authz;

import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.stream.Stream;

/**
 * Refuses a request that names a tenant other than the token's. The M4 design, section 5.
 *
 * <p>No routed path carries a tenant. What a request <em>can</em> name is the tenant AuthCore
 * resolves it against: the {@code X-Tenant} header, or the {@code tenant} request parameter.
 * Every value of either must equal the token's {@code tenant} claim exactly — case-sensitive,
 * compared raw and never split, a blank counting as a name. A request naming no tenant passes.
 * This is stricter than AuthCore where it acts, and it needs to know neither which tenants
 * exist nor the order AuthCore consults its sources in.
 *
 * <p>Mirrors AuthCore's class of the same name: the wrapped rule decides first, and a caller
 * with no tenant claim — a client-credentials token, or any API key — is never checked. That
 * is the single rule for tenant-less principals the M3 design's section 8 anticipated.
 *
 * <p><strong>Deliberately not inspected:</strong> the subdomain, because the gateway does not
 * forward the client's {@code Host} and strips forwarded-host headers while no trusted proxies
 * are configured; the request body, which AuthCore's {@code getParameter} would also read for a
 * form POST; and AuthCore's session, which it consults when a request names no tenant and
 * carries a session cookie. A tenant resolved from any of these passes here and is refused by
 * AuthCore's own check. This is defence in depth; AuthCore stays the authority.
 */
public class TenantAuthorizationManager implements ReactiveAuthorizationManager<AuthorizationContext> {

    private static final String TENANT_HEADER = "X-Tenant";
    private static final String TENANT_PARAMETER = "tenant";
    private static final String TENANT_CLAIM = "tenant";

    private final ReactiveAuthorizationManager<AuthorizationContext> delegate;

    public TenantAuthorizationManager(ReactiveAuthorizationManager<AuthorizationContext> delegate) {
        this.delegate = delegate;
    }

    @Override
    public Mono<AuthorizationResult> authorize(Mono<Authentication> authentication, AuthorizationContext context) {
        return delegate.authorize(authentication, context)
                .flatMap(result -> result.isGranted()
                        ? tenantChecked(result, authentication, context.getExchange().getRequest())
                        : Mono.just(result));
    }

    private static Mono<AuthorizationResult> tenantChecked(
            AuthorizationResult granted, Mono<Authentication> authentication, ServerHttpRequest request) {
        return authentication
                .mapNotNull(TenantAuthorizationManager::tenantClaimOf)
                .flatMap(tenant -> namedTenants(request).allMatch(tenant::equals)
                        ? Mono.just(granted)
                        : Mono.<AuthorizationResult>error(new GatewayAccessDeniedException(Reason.TENANT_MISMATCH)))
                .defaultIfEmpty(granted);
    }

    private static String tenantClaimOf(Authentication authentication) {
        return authentication instanceof JwtAuthenticationToken jwt
                ? jwt.getToken().getClaimAsString(TENANT_CLAIM)
                : null;
    }

    /**
     * Query values arrive decoded, as AuthCore's {@code getParameter} sees them. A valueless
     * {@code ?tenant} yields a {@code null}, which equals no tenant and is therefore refused.
     */
    private static Stream<String> namedTenants(ServerHttpRequest request) {
        return Stream.concat(
                request.getHeaders().getOrEmpty(TENANT_HEADER).stream(),
                request.getQueryParams().getOrDefault(TENANT_PARAMETER, List.of()).stream());
    }
}
