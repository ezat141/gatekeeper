package com.gatekeeper.authz;

import org.springframework.http.HttpMethod;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatcher;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.List;
import java.util.Optional;

import static org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers.anyExchange;
import static org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers.pathMatchers;

/**
 * What each route requires, and nothing else — the tenant check wraps this in {@link
 * TenantAuthorizationManager}. The table is the M4 design, section 4.
 *
 * <p><strong>The edge checks scope, the downstream checks permission.</strong> A scope is what
 * the client application was granted on the user's behalf; a permission is what the user may
 * do. Every rule here reads {@code SCOPE_*} authorities, which a JWT and an API key both carry
 * (M3 made the key's scopes the same shape), so one rule covers both credentials with no
 * branching on mechanism.
 *
 * <p><strong>Rules are evaluated in order; the first match decides.</strong> A rule inserted
 * above an overlapping one silently shadows it, which is why the test pins every row.
 *
 * <p><strong>Deny by default lives in this table</strong>, as its last rule, so that a route
 * added later without a rule fails closed with a reason of its own. Spring's delegating
 * wrapper has a fallback too — a plain {@code false} decision — but the last rule here matches
 * every exchange, so that fallback is never reached.
 *
 * <p><strong>A refusal is an error, not a {@code false} decision.</strong> See {@link
 * GatewayAccessDeniedException} for why that is the only way the reason reaches the handler.
 * The one plain {@code false} this class returns is for a caller with no authentication, who
 * is sent to the 401 entry point before any reason could be rendered.
 */
public class RouteScopeAuthorizationManager implements ReactiveAuthorizationManager<AuthorizationContext> {

    private static final AuthorizationResult GRANTED = new AuthorizationDecision(true);
    private static final AuthorizationResult UNAUTHENTICATED = new AuthorizationDecision(false);

    private static final List<Rule> RULES = List.of(
            new Rule(pathMatchers(HttpMethod.GET, "/actuator/info"), authenticated()),
            // Authenticated only, deliberately. AuthCore's real checks here depend on the
            // request's arguments (@PreAuthorize with #ownerId, hasRole), which a route rule
            // cannot see — and this is why authcore-accounts is a separate route from
            // authcore-machine: a scope rule attaches to the machine route without forcing a
            // hollow one onto this one.
            new Rule(pathMatchers("/api/accounts/**"), authenticated()),
            // Mirrors AuthCore's own URL rules for this route exactly: defence in depth.
            new Rule(pathMatchers(HttpMethod.GET, "/api/machine/**"), scope("payments:read")),
            new Rule(pathMatchers(HttpMethod.POST, "/api/machine/**"), scope("payments:write")),
            // ledger-service is a JWT-only resource server; a key caller could only ever get
            // its 401, so the key is refused here instead.
            new Rule(pathMatchers(HttpMethod.GET, "/api/ledger/**"), jwtWithScope("payments:read")),
            new Rule(pathMatchers(HttpMethod.POST, "/api/ledger/**"), jwtWithScope("payments:write")),
            new Rule(anyExchange(), refuse(Reason.NO_RULE)));

    @Override
    public Mono<AuthorizationResult> authorize(Mono<Authentication> authentication, AuthorizationContext context) {
        return firstRuleMatching(context.getExchange())
                .flatMap(rule -> authentication
                        .filter(Authentication::isAuthenticated)
                        .flatMap(caller -> decide(rule.requirement().refusal(caller)))
                        .switchIfEmpty(Mono.just(UNAUTHENTICATED)));
    }

    private static Mono<Rule> firstRuleMatching(ServerWebExchange exchange) {
        return Flux.fromIterable(RULES)
                .concatMap(rule -> rule.matcher().matches(exchange)
                        .filter(ServerWebExchangeMatcher.MatchResult::isMatch)
                        .map(match -> rule))
                .next();
    }

    private static Mono<AuthorizationResult> decide(Optional<Reason> refusal) {
        return refusal
                .<Mono<AuthorizationResult>>map(reason -> Mono.error(new GatewayAccessDeniedException(reason)))
                .orElseGet(() -> Mono.just(GRANTED));
    }

    private static Requirement authenticated() {
        return caller -> Optional.empty();
    }

    private static Requirement scope(String scope) {
        String authority = "SCOPE_" + scope;
        return caller -> caller.getAuthorities().stream()
                .anyMatch(granted -> authority.equals(granted.getAuthority()))
                ? Optional.empty()
                : Optional.of(Reason.MISSING_SCOPE);
    }

    /**
     * The credential type is checked before the scope. This chain authenticates exactly two
     * kinds of caller — a {@link JwtAuthenticationToken} or an API key — so anything that is
     * not a JWT here is a key.
     */
    private static Requirement jwtWithScope(String scope) {
        Requirement scopeRequirement = scope(scope);
        return caller -> caller instanceof JwtAuthenticationToken
                ? scopeRequirement.refusal(caller)
                : Optional.of(Reason.API_KEY_NOT_ACCEPTED);
    }

    private static Requirement refuse(Reason reason) {
        return caller -> Optional.of(reason);
    }

    private record Rule(ServerWebExchangeMatcher matcher, Requirement requirement) {
    }

    @FunctionalInterface
    private interface Requirement {
        /** Empty to grant; otherwise why the caller is refused. */
        Optional<Reason> refusal(Authentication caller);
    }
}
