package com.gatekeeper.authz;

import com.gatekeeper.apikey.ApiKeyAuthenticationToken;
import org.junit.jupiter.api.Named;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;
import org.springframework.http.HttpMethod;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import reactor.core.publisher.Mono;

import java.util.stream.Stream;

import static com.gatekeeper.support.Principals.apiKey;
import static com.gatekeeper.support.Principals.jwt;
import static com.gatekeeper.support.Principals.jwtWithBareAuthority;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.HttpMethod.DELETE;
import static org.springframework.http.HttpMethod.GET;
import static org.springframework.http.HttpMethod.HEAD;
import static org.springframework.http.HttpMethod.OPTIONS;
import static org.springframework.http.HttpMethod.PATCH;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.HttpMethod.PUT;

/**
 * Pins the whole table in the M4 design, section 4, row by row. The rules are evaluated in
 * order and the first match decides, so a reordering that changes any outcome fails here.
 *
 * <p>Every refusal asserts its specific {@link Reason}, never merely "denied": a missing scope
 * and a missing rule are different facts, and the caller is told which.
 */
class RouteScopeAuthorizationManagerTest {

    static final String GRANTED = "granted";
    static final String DENIED_WITHOUT_REASON = "denied without a reason";
    static final String COMPLETED_EMPTY = "completed empty";

    private final RouteScopeAuthorizationManager manager = new RouteScopeAuthorizationManager();

    static Stream<Arguments> table() {
        return Stream.of(
                // /actuator/info — authenticated, GET only
                row(GET, "/actuator/info", "jwt[]", jwt(), GRANTED),
                row(GET, "/actuator/info", "key[]", apiKey(), GRANTED),
                row(POST, "/actuator/info", "jwt[]", jwt(), Reason.NO_RULE),

                // /api/accounts/** — authenticated, any method; AuthCore decides the rest
                row(GET, "/api/accounts/me", "jwt[]", jwt(), GRANTED),
                row(GET, "/api/accounts/me", "key[]", apiKey(), GRANTED),
                row(POST, "/api/accounts/ezzat/payments", "jwt[]", jwt(), GRANTED),
                row(DELETE, "/api/accounts/ezzat", "jwt[]", jwt(), GRANTED),

                // /api/machine/** — scope, either credential
                row(GET, "/api/machine/payments", "jwt[read]", jwt("payments:read"), GRANTED),
                row(GET, "/api/machine/payments", "key[read]", apiKey("payments:read"), GRANTED),
                row(GET, "/api/machine/payments", "jwt[write]", jwt("payments:write"), Reason.MISSING_SCOPE),
                row(GET, "/api/machine/payments", "key[]", apiKey(), Reason.MISSING_SCOPE),
                row(POST, "/api/machine/payments", "jwt[write]", jwt("payments:write"), GRANTED),
                row(POST, "/api/machine/payments", "key[write]", apiKey("payments:write"), GRANTED),
                row(POST, "/api/machine/payments", "jwt[read]", jwt("payments:read"), Reason.MISSING_SCOPE),
                row(POST, "/api/machine/payments", "key[read]", apiKey("payments:read"), Reason.MISSING_SCOPE),
                row(PUT, "/api/machine/payments", "jwt[read,write]", jwt("payments:read", "payments:write"), Reason.NO_RULE),
                row(DELETE, "/api/machine/payments", "jwt[read,write]", jwt("payments:read", "payments:write"), Reason.NO_RULE),
                row(HEAD, "/api/machine/payments", "jwt[read,write]", jwt("payments:read", "payments:write"), Reason.NO_RULE),
                row(OPTIONS, "/api/machine/payments", "jwt[read,write]", jwt("payments:read", "payments:write"), Reason.NO_RULE),

                // /api/ledger/** — JWT principal and scope
                row(GET, "/api/ledger/entries", "jwt[read]", jwt("payments:read"), GRANTED),
                row(GET, "/api/ledger/whoami", "jwt[read]", jwt("payments:read"), GRANTED),
                row(GET, "/api/ledger/whoami", "jwt[openid,profile]", jwt("openid", "profile"), Reason.MISSING_SCOPE),
                row(POST, "/api/ledger/entries", "jwt[write]", jwt("payments:write"), GRANTED),
                row(POST, "/api/ledger/entries", "jwt[read]", jwt("payments:read"), Reason.MISSING_SCOPE),
                // The credential type is decided before the scope: a key is refused as a key
                // whether or not it happens to carry the scope.
                row(GET, "/api/ledger/entries", "key[read]", apiKey("payments:read"), Reason.API_KEY_NOT_ACCEPTED),
                row(GET, "/api/ledger/entries", "key[]", apiKey(), Reason.API_KEY_NOT_ACCEPTED),
                row(POST, "/api/ledger/entries", "key[write]", apiKey("payments:write"), Reason.API_KEY_NOT_ACCEPTED),
                row(POST, "/api/ledger/entries", "key[]", apiKey(), Reason.API_KEY_NOT_ACCEPTED),
                row(PUT, "/api/ledger/entries", "jwt[read,write]", jwt("payments:read", "payments:write"), Reason.NO_RULE),
                row(PATCH, "/api/ledger/entries", "jwt[read,write]", jwt("payments:read", "payments:write"), Reason.NO_RULE),
                row(DELETE, "/api/ledger/entries", "jwt[read,write]", jwt("payments:read", "payments:write"), Reason.NO_RULE),
                row(HEAD, "/api/ledger/entries", "jwt[read,write]", jwt("payments:read", "payments:write"), Reason.NO_RULE),
                row(OPTIONS, "/api/ledger/entries", "jwt[read,write]", jwt("payments:read", "payments:write"), Reason.NO_RULE),

                // Everything else — deny by default
                row(GET, "/api/unknown/thing", "jwt[read,write]", jwt("payments:read", "payments:write"), Reason.NO_RULE),
                row(POST, "/api/internal/api-keys/introspect", "key[read]", apiKey("payments:read"), Reason.NO_RULE),
                row(GET, "/actuator/env", "jwt[read,write]", jwt("payments:read", "payments:write"), Reason.NO_RULE),
                row(GET, "/", "jwt[read,write]", jwt("payments:read", "payments:write"), Reason.NO_RULE));
    }

    @ParameterizedTest(name = "{0} {1} as {2} -> {3}")
    @MethodSource("table")
    void decidesEveryRowOfTheTable(HttpMethod method, String path, Authentication caller, Object expected) {
        assertThat(outcome(method, path, Mono.just(caller))).isEqualTo(expected);
    }

    /**
     * The edge checks scope; the downstream checks permission. A token holding a
     * permission-shaped authority but no scope must not pass a scope rule — otherwise a future
     * converter that maps {@code permissions} would silently turn every permission into a
     * grant the client was never given.
     */
    @Test
    void doesNotAcceptAPermissionInPlaceOfAScope() {
        assertThat(outcome(POST, "/api/machine/payments", Mono.just(jwtWithBareAuthority("payments:write"))))
                .isEqualTo(Reason.MISSING_SCOPE);
    }

    /**
     * With no authentication there is no reason to report: ExceptionTranslationWebFilter
     * sends a principal-less exchange to the 401 entry point before any access-denied handler
     * runs. So the answer must be a plain denial, not a reasoned one, on every kind of row.
     */
    @Test
    void deniesAnUnauthenticatedCallerWithoutAReason() {
        assertThat(outcome(GET, "/api/accounts/me", Mono.empty())).isEqualTo(DENIED_WITHOUT_REASON);
        assertThat(outcome(GET, "/api/machine/payments", Mono.empty())).isEqualTo(DENIED_WITHOUT_REASON);
        assertThat(outcome(GET, "/api/unknown/thing", Mono.empty())).isEqualTo(DENIED_WITHOUT_REASON);
    }

    /**
     * Only a genuinely authenticated caller satisfies a rule. An anonymous token reports
     * itself authenticated, and a token straight from a converter does not; neither may pass
     * even the authenticated-only rules, and neither gets a reason — both belong at the 401.
     */
    @Test
    void deniesAnAnonymousOrUnverifiedTokenWithoutAReason() {
        Authentication anonymous = new AnonymousAuthenticationToken(
                "key", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));
        Authentication unverified = new ApiKeyAuthenticationToken("ak_raw_key");

        assertThat(outcome(GET, "/api/accounts/me", Mono.just(anonymous))).isEqualTo(DENIED_WITHOUT_REASON);
        assertThat(outcome(GET, "/api/accounts/me", Mono.just(unverified))).isEqualTo(DENIED_WITHOUT_REASON);
    }

    private Object outcome(HttpMethod method, String path, Mono<Authentication> caller) {
        AuthorizationContext context = new AuthorizationContext(
                MockServerWebExchange.from(MockServerHttpRequest.method(method, path)));
        try {
            AuthorizationResult result = manager.authorize(caller, context).block();
            if (result == null) {
                return COMPLETED_EMPTY;
            }
            return result.isGranted() ? GRANTED : DENIED_WITHOUT_REASON;
        } catch (GatewayAccessDeniedException denied) {
            return denied.reason();
        }
    }

    private static Arguments row(HttpMethod method, String path, String callerName,
                                 Authentication caller, Object expected) {
        return Arguments.of(method, path, Named.of(callerName, caller), expected);
    }
}
