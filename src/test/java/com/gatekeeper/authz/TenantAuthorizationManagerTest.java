package com.gatekeeper.authz;

import org.junit.jupiter.api.Test;
import org.springframework.http.HttpMethod;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.authorization.AuthorizationDecision;
import org.springframework.security.authorization.AuthorizationResult;
import org.springframework.security.authorization.ReactiveAuthorizationManager;
import org.springframework.security.core.Authentication;
import org.springframework.security.web.server.authorization.AuthorizationContext;
import reactor.core.publisher.Mono;

import java.net.URI;

import static com.gatekeeper.support.Principals.apiKey;
import static com.gatekeeper.support.Principals.jwt;
import static com.gatekeeper.support.Principals.jwtInTenant;
import static org.assertj.core.api.Assertions.assertThat;

/**
 * The M4 design, section 5: every tenant a request names must equal the token's own, a
 * request naming none passes, and a caller whose credential carries no tenant is never
 * checked.
 *
 * <p>The delegate here stands in for the rule table, so these tests are about the tenant
 * check alone.
 */
class TenantAuthorizationManagerTest {

    static final String GRANTED = "granted";
    static final String DENIED_WITHOUT_REASON = "denied without a reason";
    static final String COMPLETED_EMPTY = "completed empty";

    static final ReactiveAuthorizationManager<AuthorizationContext> GRANTING =
            (authentication, context) -> Mono.just(new AuthorizationDecision(true));

    private final TenantAuthorizationManager manager = new TenantAuthorizationManager(GRANTING);

    private final Authentication acmeUser = jwtInTenant("acme", "payments:read");

    // --- A request that names no tenant -------------------------------------------------

    @Test
    void passesARequestThatNamesNoTenant() {
        assertThat(outcome(acmeUser, request("/api/accounts/me"))).isEqualTo(GRANTED);
    }

    // --- The header ----------------------------------------------------------------------

    @Test
    void passesAHeaderNamingTheTokensOwnTenant() {
        assertThat(outcome(acmeUser, request("/api/accounts/me").header("X-Tenant", "acme")))
                .isEqualTo(GRANTED);
    }

    @Test
    void refusesAHeaderNamingAnotherTenant() {
        assertThat(outcome(acmeUser, request("/api/accounts/me").header("X-Tenant", "default")))
                .isEqualTo(Reason.TENANT_MISMATCH);
    }

    /** Header names are case-insensitive in HTTP; a check keyed on one spelling is bypassed. */
    @Test
    void readsTheHeaderWhateverItsNameCasing() {
        assertThat(outcome(acmeUser, request("/api/accounts/me").header("x-tenant", "default")))
                .isEqualTo(Reason.TENANT_MISMATCH);
    }

    /** Every value must match, not merely one of them. */
    @Test
    void refusesTwoHeadersWhenEitherNamesAnotherTenant() {
        assertThat(outcome(acmeUser, request("/api/accounts/me").header("X-Tenant", "acme", "default")))
                .isEqualTo(Reason.TENANT_MISMATCH);
    }

    /** Values are compared raw, never split, so a list cannot smuggle a second tenant past. */
    @Test
    void refusesACommaSeparatedValue() {
        assertThat(outcome(acmeUser, request("/api/accounts/me").header("X-Tenant", "acme,default")))
                .isEqualTo(Reason.TENANT_MISMATCH);
    }

    /** A blank value is a named tenant, and it is not the token's. Stricter than AuthCore. */
    @Test
    void refusesABlankValue() {
        assertThat(outcome(acmeUser, request("/api/accounts/me").header("X-Tenant", "")))
                .isEqualTo(Reason.TENANT_MISMATCH);
    }

    /** AuthCore compares with equals; so does the gateway. */
    @Test
    void comparesCaseSensitively() {
        assertThat(outcome(acmeUser, request("/api/accounts/me").header("X-Tenant", "ACME")))
                .isEqualTo(Reason.TENANT_MISMATCH);
    }

    // --- The query parameter -------------------------------------------------------------

    @Test
    void refusesAQueryParameterNamingAnotherTenant() {
        assertThat(outcome(acmeUser, request("/api/accounts/me?tenant=default")))
                .isEqualTo(Reason.TENANT_MISMATCH);
    }

    /**
     * {@code ac%6De} decodes to {@code acme}. Passing proves the check reads decoded values,
     * as AuthCore's {@code getParameter} does; comparing the raw text would refuse it.
     */
    @Test
    void comparesTheDecodedQueryValue() {
        assertThat(outcome(acmeUser, request("/api/accounts/me?tenant=ac%6De"))).isEqualTo(GRANTED);
    }

    /** {@code ?tenant} with no value still names a tenant — an empty one. */
    @Test
    void refusesAValuelessQueryParameter() {
        assertThat(outcome(acmeUser, request("/api/accounts/me?tenant")))
                .isEqualTo(Reason.TENANT_MISMATCH);
    }

    @Test
    void refusesWhenTheHeaderMatchesButTheQueryDoesNot() {
        assertThat(outcome(acmeUser, request("/api/accounts/me?tenant=default").header("X-Tenant", "acme")))
                .isEqualTo(Reason.TENANT_MISMATCH);
    }

    /**
     * AuthCore's {@code getParameter} reads only the first value. The gateway reads every
     * one, so neither order can slip a second tenant past.
     */
    @Test
    void refusesARepeatedQueryParameterWhicheverValueComesFirst() {
        assertThat(outcome(acmeUser, request("/api/accounts/me?tenant=acme&tenant=default")))
                .isEqualTo(Reason.TENANT_MISMATCH);
        assertThat(outcome(acmeUser, request("/api/accounts/me?tenant=default&tenant=acme")))
                .isEqualTo(Reason.TENANT_MISMATCH);
    }

    /** Parameter names are decoded too, on both sides: {@code %74enant} is {@code tenant}. */
    @Test
    void readsAnEncodedParameterName() {
        assertThat(outcome(acmeUser, request("/api/accounts/me?%74enant=default")))
                .isEqualTo(Reason.TENANT_MISMATCH);
    }

    @Test
    void passesWhenTheHeaderAndTheQueryBothNameTheTokensTenant() {
        assertThat(outcome(acmeUser, request("/api/accounts/me?tenant=acme").header("X-Tenant", "acme")))
                .isEqualTo(GRANTED);
    }

    // --- Callers with no tenant ----------------------------------------------------------

    /**
     * A client-credentials token carries no tenant claim. AuthCore does not tenant-check it,
     * and neither does the gateway — the one rule for tenant-less principals that the M3
     * design's section 8 anticipated.
     */
    @Test
    void neverChecksATokenWithNoTenantClaim() {
        assertThat(outcome(jwt("payments:read"), request("/api/machine/payments?tenant=default")
                .header("X-Tenant", "acme"))).isEqualTo(GRANTED);
    }

    /** API keys are tenant-less by construction — the same rule, not a special case. */
    @Test
    void neverChecksAnApiKey() {
        assertThat(outcome(apiKey("payments:read"), request("/api/machine/payments")
                .header("X-Tenant", "default"))).isEqualTo(GRANTED);
    }

    // --- The rule table decides first ----------------------------------------------------

    /** A missing scope must read as a missing scope, never masked by a tenant message. */
    @Test
    void reportsTheTablesReasonWhenBothWouldRefuse() {
        TenantAuthorizationManager refusingScope = new TenantAuthorizationManager(
                (authentication, context) -> Mono.error(new GatewayAccessDeniedException(Reason.MISSING_SCOPE)));

        assertThat(outcome(refusingScope, acmeUser, request("/api/accounts/me").header("X-Tenant", "default")))
                .isEqualTo(Reason.MISSING_SCOPE);
    }

    /** A plain denial from the table — an unauthenticated caller — passes through unchanged. */
    @Test
    void passesAPlainDenialThroughUnchanged() {
        TenantAuthorizationManager denying = new TenantAuthorizationManager(
                (authentication, context) -> Mono.just(new AuthorizationDecision(false)));

        assertThat(outcome(denying, acmeUser, request("/api/accounts/me").header("X-Tenant", "default")))
                .isEqualTo(DENIED_WITHOUT_REASON);
    }

    // --- Helpers -------------------------------------------------------------------------

    /** Built from a URI so a percent-escape reaches the request exactly as written. */
    private static MockServerHttpRequest.BaseBuilder<?> request(String uri) {
        return MockServerHttpRequest.method(HttpMethod.GET, URI.create(uri));
    }

    private Object outcome(Authentication caller, MockServerHttpRequest.BaseBuilder<?> request) {
        return outcome(manager, caller, request);
    }

    private static Object outcome(TenantAuthorizationManager manager, Authentication caller,
                                  MockServerHttpRequest.BaseBuilder<?> request) {
        AuthorizationContext context = new AuthorizationContext(MockServerWebExchange.from(request));
        try {
            AuthorizationResult result = manager.authorize(Mono.just(caller), context).block();
            return result == null ? COMPLETED_EMPTY : result.isGranted() ? GRANTED : DENIED_WITHOUT_REASON;
        } catch (GatewayAccessDeniedException denied) {
            return denied.reason();
        }
    }
}
