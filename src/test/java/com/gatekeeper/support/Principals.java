package com.gatekeeper.support;

import com.gatekeeper.apikey.ApiKeyAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.authority.SimpleGrantedAuthority;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.Arrays;
import java.util.List;

/**
 * Authenticated callers shaped like the ones the gateway's two authentication paths produce —
 * the same token types and the same {@code SCOPE_*} authorities, which is all the rule table
 * reads. (The real JWT converter also adds a {@code FACTOR_BEARER} authority, and the key
 * manager builds a set rather than a list; neither affects a scope check.)
 *
 * <p>Scopes become {@code SCOPE_*} authorities on both kinds of principal. That is what
 * Spring's default {@code JwtGrantedAuthoritiesConverter} derives from a token's {@code scope}
 * claim — GateKeeper configures no converter of its own — and what M3's {@code
 * ApiKeyReactiveAuthenticationManager} derives from a key's introspected scopes.
 */
public final class Principals {

    private Principals() {
    }

    /** A JWT caller with no {@code tenant} claim — the shape of a client-credentials token. */
    public static Authentication jwt(String... scopes) {
        return jwtInTenant(null, scopes);
    }

    /** A JWT caller whose token carries {@code tenant}, as every user token does. */
    public static Authentication jwtInTenant(String tenant, String... scopes) {
        Jwt.Builder token = Jwt.withTokenValue("test-token")
                .header("alg", "RS256")
                .subject("ezzat")
                .claim("scope", List.of(scopes));
        if (tenant != null) {
            token.claim("tenant", tenant);
        }
        return new JwtAuthenticationToken(token.build(), scopeAuthorities(scopes));
    }

    /**
     * A JWT caller holding an authority spelled like a permission ({@code payments:write})
     * rather than a scope ({@code SCOPE_payments:write}). The gateway maps no permissions, so
     * this can only arise from a future converter change — and must never satisfy a scope rule.
     */
    public static Authentication jwtWithBareAuthority(String authority) {
        Jwt token = Jwt.withTokenValue("test-token")
                .header("alg", "RS256")
                .subject("ezzat")
                .build();
        return new JwtAuthenticationToken(token, List.of(new SimpleGrantedAuthority(authority)));
    }

    /** An API-key caller named {@code reporting}, as introspection authenticates one. */
    public static Authentication apiKey(String... scopes) {
        return new ApiKeyAuthenticationToken("reporting", scopeAuthorities(scopes));
    }

    private static List<GrantedAuthority> scopeAuthorities(String... scopes) {
        return Arrays.stream(scopes)
                .<GrantedAuthority>map(scope -> new SimpleGrantedAuthority("SCOPE_" + scope))
                .toList();
    }
}
