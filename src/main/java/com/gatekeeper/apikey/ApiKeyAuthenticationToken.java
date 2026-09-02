package com.gatekeeper.apikey;

import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * Two states, as Spring Security expects: unauthenticated (the raw key, straight from the
 * header) and authenticated (the key's name and its scopes as authorities).
 *
 * <p>No {@code getName()} override: {@link AbstractAuthenticationToken#getName()} already
 * falls back to {@code getPrincipal().toString()} for a plain {@link String} principal —
 * which, once authenticated, is exactly {@code name} — and to {@code ""} before then, since
 * the principal is still null. The manager (Task 10) and the identity-stamp filter (Task 13)
 * only read {@code getName()} after authentication succeeds, so the inherited behavior already
 * gives them the key's name.
 */
public class ApiKeyAuthenticationToken extends AbstractAuthenticationToken {

    private final String rawKey;
    private final String name;

    /** Unauthenticated — what the converter produces. */
    public ApiKeyAuthenticationToken(String rawKey) {
        // The cast disambiguates: Spring Security 7 added a second, protected
        // AbstractAuthenticationToken(AbstractAuthenticationBuilder<?>) constructor, so a bare
        // super(null) no longer compiles — javac cannot tell which overload null targets.
        super((Collection<? extends GrantedAuthority>) null);
        this.rawKey = rawKey;
        this.name = null;
        setAuthenticated(false);
    }

    /** Authenticated — what the manager produces once introspection says the key is good. */
    public ApiKeyAuthenticationToken(String name, Collection<? extends GrantedAuthority> authorities) {
        super(authorities);
        this.rawKey = null;
        this.name = name;
        setAuthenticated(true);
    }

    @Override
    public Object getCredentials() {
        return rawKey;
    }

    @Override
    public Object getPrincipal() {
        return name;
    }
}
