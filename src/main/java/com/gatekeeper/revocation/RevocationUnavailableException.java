package com.gatekeeper.revocation;

/**
 * Whether the token is revoked could not be established — Redis erroring, silent, answering
 * nothing, or its breaker open. Answered 503 with {@code Retry-After: 5}. The M6 design, section 4.
 *
 * <p>Deliberately neither a {@code JwtException} nor an {@code AuthenticationException}. {@code
 * JwtReactiveAuthenticationManager} maps only {@code JwtException}, and {@code
 * AuthenticationWebFilter} catches only {@code AuthenticationException} (both verified in the 7.0.6
 * bytecode), so this passes both untouched to {@code GlobalErrorWebExceptionHandler} — the route
 * M3's {@code IntrospectionUnavailableException} takes to its own 503. As either of those types it
 * would become a 401, telling the caller to discard a token that is very likely valid.
 */
public class RevocationUnavailableException extends RuntimeException {

    /** The fixed {@code detail} of the 503, so it can be told from M3's introspection 503. */
    public static final String DETAIL = "REVOCATION_UNAVAILABLE";

    public RevocationUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
