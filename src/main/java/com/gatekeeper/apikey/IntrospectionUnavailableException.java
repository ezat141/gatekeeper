package com.gatekeeper.apikey;

/**
 * Introspection could not be completed — AuthCore unreachable, erroring, too slow, or
 * answering with something unusable.
 *
 * <p>Deliberately not an {@code AuthenticationException}. That distinction is what produces
 * a 503 instead of a 401: {@code AuthenticationWebFilter} catches only
 * {@code AuthenticationException} and converts it into the entry point's 401, so anything
 * else propagates to {@code GlobalErrorWebExceptionHandler} instead. The caller's key may
 * be perfectly valid; answering 401 would send them to rotate a working credential.
 */
public class IntrospectionUnavailableException extends RuntimeException {

    public IntrospectionUnavailableException(String message, Throwable cause) {
        super(message, cause);
    }
}
