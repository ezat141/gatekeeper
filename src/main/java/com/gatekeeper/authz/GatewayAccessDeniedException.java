package com.gatekeeper.authz;

import org.springframework.security.access.AccessDeniedException;

/**
 * A denial that remembers why.
 *
 * <p>This exists because Spring Security 7.0.6 gives a manager no other way to tell the
 * access-denied handler anything. {@code ReactiveAuthorizationManager.verify()} turns every
 * {@code false} decision into {@code new AccessDeniedException("Access Denied")}, discarding
 * the decision itself, and {@code authorizeExchange} wraps every manager in the {@code final}
 * {@code DelegatingReactiveAuthorizationManager}, so overriding {@code verify()} is never
 * reached. A manager that denies by returning this exception as an error from {@code
 * authorize()} gets its reason through both wrappers unchanged, to {@code
 * ExceptionTranslationWebFilter} and on to the handler. Verified in the bytecode; see the M4
 * design, section 7.
 */
public class GatewayAccessDeniedException extends AccessDeniedException {

    private final Reason reason;

    public GatewayAccessDeniedException(Reason reason) {
        super(reason.detail());
        this.reason = reason;
    }

    public Reason reason() {
        return reason;
    }
}
