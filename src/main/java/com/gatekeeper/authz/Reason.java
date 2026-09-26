package com.gatekeeper.authz;

/**
 * Why the gateway refused a request. Each reason carries the one {@code detail} string a
 * caller sees for it, so the reason and its wire text cannot drift apart — see the M4
 * design, section 7.
 *
 * <p>Every string is authored here. None of them ever comes from an exception message.
 */
public enum Reason {

    MISSING_SCOPE("the credential does not carry the scope this route requires"),
    API_KEY_NOT_ACCEPTED("this route does not accept API keys"),
    TENANT_MISMATCH("the request names a tenant other than the token's"),
    NO_RULE("no rule permits this method and path");

    private final String detail;

    Reason(String detail) {
        this.detail = detail;
    }

    public String detail() {
        return detail;
    }
}
