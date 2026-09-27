package com.gatekeeper.ratelimit;

/**
 * Why a request was refused 429, with the one {@code detail} string a caller sees for it. Neither
 * names the plan or the identity. The M5 design, section 8.
 */
public enum RateLimitReason {

    RATE_LIMITED("the request rate exceeds the caller's plan"),
    QUOTA_EXCEEDED("the caller's daily quota is used up");

    private final String detail;

    RateLimitReason(String detail) {
        this.detail = detail;
    }

    public String detail() {
        return detail;
    }
}
