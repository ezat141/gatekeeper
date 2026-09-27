package com.gatekeeper.ratelimit;

/**
 * One check's outcome. {@code reason} is null when the request is allowed; {@code
 * retryAfterSeconds} is zero then.
 */
public record Decision(
        boolean allowed,
        RateLimitReason reason,
        long tokensRemaining,
        long quotaRemaining,
        long retryAfterSeconds,
        long quotaResetSeconds) {
}
