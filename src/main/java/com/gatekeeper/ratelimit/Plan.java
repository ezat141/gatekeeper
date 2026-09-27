package com.gatekeeper.ratelimit;

/** A plan's name and the allowance it grants every caller assigned to it. */
public record Plan(String name, int requestsPerSecond, long burst, long dailyQuota) {
}
