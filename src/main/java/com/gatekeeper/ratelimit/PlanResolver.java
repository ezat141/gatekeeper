package com.gatekeeper.ratelimit;

/**
 * Which plan a caller is on. An interface so that a later milestone can move assignments out of
 * configuration — into Redis behind a management API — without touching the limiter.
 */
public interface PlanResolver {

    Plan resolve(RateLimitIdentity identity);
}
