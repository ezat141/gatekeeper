package com.gatekeeper.ratelimit;

import reactor.core.publisher.Mono;

/** Checks, and on success spends, one request of a caller's allowance. */
@FunctionalInterface
public interface RateLimitStore {

    Mono<Decision> check(RateLimitIdentity identity, Plan plan);
}
