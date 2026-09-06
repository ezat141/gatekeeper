package com.gatekeeper.apikey;

import reactor.core.publisher.Mono;

import java.time.Duration;

/**
 * Narrow on purpose: the authentication manager is unit-tested against a fake
 * implementation, and one integration test proves the Redis one is wired correctly.
 */
public interface ApiKeyCache {

    /** Empty when nothing is cached for this hash. */
    Mono<ApiKeyIntrospection> get(String keyHash);

    Mono<Void> put(String keyHash, ApiKeyIntrospection introspection, Duration ttl);
}
