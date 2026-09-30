package com.gatekeeper.revocation;

import reactor.core.publisher.Mono;

/** Whether a token has been revoked, by its {@code jti}. The M6 design, section 9. */
public interface RevocationStore {

    /** True if revoked, false if not; an error or an empty answer means the store could not say. */
    Mono<Boolean> isRevoked(String jti);
}