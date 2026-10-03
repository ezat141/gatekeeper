package com.gatekeeper.resilience;

import org.springframework.cloud.gateway.filter.factory.SpringCloudCircuitBreakerFilterFactory.CircuitBreakerStatusCodeException;
import org.springframework.cloud.gateway.support.TimeoutException;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.net.ConnectException;

/**
 * What a downstream's failure looks like when it reaches the gateway: the single source of truth for
 * what the circuit breakers count and what {@code GlobalErrorWebExceptionHandler} maps. The M7 design,
 * sections 6 to 8.
 *
 * <p>Three things are availability failures, and nothing else is: a connect error (a refused connection
 * or a connect timeout), a response timeout, and a downstream 502, 503 or 504 (which the gateway's
 * breaker filter raises as a {@link CircuitBreakerStatusCodeException}). A downstream 500 is the
 * downstream's own answer, and an exception that comes from the caller's request, such as a claim Netty
 * refuses to forward, says nothing about the downstream; if either counted, one caller could cut a
 * downstream off for everyone.
 */
public final class DownstreamFailures {

    private DownstreamFailures() {
    }

    /**
     * Spring Cloud Gateway's routing filter, when a downstream exceeds the route's response timeout:
     * a 504 {@code ResponseStatusException} caused by the gateway's own {@code TimeoutException}
     * (verified in 5.0.2). Matched on both, so a 504 raised for another reason is not relabelled.
     */
    public static boolean isTimeout(Throwable error) {
        return error instanceof ResponseStatusException status
                && status.getStatusCode().value() == HttpStatus.GATEWAY_TIMEOUT.value()
                && status.getCause() instanceof TimeoutException;
    }

    /**
     * A bare {@link ConnectException} match, which is safe: it covers a refused connection (Netty's
     * {@code AnnotatedConnectException}) and a connect timeout (Netty's {@code ConnectTimeoutException}),
     * both subclasses, and every other remote call in the gateway wraps its connect errors in its own
     * exception before they could reach the routing filter.
     */
    public static boolean isConnectError(Throwable error) {
        return error instanceof ConnectException;
    }

    /** The downstream answered 502, 503 or 504, as the breaker filter's {@code statusCodes} lists them. */
    public static boolean isCountedStatus(Throwable error) {
        return error instanceof CircuitBreakerStatusCodeException;
    }

    /** True for exactly what the breaker counts as a failure. */
    public static boolean isAvailabilityFailure(Throwable error) {
        return isTimeout(error) || isConnectError(error) || isCountedStatus(error);
    }
}
