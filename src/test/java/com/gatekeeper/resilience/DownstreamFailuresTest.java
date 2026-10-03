package com.gatekeeper.resilience;

import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.factory.SpringCloudCircuitBreakerFilterFactory;
import org.springframework.cloud.gateway.support.TimeoutException;
import org.springframework.http.HttpStatus;
import org.springframework.web.server.ResponseStatusException;

import java.net.ConnectException;
import java.net.SocketTimeoutException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.mock;

/** What counts against a downstream, and what does not. The M7 design, sections 6 to 8. */
class DownstreamFailuresTest {

    @Test
    void aGatewayTimeoutCausedByTheGatewaysTimeoutIsATimeout() {
        Throwable timeout = new ResponseStatusException(HttpStatus.GATEWAY_TIMEOUT, null, new TimeoutException());

        assertThat(DownstreamFailures.isTimeout(timeout)).isTrue();
        assertThat(DownstreamFailures.isAvailabilityFailure(timeout)).isTrue();
    }

    @Test
    void aGatewayTimeoutRaisedForAnotherReasonIsNotATimeout() {
        assertThat(DownstreamFailures.isTimeout(new ResponseStatusException(HttpStatus.GATEWAY_TIMEOUT))).isFalse();
        assertThat(DownstreamFailures.isTimeout(
                new ResponseStatusException(HttpStatus.BAD_GATEWAY, null, new TimeoutException()))).isFalse();
        assertThat(DownstreamFailures.isTimeout(new SocketTimeoutException())).isFalse();
    }

    @Test
    void aConnectErrorIsOne() {
        assertThat(DownstreamFailures.isConnectError(new ConnectException("refused"))).isTrue();
        assertThat(DownstreamFailures.isAvailabilityFailure(new ConnectException("refused"))).isTrue();
        assertThat(DownstreamFailures.isConnectError(new java.io.IOException("reset"))).isFalse();
    }

    @Test
    void aCountedStatusIsOne() {
        // The exception is a non-static inner class of the filter factory; a mock supplies the instance.
        SpringCloudCircuitBreakerFilterFactory factory = mock(SpringCloudCircuitBreakerFilterFactory.class);
        Throwable counted = factory.new CircuitBreakerStatusCodeException(HttpStatus.BAD_GATEWAY);

        assertThat(DownstreamFailures.isCountedStatus(counted)).isTrue();
        assertThat(DownstreamFailures.isAvailabilityFailure(counted)).isTrue();
        assertThat(DownstreamFailures.isCountedStatus(new ResponseStatusException(HttpStatus.BAD_GATEWAY))).isFalse();
    }

    @Test
    void aCallersOwnFailureIsNone() {
        Throwable rejectedHeader = new IllegalArgumentException("Validation failed for header 'x'");

        assertThat(DownstreamFailures.isTimeout(rejectedHeader)).isFalse();
        assertThat(DownstreamFailures.isConnectError(rejectedHeader)).isFalse();
        assertThat(DownstreamFailures.isCountedStatus(rejectedHeader)).isFalse();
        assertThat(DownstreamFailures.isAvailabilityFailure(rejectedHeader)).isFalse();
        assertThat(DownstreamFailures.isAvailabilityFailure(new IllegalStateException("anything"))).isFalse();
    }
}
