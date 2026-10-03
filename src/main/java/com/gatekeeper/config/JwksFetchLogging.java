package com.gatekeeper.config;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import reactor.core.publisher.Mono;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Logs AuthCore's key set going away and coming back, once each — not once per request. The M7
 * design, section 14. There is no breaker for the key set, so this flag is what keeps an outage to a
 * few lines: WARN on the first failed fetch after a success (or at startup), DEBUG for further
 * failures, INFO when a fetch succeeds again. A non-2xx answer is a failure too.
 */
final class JwksFetchLogging implements ExchangeFilterFunction {

    private static final Logger log = LoggerFactory.getLogger(JwksFetchLogging.class);

    private final AtomicBoolean failing = new AtomicBoolean();

    @Override
    public Mono<ClientResponse> filter(ClientRequest request, ExchangeFunction next) {
        return next.exchange(request)
                .doOnNext(response -> {
                    if (response.statusCode().is2xxSuccessful()) {
                        answered();
                    } else {
                        failed("HTTP " + response.statusCode().value());
                    }
                })
                .doOnError(error -> failed(error.toString()));
    }

    private void failed(String cause) {
        if (failing.compareAndSet(false, true)) {
            log.warn("AuthCore's key set could not be fetched; bearer tokens that need a key fetch are refused"
                    + " 503 until it answers: {}", cause);
        } else {
            log.debug("AuthCore's key set still not answering: {}", cause);
        }
    }

    private void answered() {
        if (failing.compareAndSet(true, false)) {
            log.info("AuthCore's key set answered again");
        }
    }
}
