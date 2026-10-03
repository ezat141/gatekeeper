package com.gatekeeper.config;

import com.nimbusds.jose.jwk.JWKSet;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFilterFunction;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import reactor.core.publisher.Flux;
import reactor.core.publisher.Mono;

import java.util.concurrent.atomic.AtomicBoolean;

/**
 * Logs AuthCore's key set going away and coming back, once each — not once per request. The M7
 * design, sections 4 and 14. There is no breaker for the key set, so this flag is what keeps an
 * outage to a few lines: WARN on the first failed fetch after a success (or at startup), DEBUG for
 * further failures, INFO when a fetch succeeds again.
 *
 * <p>A fetch is judged by what the decoder will do with it, so the body counts, not just the status.
 * A non-2xx answer is a failure. A 2xx answer is read in full and parsed as a key set, the way the
 * decoder will parse it: a login page, malformed JSON or a body that stalls is a failure too, since
 * the decoder refuses all of those with "Could not obtain the keys". Only a body that parses is an
 * answer. The decoder is always handed the same body it would have got: the body is read here once
 * and handed on rebuilt, whatever the verdict. Key-set fetches are rare, so parsing twice costs
 * nothing.
 */
final class JwksFetchLogging implements ExchangeFilterFunction {

    private static final Logger log = LoggerFactory.getLogger(JwksFetchLogging.class);

    private final AtomicBoolean failing = new AtomicBoolean();

    @Override
    public Mono<ClientResponse> filter(ClientRequest request, ExchangeFunction next) {
        return next.exchange(request)
                .flatMap(this::judge)
                .doOnError(error -> failed(error.toString()));
    }

    private Mono<ClientResponse> judge(ClientResponse response) {
        if (!response.statusCode().is2xxSuccessful()) {
            failed("HTTP " + response.statusCode().value());
            return Mono.just(response);
        }
        return response.bodyToMono(String.class)
                .map(body -> {
                    judgeBody(body);
                    return response.mutate().body(body).build();
                })
                .switchIfEmpty(Mono.fromSupplier(() -> {
                    failed("empty body");
                    return response.mutate().body(Flux.empty()).build();
                }));
    }

    private void judgeBody(String body) {
        try {
            JWKSet.parse(body);
        } catch (Exception notAKeySet) {
            failed("not a key set: " + notAKeySet.getMessage());
            return;
        }
        answered();
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
