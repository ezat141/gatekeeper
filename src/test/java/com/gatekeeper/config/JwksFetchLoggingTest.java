package com.gatekeeper.config;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.http.HttpMethod;
import org.springframework.http.HttpStatus;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import reactor.core.publisher.Mono;

import java.net.ConnectException;
import java.net.URI;

import static org.assertj.core.api.Assertions.assertThat;

/** One WARN when the key set stops answering, one INFO when it answers again. The M7 design, section 14. */
@ExtendWith(OutputCaptureExtension.class)
class JwksFetchLoggingTest {

    static final ClientRequest REQUEST = ClientRequest.create(HttpMethod.GET, URI.create("http://authcore/oauth2/jwks")).build();

    @Test
    void warnsOnceThenInformsOnRecovery(CapturedOutput output) {
        JwksFetchLogging logging = new JwksFetchLogging();
        ExchangeFunction refused = request -> Mono.error(new ConnectException("Connection refused"));
        ExchangeFunction ok = request -> Mono.just(ClientResponse.create(HttpStatus.OK).build());

        for (int i = 0; i < 3; i++) {
            logging.filter(REQUEST, refused).onErrorResume(e -> Mono.empty()).block();
        }
        logging.filter(REQUEST, ok).block();
        logging.filter(REQUEST, ok).block();

        assertThat(count(output.getOut(), "AuthCore's key set could not be fetched")).isEqualTo(1);
        assertThat(count(output.getOut(), "AuthCore's key set answered again")).isEqualTo(1);
    }

    @Test
    void aNonSuccessStatusIsAFailure(CapturedOutput output) {
        JwksFetchLogging logging = new JwksFetchLogging();

        logging.filter(REQUEST, request -> Mono.just(ClientResponse.create(HttpStatus.BAD_GATEWAY).build())).block();

        assertThat(output.getOut()).contains("AuthCore's key set could not be fetched");
    }

    private static int count(String text, String needle) {
        int count = 0;
        for (int i = text.indexOf(needle); i >= 0; i = text.indexOf(needle, i + 1)) {
            count++;
        }
        return count;
    }
}
