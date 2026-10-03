package com.gatekeeper.config;

import com.gatekeeper.redis.RedisCircuitBreaker;
import com.gatekeeper.resilience.ResilienceProperties;
import com.gatekeeper.revocation.RevocationCheckingJwtDecoder;
import com.gatekeeper.revocation.RevocationProperties;
import com.gatekeeper.revocation.RevocationStore;
import io.netty.channel.ChannelOption;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.client.reactive.ReactorClientHttpConnector;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.netty.http.client.HttpClient;

import java.time.Duration;

/**
 * Trust is anchored on AuthCore's JWKS rather than a copied public key, which is what lets
 * AuthCore rotate its signing key without redeploying the gateway.
 *
 * <p>The issuer is pinned explicitly. AuthCore derives its issuer from the request host, so
 * a token fetched at 127.0.0.1:8080 carries a different {@code iss} than one fetched at
 * localhost:8080 and is refused here. Failing closed is correct; the README records the
 * cause so the failure is diagnosable rather than mysterious.
 *
 * <p>Since M6 the Nimbus decoder is wrapped: a token that passes it is then checked against
 * AuthCore's revocation deny-list — see {@link RevocationCheckingJwtDecoder} and the M6 design.
 *
 * <p>Since M7 the key-set fetch has its own timeouts — see {@link #jwksWebClient}.
 */
@Configuration
public class JwtDecoderConfig {

    @Bean
    public ReactiveJwtDecoder jwtDecoder(
            @Value("${gatekeeper.auth.jwk-set-uri}") String jwkSetUri,
            @Value("${gatekeeper.auth.issuer}") String issuer,
            RevocationStore revocations,
            @Qualifier("revocationBreaker") RedisCircuitBreaker revocationBreaker,
            RevocationProperties revocation,
            ResilienceProperties resilience) {

        NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder.withJwkSetUri(jwkSetUri)
                .webClient(jwksWebClient(resilience.jwksTimeout()))
                .build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuer));
        return new RevocationCheckingJwtDecoder(decoder, revocations, revocationBreaker, revocation.redisTimeout());
    }

    /**
     * The key-set fetch with a connect and a response timeout. The M7 design, section 4. Without them
     * an AuthCore that accepted the connection and never answered hung the request; a connect timeout is
     * needed as well, or a host that never accepts would wait for the operating system's own, which can
     * exceed 20 s. Any failure — refused, silent, non-2xx — reaches {@code GlobalErrorWebExceptionHandler}
     * as the decoder's "Could not obtain the keys" (verified in Spring Security 7.0.6), answered 503.
     */
    static WebClient jwksWebClient(Duration timeout) {
        HttpClient http = HttpClient.create()
                .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, Math.toIntExact(timeout.toMillis()))
                .responseTimeout(timeout);
        return WebClient.builder()
                .clientConnector(new ReactorClientHttpConnector(http))
                .filter(new JwksFetchLogging())
                .build();
    }
}
