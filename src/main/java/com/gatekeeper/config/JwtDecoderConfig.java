package com.gatekeeper.config;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.jwt.JwtValidators;
import org.springframework.security.oauth2.jwt.NimbusReactiveJwtDecoder;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;

/**
 * Trust is anchored on AuthCore's JWKS rather than a copied public key, which is what lets
 * AuthCore rotate its signing key without redeploying the gateway.
 *
 * <p>The issuer is pinned explicitly. AuthCore derives its issuer from the request host, so
 * a token fetched at 127.0.0.1:8080 carries a different {@code iss} than one fetched at
 * localhost:8080 and is refused here. Failing closed is correct; the README records the
 * cause so the failure is diagnosable rather than mysterious.
 */
@Configuration
public class JwtDecoderConfig {

    @Bean
    public ReactiveJwtDecoder jwtDecoder(
            @Value("${gatekeeper.auth.jwk-set-uri}") String jwkSetUri,
            @Value("${gatekeeper.auth.issuer}") String issuer) {

        NimbusReactiveJwtDecoder decoder = NimbusReactiveJwtDecoder.withJwkSetUri(jwkSetUri).build();
        decoder.setJwtValidator(JwtValidators.createDefaultWithIssuer(issuer));
        return decoder;
    }
}
