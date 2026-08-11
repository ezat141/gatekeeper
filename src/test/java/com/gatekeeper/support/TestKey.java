package com.gatekeeper.support;

import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.jwk.JWK;
import com.nimbusds.jose.jwk.JWKSet;
import com.nimbusds.jose.jwk.RSAKey;
import com.nimbusds.jose.jwk.gen.RSAKeyGenerator;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import java.time.Instant;
import java.util.Arrays;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

/** Mints RS256 tokens and renders JWKS documents, standing in for AuthCore in tests. */
public final class TestKey {

    private final RSAKey key;

    private TestKey(RSAKey key) {
        this.key = key;
    }

    public static TestKey generate(String keyId) {
        try {
            return new TestKey(new RSAKeyGenerator(2048).keyID(keyId).generate());
        } catch (Exception ex) {
            throw new IllegalStateException("could not generate a test key", ex);
        }
    }

    /** The public half of every supplied key, as AuthCore's /oauth2/jwks would serve it. */
    public static String jwksDocument(TestKey... keys) {
        List<JWK> jwks = Arrays.stream(keys).map(k -> (JWK) k.key).toList();
        return new JWKSet(jwks).toPublicJWKSet().toString();
    }

    public String mint(String issuer, String subject, Instant expiresAt, Map<String, Object> claims) {
        return mintAdvertisingKeyId(this.key.getKeyID(), issuer, subject, expiresAt, claims);
    }

    /**
     * Signs with this key but writes a different {@code kid} into the header. Task 10 needs
     * this to separate a bad signature over a known key from an entirely unknown key id —
     * they fail on different code paths.
     */
    public String mintAdvertisingKeyId(String keyId, String issuer, String subject,
                                       Instant expiresAt, Map<String, Object> claims) {
        try {
            JWTClaimsSet.Builder builder = new JWTClaimsSet.Builder()
                    .issuer(issuer)
                    .subject(subject)
                    .jwtID(UUID.randomUUID().toString())
                    .issueTime(Date.from(Instant.now().minusSeconds(30)))
                    .expirationTime(Date.from(expiresAt));
            claims.forEach(builder::claim);

            SignedJWT jwt = new SignedJWT(
                    new JWSHeader.Builder(JWSAlgorithm.RS256)
                            .keyID(keyId)
                            .type(JOSEObjectType.JWT)
                            .build(),
                    builder.build());
            jwt.sign(new RSASSASigner(this.key));
            return jwt.serialize();
        } catch (Exception ex) {
            throw new IllegalStateException("could not mint a test token", ex);
        }
    }
}
