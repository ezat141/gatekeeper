package com.gatekeeper.ratelimit;

import com.gatekeeper.apikey.ApiKeyAuthenticationToken;
import com.gatekeeper.ratelimit.RateLimitIdentity.Kind;
import org.junit.jupiter.api.Test;
import org.springframework.security.authentication.AnonymousAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;

import java.util.List;
import java.util.function.UnaryOperator;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatNullPointerException;

/** The M5 design, section 4: tenant where there is one, otherwise the client, or the key. */
class RateLimitIdentityTest {

    @Test
    void aUserTokenCountsAgainstItsTenant() {
        assertThat(RateLimitIdentity.of(jwt(builder -> builder
                .subject("ezzat").audience(List.of("authcore-spa")).claim("tenant", "acme"))))
                .contains(new RateLimitIdentity(Kind.TENANT, "acme"));
    }

    /** Client credentials: no tenant, and aud names the client. */
    @Test
    void aTenantlessTokenCountsAgainstItsClient() {
        assertThat(RateLimitIdentity.of(jwt(builder -> builder
                .subject("authcore-machine").audience(List.of("authcore-machine")))))
                .contains(new RateLimitIdentity(Kind.CLIENT, "authcore-machine"));
    }

    /** aud is the identity when present, even where sub differs. */
    @Test
    void preferTheAudienceOverTheSubject() {
        assertThat(RateLimitIdentity.of(jwt(builder -> builder
                .subject("someone").audience(List.of("the-client")))))
                .contains(new RateLimitIdentity(Kind.CLIENT, "the-client"));
    }

    /** Without aud, sub — which on a client-credentials token is the same client id. */
    @Test
    void fallsBackToTheSubjectWithoutAnAudience() {
        assertThat(RateLimitIdentity.of(jwt(builder -> builder.subject("authcore-machine"))))
                .contains(new RateLimitIdentity(Kind.CLIENT, "authcore-machine"));
    }

    /** A blank tenant is no tenant: every such token would otherwise share one bucket. */
    @Test
    void treatsABlankTenantAsAbsent() {
        assertThat(RateLimitIdentity.of(jwt(builder -> builder
                .subject("c").audience(List.of("c")).claim("tenant", " "))))
                .contains(new RateLimitIdentity(Kind.CLIENT, "c"));
    }

    @Test
    void anApiKeyCountsAgainstItsName() {
        Authentication key = new ApiKeyAuthenticationToken("demo-reporting-job",
                AuthorityUtils.createAuthorityList("SCOPE_payments:read"));

        assertThat(RateLimitIdentity.of(key)).contains(new RateLimitIdentity(Kind.API_KEY, "demo-reporting-job"));
    }

    @Test
    void anythingElseHasNoIdentity() {
        Authentication anonymous = new AnonymousAuthenticationToken(
                "key", "anonymousUser", AuthorityUtils.createAuthorityList("ROLE_ANONYMOUS"));

        assertThat(RateLimitIdentity.of(anonymous)).isEmpty();
        assertThat(RateLimitIdentity.of(null)).isEmpty();
    }

    @Test
    void keysCarryTheKindAndTheName() {
        assertThat(new RateLimitIdentity(Kind.TENANT, "acme").key()).isEqualTo("tenant:acme");
        assertThat(new RateLimitIdentity(Kind.CLIENT, "authcore-machine").key()).isEqualTo("client:authcore-machine");
        assertThat(new RateLimitIdentity(Kind.API_KEY, "demo_job.v2").key()).isEqualTo("apikey:demo_job.v2");
    }

    /** Braces would move the Redis Cluster hash tag; colons and spaces would blur the structure. */
    @Test
    void percentEncodesAnythingOutsideTheSafeSet() {
        assertThat(new RateLimitIdentity(Kind.TENANT, "we{ird}:name one").key())
                .isEqualTo("tenant:we%7Bird%7D%3Aname%20one");
        assertThat(new RateLimitIdentity(Kind.TENANT, "café").key()).isEqualTo("tenant:caf%C3%A9");
    }

    @Test
    void rejectsAnIdentityWithoutAName() {
        assertThatNullPointerException().isThrownBy(() -> new RateLimitIdentity(Kind.TENANT, null));
    }

    @Test
    void rejectsAnIdentityWithoutAKind() {
        assertThatNullPointerException().isThrownBy(() -> new RateLimitIdentity(null, "acme"));
    }

    private static Authentication jwt(UnaryOperator<Jwt.Builder> claims) {
        Jwt token = claims.apply(Jwt.withTokenValue("t").header("alg", "RS256")).build();
        return new JwtAuthenticationToken(token, AuthorityUtils.NO_AUTHORITIES);
    }
}
