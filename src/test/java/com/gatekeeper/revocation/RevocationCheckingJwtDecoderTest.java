package com.gatekeeper.revocation;

import com.gatekeeper.redis.RedisCircuitBreaker;
import com.gatekeeper.redis.RedisCircuitBreaker.Permit;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.jwt.BadJwtException;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import reactor.core.publisher.Mono;
import reactor.core.publisher.Sinks;
import reactor.test.StepVerifier;

import java.time.Duration;
import java.util.concurrent.TimeoutException;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicLong;
import java.util.concurrent.atomic.AtomicReference;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * The check, with a fake inner decoder, a fake store and a breaker on a fake clock. The M6 design,
 * sections 3, 4, 6 and 7.
 */
class RevocationCheckingJwtDecoderTest {

    static final Duration TIMEOUT = Duration.ofMillis(100);
    static final IllegalStateException DOWN = new IllegalStateException("redis down");

    final AtomicInteger storeCalls = new AtomicInteger();
    final AtomicReference<String> askedAbout = new AtomicReference<>();
    final AtomicReference<Mono<Boolean>> answer = new AtomicReference<>(Mono.just(false));
    final AtomicLong now = new AtomicLong(1_000_000_000L);
    final RedisCircuitBreaker breaker = new RedisCircuitBreaker("Revocation check", "refusing",
            RedisCircuitBreaker.OPEN_FOR, RedisCircuitBreaker.FAILURES_TO_OPEN, now::get);

    final RevocationStore store = jti -> {
        storeCalls.incrementAndGet();
        askedAbout.set(jti);
        return answer.get();
    };

    @Test
    void passesATokenThatIsNotRevoked() {
        Jwt jwt = jwt("j-1");

        StepVerifier.create(decoder(jwt).decode("t")).expectNext(jwt).verifyComplete();

        assertThat(storeCalls).hasValue(1);
    }

    @Test
    void asksAboutTheTokensOwnJti() {
        decoder(jwt("j-42")).decode("t").block();

        assertThat(askedAbout).hasValue("j-42");
    }

    @Test
    void refusesARevokedTokenAsABadToken() {
        answer.set(Mono.just(true));

        StepVerifier.create(decoder(jwt("j-1")).decode("t"))
                .expectErrorSatisfies(error -> assertThat(error)
                        .isInstanceOf(BadJwtException.class)
                        .hasMessageContaining("revoked"))
                .verify();
    }

    /** A token that cannot be revoked does not pass a gateway that enforces revocation (section 6). */
    @Test
    void refusesATokenWithNoJtiWithoutAskingTheStore() {
        StepVerifier.create(decoder(jwt(null)).decode("t"))
                .expectError(BadJwtException.class)
                .verify();

        assertThat(storeCalls).hasValue(0);
    }

    /** Blank would check the key "authcore:revoked:jti:", which nobody writes. */
    @Test
    void refusesABlankJtiWithoutAskingTheStore() {
        StepVerifier.create(decoder(jwt(" ")).decode("t"))
                .expectError(BadJwtException.class)
                .verify();

        assertThat(storeCalls).hasValue(0);
    }

    /** Forged or expired tokens must not reach Redis: an outsider picks their jti freely (section 3). */
    @Test
    void aTokenTheInnerDecoderRejectsNeverReachesTheStore() {
        ReactiveJwtDecoder rejecting = token -> Mono.error(new BadJwtException("bad signature"));

        StepVerifier.create(decoder(rejecting).decode("t"))
                .expectErrorMessage("bad signature")
                .verify();

        assertThat(storeCalls).hasValue(0);
    }

    @Test
    void refusesWhenTheStoreFails() {
        answer.set(Mono.error(DOWN));

        StepVerifier.create(decoder(jwt("j-1")).decode("t"))
                .expectErrorSatisfies(error -> assertThat(error)
                        .isInstanceOf(RevocationUnavailableException.class)
                        .hasCause(DOWN))
                .verify();
    }

    @Test
    void refusesWhenTheStoreAnswersNothing() {
        answer.set(Mono.empty());

        StepVerifier.create(decoder(jwt("j-1")).decode("t"))
                .expectErrorSatisfies(error -> assertThat(error)
                        .isInstanceOf(RevocationUnavailableException.class)
                        .hasCauseInstanceOf(IllegalStateException.class))
                .verify();
    }

    @Test
    void refusesWhenTheStoreDoesNotAnswerInTime() {
        answer.set(Mono.never());

        StepVerifier.create(decoder(jwt("j-1")).decode("t"))
                .expectErrorSatisfies(error -> assertThat(error)
                        .isInstanceOf(RevocationUnavailableException.class)
                        .hasCauseInstanceOf(TimeoutException.class))
                .verify(Duration.ofSeconds(2));
    }

    /**
     * The handoff's warning: copying the limiter's handling of an open breaker would skip the check,
     * failing open. Here an open breaker refuses, and does not ask Redis.
     */
    @Test
    void anOpenBreakerRefusesWithoutAskingTheStore() {
        answer.set(Mono.error(DOWN));
        RevocationCheckingJwtDecoder decoder = decoder(jwt("j-1"));
        for (int i = 0; i < RedisCircuitBreaker.FAILURES_TO_OPEN; i++) {
            StepVerifier.create(decoder.decode("t")).expectError(RevocationUnavailableException.class).verify();
        }
        assertThat(breaker.allowCall()).isEqualTo(Permit.DENIED);
        answer.set(Mono.just(false));

        StepVerifier.create(decoder.decode("t")).expectError(RevocationUnavailableException.class).verify();

        assertThat(storeCalls).hasValue(RedisCircuitBreaker.FAILURES_TO_OPEN);
    }

    /** A revoked token is Redis answering, not failing: it must not count towards opening. */
    @Test
    void aRevokedTokenIsNotARedisFailure() {
        RedisCircuitBreaker opensOnOne = new RedisCircuitBreaker("Revocation check", "refusing",
                RedisCircuitBreaker.OPEN_FOR, 1, now::get);
        answer.set(Mono.just(true));

        StepVerifier.create(new RevocationCheckingJwtDecoder(token -> Mono.just(jwt("j-1")), store, opensOnOne, TIMEOUT)
                        .decode("t"))
                .expectError(BadJwtException.class)
                .verify();

        assertThat(opensOnOne.allowCall()).isEqualTo(Permit.CLOSED);
    }

    @Test
    void theProbesSuccessClosesTheBreaker() {
        answer.set(Mono.error(DOWN));
        RevocationCheckingJwtDecoder decoder = decoder(jwt("j-1"));
        for (int i = 0; i < RedisCircuitBreaker.FAILURES_TO_OPEN; i++) {
            decoder.decode("t").onErrorResume(error -> Mono.empty()).block();
        }
        now.addAndGet(RedisCircuitBreaker.OPEN_FOR.toNanos());
        answer.set(Mono.just(false));

        StepVerifier.create(decoder.decode("t")).expectNextCount(1).verifyComplete();

        assertThat(breaker.allowCall()).isEqualTo(Permit.CLOSED);
    }

    /**
     * Only the probe's success may close the breaker. A call that took its CLOSED permit before the
     * breaker opened, and answers after, is a late success from before the opening: it must not
     * close the breaker again.
     */
    @Test
    void aLateSuccessDoesNotCloseTheBreaker() {
        Sinks.One<Boolean> late = Sinks.one();
        answer.set(late.asMono());
        RevocationCheckingJwtDecoder decoder = decoder(jwt("j-1"));
        decoder.decode("t").subscribe(jwt -> { }, error -> { });
        answer.set(Mono.error(DOWN));
        for (int i = 0; i < RedisCircuitBreaker.FAILURES_TO_OPEN; i++) {
            decoder.decode("t").onErrorResume(error -> Mono.empty()).block();
        }

        late.tryEmitValue(false);

        assertThat(breaker.allowCall()).isEqualTo(Permit.DENIED);
    }

    /**
     * The permit is taken when the check runs, not when the decode is assembled: a decode assembled
     * while the breaker was closed, and run after it opened, is refused without asking Redis.
     */
    @Test
    void thePermitIsTakenWhenTheCheckRuns() {
        RevocationCheckingJwtDecoder decoder = decoder(jwt("j-1"));
        Mono<Jwt> assembledWhileClosed = decoder.decode("t");
        answer.set(Mono.error(DOWN));
        for (int i = 0; i < RedisCircuitBreaker.FAILURES_TO_OPEN; i++) {
            decoder.decode("t").onErrorResume(error -> Mono.empty()).block();
        }

        StepVerifier.create(assembledWhileClosed).expectError(RevocationUnavailableException.class).verify();

        assertThat(storeCalls).hasValue(RedisCircuitBreaker.FAILURES_TO_OPEN);
    }

    private RevocationCheckingJwtDecoder decoder(Jwt decoded) {
        return decoder(token -> Mono.just(decoded));
    }

    private RevocationCheckingJwtDecoder decoder(ReactiveJwtDecoder inner) {
        return new RevocationCheckingJwtDecoder(inner, store, breaker, TIMEOUT);
    }

    private static Jwt jwt(String jti) {
        Jwt.Builder builder = Jwt.withTokenValue("t")
                .header("alg", "RS256")
                .subject("ezzat")
                .issuer("http://localhost:8080");
        if (jti != null) {
            builder.jti(jti);
        }
        return builder.build();
    }
}
