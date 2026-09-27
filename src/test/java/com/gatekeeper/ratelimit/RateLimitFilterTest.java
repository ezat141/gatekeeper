package com.gatekeeper.ratelimit;

import com.gatekeeper.error.TooManyRequestsWriter;
import com.gatekeeper.ratelimit.RateLimitProperties.PlanLimits;
import org.junit.jupiter.api.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.authority.AuthorityUtils;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.server.resource.authentication.JwtAuthenticationToken;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.Map;
import java.util.concurrent.atomic.AtomicInteger;

import static org.assertj.core.api.Assertions.assertThat;

class RateLimitFilterTest {

    static final Authentication ACME = new JwtAuthenticationToken(
            Jwt.withTokenValue("t").header("alg", "RS256").subject("ezzat").claim("tenant", "acme").build(),
            AuthorityUtils.NO_AUTHORITIES);

    static final RateLimitProperties PROPERTIES = new RateLimitProperties(
            Duration.ofMillis(100), "free", Map.of("free", new PlanLimits(5, 10, 1000)), null);

    final AtomicInteger chainCalls = new AtomicInteger();
    final AtomicInteger storeCalls = new AtomicInteger();
    final GatewayFilterChain chain = exchange -> {
        chainCalls.incrementAndGet();
        return Mono.empty();
    };

    @Test
    void forwardsAnAllowedRequestOnceWithTheHeaders() {
        MockServerWebExchange exchange = exchange();

        run(exchange, store(Mono.just(new Decision(true, null, 9, 999, 0, 3600))), ACME);

        assertThat(chainCalls).hasValue(1);
        HttpHeaders headers = exchange.getResponse().getHeaders();
        assertThat(headers.getFirst("X-RateLimit-Remaining")).isEqualTo("9");
        assertThat(headers.getFirst("X-RateLimit-Replenish-Rate")).isEqualTo("5");
        assertThat(headers.getFirst("X-RateLimit-Burst-Capacity")).isEqualTo("10");
        assertThat(headers.getFirst("X-Quota-Limit")).isEqualTo("1000");
        assertThat(headers.getFirst("X-Quota-Remaining")).isEqualTo("999");
        assertThat(headers.getFirst("X-Quota-Reset")).isEqualTo("3600");
        assertThat(headers.getFirst(HttpHeaders.RETRY_AFTER)).isNull();
    }

    @Test
    void refusesWithoutForwarding() {
        MockServerWebExchange exchange = exchange();

        run(exchange, store(Mono.just(new Decision(false, RateLimitReason.QUOTA_EXCEEDED, 4, 0, 120, 120))), ACME);

        assertThat(chainCalls).hasValue(0);
        assertThat(exchange.getResponse().getStatusCode()).isEqualTo(HttpStatus.TOO_MANY_REQUESTS);
        assertThat(exchange.getResponse().getHeaders().getFirst(HttpHeaders.RETRY_AFTER)).isEqualTo("120");
        assertThat(exchange.getResponse().getHeaders().getFirst("X-Quota-Remaining")).isEqualTo("0");
        assertThat(exchange.getResponse().getBodyAsString().block())
                .contains("\"detail\":\"the caller's daily quota is used up\"");
    }

    @Test
    void letsARequestThroughUnlimitedWhenTheStoreFails() {
        MockServerWebExchange exchange = exchange();

        run(exchange, store(Mono.error(new IllegalStateException("redis down"))), ACME);

        assertThat(chainCalls).hasValue(1);
        assertThat(exchange.getResponse().getHeaders().getFirst("X-RateLimit-Remaining")).isNull();
    }

    @Test
    void letsARequestThroughUnlimitedWhenTheStoreNeverAnswers() {
        MockServerWebExchange exchange = exchange();
        long started = System.nanoTime();

        run(exchange, store(Mono.never()), ACME);

        assertThat(chainCalls).hasValue(1);
        assertThat(Duration.ofNanos(System.nanoTime() - started)).isLessThan(Duration.ofSeconds(2));
        assertThat(exchange.getResponse().getHeaders().getFirst("X-RateLimit-Remaining")).isNull();
    }

    @Test
    void letsARequestThroughUnlimitedWhenTheStoreCompletesEmpty() {
        MockServerWebExchange exchange = exchange();

        run(exchange, store(Mono.empty()), ACME);

        assertThat(chainCalls).hasValue(1);
        assertThat(exchange.getResponse().getHeaders().getFirst("X-RateLimit-Remaining")).isNull();
    }

    @Test
    void forwardsACallerWithNoIdentityOnceWithoutConsultingTheStore() {
        MockServerWebExchange exchange = exchange();

        filter(store(Mono.just(new Decision(true, null, 9, 999, 0, 3600)))).filter(exchange, chain).block();

        assertThat(chainCalls).hasValue(1);
        assertThat(storeCalls).hasValue(0);
    }

    private static MockServerWebExchange exchange() {
        return MockServerWebExchange.from(MockServerHttpRequest.get("/api/ledger/entries"));
    }

    private RateLimitStore store(Mono<Decision> answer) {
        return (identity, plan) -> {
            storeCalls.incrementAndGet();
            return answer;
        };
    }

    private RateLimitFilter filter(RateLimitStore store) {
        return new RateLimitFilter(new ConfiguredPlanResolver(PROPERTIES), store,
                new TooManyRequestsWriter(ServerCodecConfigurer.create()), PROPERTIES);
    }

    private void run(MockServerWebExchange exchange, RateLimitStore store, Authentication caller) {
        filter(store).filter(exchange, chain)
                .contextWrite(ReactiveSecurityContextHolder.withAuthentication(caller))
                .block(Duration.ofSeconds(5));
    }
}
