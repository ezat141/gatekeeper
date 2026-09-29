package com.gatekeeper.ratelimit;

import com.gatekeeper.error.TooManyRequestsWriter;
import com.gatekeeper.ratelimit.RedisCircuitBreaker.Permit;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.security.core.context.ReactiveSecurityContextHolder;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;

import java.time.Duration;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Optional;

/**
 * Limits every routed request to its caller's plan. The M5 design, sections 4 to 8.
 *
 * <p>A gateway filter, so it runs after Spring Security's whole chain: only a request that
 * passed authentication and the rule table is counted, and a 401 or 403 never touches Redis.
 * Ordered just after {@code IdentityStampFilter} and ahead of every routing filter, so a refusal
 * never reaches a downstream. It applies to every route without route configuration.
 *
 * <p><strong>Fails open, fast.</strong> A Redis error, a timeout, or an empty answer lets the
 * request through unlimited, with no rate-limit headers, and counts against the
 * {@link RedisCircuitBreaker}. Three in a row open it: for its window no request calls Redis at all,
 * and the breaker logs the outage once when it opens and once when it closes. An isolated failure
 * fails only its own request open. Rate limiting is a capacity control; a Redis outage must not
 * become a gateway outage. M6's revocation check will fail closed on the same Redis, deliberately —
 * see the M5 design, section 7.
 *
 * <p>The fail-open branch covers only the store call, never the downstream chain: an error from
 * the downstream must not be mistaken for Redis failing and forward the request a second time.
 */
@Component
public class RateLimitFilter implements GlobalFilter, Ordered {

    private static final Logger log = LoggerFactory.getLogger(RateLimitFilter.class);

    private final PlanResolver plans;
    private final RateLimitStore store;
    private final TooManyRequestsWriter writer;
    private final Duration timeout;
    private final RedisCircuitBreaker breaker;

    public RateLimitFilter(PlanResolver plans, RateLimitStore store, TooManyRequestsWriter writer,
                           RateLimitProperties properties, RedisCircuitBreaker breaker) {
        this.plans = plans;
        this.store = store;
        this.writer = writer;
        this.timeout = properties.redisTimeout();
        this.breaker = breaker;
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return ReactiveSecurityContextHolder.getContext()
                .mapNotNull(SecurityContext::getAuthentication)
                .map(RateLimitIdentity::of)
                .defaultIfEmpty(Optional.empty())
                .flatMap(identity -> identity
                        .map(caller -> limit(exchange, chain, caller))
                        .orElseGet(() -> {
                            log.debug("Routed request with no rate-limit identity; forwarding unlimited: {}",
                                    exchange.getRequest().getPath());
                            return chain.filter(exchange);
                        }));
    }

    private Mono<Void> limit(ServerWebExchange exchange, GatewayFilterChain chain, RateLimitIdentity caller) {
        Permit permit = breaker.allowCall();
        if (permit == Permit.DENIED) {
            log.debug("Rate limiter's breaker is open; forwarding {} unlimited", caller.key());
            return chain.filter(exchange);
        }
        Plan plan = plans.resolve(caller);
        return store.check(caller, plan)
                .timeout(timeout)
                .map(Optional::of)
                .switchIfEmpty(Mono.error(() -> new IllegalStateException("store answered nothing")))
                // The permit taken before the call, not the breaker's state now: only a probe's
                // success may close it.
                .doOnNext(decision -> breaker.recordSuccess(permit))
                .onErrorResume(error -> {
                    breaker.recordFailure(permit, error);
                    return Mono.just(Optional.<Decision>empty());
                })
                // From here the chain continues on Lettuce's or the timeout's thread, as Spring Cloud
                // Gateway's own limiter does.
                .flatMap(decision -> decision
                        .map(outcome -> apply(exchange, chain, plan, outcome))
                        .orElseGet(() -> chain.filter(exchange)));
    }

    private Mono<Void> apply(ServerWebExchange exchange, GatewayFilterChain chain, Plan plan, Decision decision) {
        Map<String, String> headers = headers(plan, decision);
        if (decision.allowed()) {
            exchange.getResponse().getHeaders().setAll(headers);
            return chain.filter(exchange);
        }
        headers.put(HttpHeaders.RETRY_AFTER, Long.toString(decision.retryAfterSeconds()));
        return writer.write(exchange, decision.reason().detail(), headers);
    }

    private static Map<String, String> headers(Plan plan, Decision decision) {
        Map<String, String> headers = new LinkedHashMap<>();
        headers.put("X-RateLimit-Remaining", Long.toString(decision.tokensRemaining()));
        headers.put("X-RateLimit-Replenish-Rate", Integer.toString(plan.requestsPerSecond()));
        headers.put("X-RateLimit-Burst-Capacity", Long.toString(plan.burst()));
        headers.put("X-Quota-Limit", Long.toString(plan.dailyQuota()));
        headers.put("X-Quota-Remaining", Long.toString(decision.quotaRemaining()));
        headers.put("X-Quota-Reset", Long.toString(decision.quotaResetSeconds()));
        return headers;
    }

    /** Just after {@code IdentityStampFilter}, which is {@code HIGHEST_PRECEDENCE}. */
    @Override
    public int getOrder() {
        return Ordered.HIGHEST_PRECEDENCE + 1;
    }
}
