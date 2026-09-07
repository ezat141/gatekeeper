package com.gatekeeper.config;

import com.gatekeeper.apikey.ApiKeyAuthenticationConverter;
import com.gatekeeper.apikey.ApiKeyCache;
import com.gatekeeper.apikey.ApiKeyProperties;
import com.gatekeeper.apikey.ApiKeyReactiveAuthenticationManager;
import com.gatekeeper.apikey.IntrospectionClient;
import com.gatekeeper.apikey.RedisApiKeyCache;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.data.redis.core.ReactiveStringRedisTemplate;
import org.springframework.security.config.annotation.web.reactive.EnableWebFluxSecurity;
import org.springframework.security.config.web.server.SecurityWebFiltersOrder;
import org.springframework.security.config.web.server.ServerHttpSecurity;
import org.springframework.security.oauth2.jwt.ReactiveJwtDecoder;
import org.springframework.security.oauth2.server.resource.web.server.authentication.ServerBearerTokenAuthenticationConverter;
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.ServerAuthenticationConverter;
import org.springframework.security.web.server.authentication.ServerAuthenticationEntryPointFailureHandler;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import tools.jackson.databind.ObjectMapper;

/**
 * Replaces Boot's default deny-all chain, which was installed simply because the OAuth2
 * resource-server starter is on the classpath.
 *
 * <p>Only authentication is decided here. Route-level authorization is M4; mixing the two
 * now would bury the route rules inside this method later.
 *
 * <p>The entry point is overridden because Spring Security's default writes the 401
 * response body directly and completes it before this class's own {@code
 * SecurityWebFilterChain} configuration has any further say — see {@code
 * com.gatekeeper.error.JsonServerAuthenticationEntryPoint} for why that path needs its own
 * copy of the platform's JSON error shape rather than inheriting it for free.
 */
@Configuration
@EnableWebFluxSecurity
public class GatewaySecurityConfig {

    @Bean
    public WebClient introspectionWebClient() {
        return WebClient.builder().build();
    }

    @Bean
    public ApiKeyCache apiKeyCache(ReactiveStringRedisTemplate redis, ObjectMapper objectMapper) {
        return new RedisApiKeyCache(redis, objectMapper);
    }

    @Bean
    public IntrospectionClient introspectionClient(
            WebClient introspectionWebClient, ApiKeyProperties properties) {
        return new IntrospectionClient(introspectionWebClient, properties);
    }

    @Bean
    public ApiKeyReactiveAuthenticationManager apiKeyAuthenticationManager(
            ApiKeyCache cache, IntrospectionClient client, ApiKeyProperties properties) {
        return new ApiKeyReactiveAuthenticationManager(cache, client, properties);
    }

    @Bean
    public SecurityWebFilterChain securityWebFilterChain(
            ServerHttpSecurity http, ReactiveJwtDecoder jwtDecoder,
            ServerAuthenticationEntryPoint authenticationEntryPoint,
            ApiKeyReactiveAuthenticationManager apiKeyAuthenticationManager) {

        return http
                // A credential arrives on every request, so a session would add server state
                // and CSRF exposure for nothing.
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .authorizeExchange(exchange -> exchange
                        .pathMatchers("/actuator/health", "/actuator/health/**").permitAll()
                        .anyExchange().authenticated())
                .oauth2ResourceServer(resourceServer -> resourceServer
                        .authenticationEntryPoint(authenticationEntryPoint)
                        .bearerTokenConverter(bearerConverterDeferringToApiKey())
                        .jwt(jwt -> jwt.jwtDecoder(jwtDecoder)))
                .addFilterAt(apiKeyAuthenticationWebFilter(apiKeyAuthenticationManager, authenticationEntryPoint),
                        SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
    }

    /**
     * Makes "the key decides" literally true.
     *
     * <p>Placing the API-key filter ahead of the resource server's is not enough: on success
     * our filter continues the chain, and the resource server's own AuthenticationWebFilter
     * then runs regardless, without checking whether the context is already populated. That
     * meant a valid key plus a malformed bearer was refused 401, and a valid key plus a valid
     * bearer authenticated as the token's subject — silently overwriting the key's principal,
     * which M4 would then authorize against.
     *
     * <p>Deferring only when the header actually carries text matches
     * {@link ApiKeyAuthenticationConverter} exactly. Keying off mere presence would let a blank
     * {@code X-API-Key:} disable bearer authentication for the whole request while the API-key
     * converter also declined it — turning an empty header into a way to switch authentication
     * off entirely.
     */
    private ServerAuthenticationConverter bearerConverterDeferringToApiKey() {
        ServerBearerTokenAuthenticationConverter delegate =
                new ServerBearerTokenAuthenticationConverter();
        return exchange -> {
            String key = exchange.getRequest().getHeaders()
                    .getFirst(ApiKeyAuthenticationConverter.HEADER_NAME);
            return StringUtils.hasText(key) ? Mono.empty() : delegate.convert(exchange);
        };
    }

    /**
     * Runs at the authentication position, ahead of the resource server's own filter, so
     * X-API-Key decides the outcome whenever it is present.
     *
     * <p>A present-but-invalid key fails here rather than falling through to the JWT path.
     * A typo'd key should read as "bad credentials", not as a confusing "no credentials", and
     * a caller must not be able to smuggle a bad key past the gateway by attaching a good
     * token. This matches ApiKeyAuthenticationFilter's behaviour in AuthCore.
     *
     * <table>
     *   <caption>Precedence when both an API key and a bearer token can be present</caption>
     *   <tr><th>{@code X-API-Key}</th><th>{@code Authorization: Bearer}</th><th>Result</th></tr>
     *   <tr><td>absent</td><td>absent</td><td>401</td></tr>
     *   <tr><td>absent</td><td>valid JWT</td><td>JWT path, unchanged from M2</td></tr>
     *   <tr><td>present, valid</td><td>either</td>
     *       <td>200, authenticated as the key; the bearer token is not consulted</td></tr>
     *   <tr><td>present, invalid</td><td>either</td>
     *       <td>401 — no fallthrough to the JWT path; this filter's failure handler,
     *       above, is what guarantees it</td></tr>
     * </table>
     *
     * <p>The third row does not hold on this filter's position alone. Left to its defaults —
     * no override on {@code bearerTokenConverter} — the resource server's own {@link
     * AuthenticationWebFilter}, chained at the same {@link
     * SecurityWebFiltersOrder#AUTHENTICATION} position, ran unconditionally once this filter
     * succeeded, regardless of whether the context was already populated, and either
     * overrode the key's principal with the bearer's or let a malformed bearer's own failure
     * handler commit a 401 over an already-successful key authentication.
     * {@link #bearerConverterDeferringToApiKey()} is what makes the row hold: it makes that
     * filter's bearer-token converter decline to look at the token at all whenever
     * {@code X-API-Key} carries text.
     */
    private AuthenticationWebFilter apiKeyAuthenticationWebFilter(
            ApiKeyReactiveAuthenticationManager manager,
            ServerAuthenticationEntryPoint entryPoint) {

        AuthenticationWebFilter filter = new AuthenticationWebFilter(manager);
        filter.setServerAuthenticationConverter(new ApiKeyAuthenticationConverter());
        filter.setAuthenticationFailureHandler(
                new ServerAuthenticationEntryPointFailureHandler(entryPoint));
        return filter;
    }
}
