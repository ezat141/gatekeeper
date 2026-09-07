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
import org.springframework.security.web.server.ServerAuthenticationEntryPoint;
import org.springframework.security.web.server.SecurityWebFilterChain;
import org.springframework.security.web.server.authentication.AuthenticationWebFilter;
import org.springframework.security.web.server.authentication.ServerAuthenticationEntryPointFailureHandler;
import org.springframework.web.reactive.function.client.WebClient;
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
                        .jwt(jwt -> jwt.jwtDecoder(jwtDecoder)))
                .addFilterAt(apiKeyAuthenticationWebFilter(apiKeyAuthenticationManager, authenticationEntryPoint),
                        SecurityWebFiltersOrder.AUTHENTICATION)
                .build();
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
     *   <tr><td>present, valid</td><td>absent</td>
     *       <td>200, authenticated as the key</td></tr>
     *   <tr><td>present, invalid</td><td>either</td>
     *       <td>401 — no fallthrough to the JWT path; this filter's failure handler,
     *       above, is what guarantees it</td></tr>
     * </table>
     *
     * <p><b>Gap, confirmed by scratch probes rather than by a committed test — the design
     * intent below the table is not fully met when a bearer is ALSO attached to a request
     * carrying a valid key:</b> {@link AuthenticationWebFilter}'s default success handler
     * unconditionally continues the filter chain once this filter authenticates the key, so
     * the resource server's own {@code AuthenticationWebFilter} — chained immediately after
     * this one, at the same {@link SecurityWebFiltersOrder#AUTHENTICATION} position — always
     * still runs, whether or not this filter already succeeded:
     * <ul>
     *   <li>Bearer present and itself valid: the JWT filter also succeeds and overwrites the
     *   reactive {@code SecurityContext} this filter just set, so the request that reaches
     *   the route is authenticated as the <em>bearer's</em> identity, not the key's, though
     *   the response is still 200 (both credentials were individually good) — confirmed by
     *   inspecting the proxied request: {@code X-GK-Subject} carried the JWT's subject, not
     *   the key's name, i.e. {@link com.gatekeeper.identity.IdentityStampFilter} stamped
     *   from a {@code JwtAuthenticationToken}, not this filter's {@code
     *   ApiKeyAuthenticationToken}. "The bearer token is not consulted" is true only when no
     *   bearer is attached at all.
     *   <li>Bearer present and invalid (expired, malformed, wrong issuer): the JWT filter
     *   fails, and its own failure handler commits a 401 that overrides this filter's
     *   already-successful authentication — reproduced with a valid key plus {@code
     *   Authorization: Bearer not-a-real-jwt}. A key that works alone stops working the
     *   moment an unrelated stale or malformed bearer rides along with it.
     * </ul>
     * Left unfixed here — a fix (a success handler on this filter that short-circuits the
     * rest of the authentication phase once the key succeeds, or a requires-authentication
     * matcher on the JWT filter that skips an already-authenticated exchange) is a design
     * decision outside what Task 11 specified, and deserves its own review rather than
     * riding along inside this one.
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
