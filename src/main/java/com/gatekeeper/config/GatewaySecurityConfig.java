package com.gatekeeper.config;

import com.gatekeeper.apikey.ApiKeyAuthenticationConverter;
import com.gatekeeper.apikey.ApiKeyCache;
import com.gatekeeper.apikey.ApiKeyProperties;
import com.gatekeeper.apikey.ApiKeyReactiveAuthenticationManager;
import com.gatekeeper.apikey.IntrospectionClient;
import com.gatekeeper.apikey.RedisApiKeyCache;
import com.gatekeeper.authz.RouteScopeAuthorizationManager;
import com.gatekeeper.authz.TenantAuthorizationManager;
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
import org.springframework.security.web.server.authorization.ServerAccessDeniedHandler;
import org.springframework.security.web.server.util.matcher.NegatedServerWebExchangeMatcher;
import org.springframework.security.web.server.util.matcher.ServerWebExchangeMatchers;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;

/**
 * Replaces Boot's default deny-all chain, which was installed simply because the OAuth2
 * resource-server starter is on the classpath.
 *
 * <p>Authentication is decided by the two filters configured below. Authorization is
 * decided by {@link RouteScopeAuthorizationManager}, wrapped in {@link
 * TenantAuthorizationManager} — in {@code com.gatekeeper.authz}, so the route rules live in a
 * class of their own rather than inside this method.
 *
 * <p>The access-denied handler is set once, on {@code exceptionHandling}, and that one
 * setting covers bearer and key callers alike: {@code ServerHttpSecurity} consults the
 * resource server's own bearer handler only when no explicit handler is configured (verified
 * in the 7.0.6 bytecode). Setting it on {@code oauth2ResourceServer} as well would be dead
 * configuration.
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
    public ApiKeyCache apiKeyCache(ReactiveStringRedisTemplate redis) {
        return new RedisApiKeyCache(redis);
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
            ServerAccessDeniedHandler accessDeniedHandler,
            ApiKeyReactiveAuthenticationManager apiKeyAuthenticationManager) {

        return http
                // A credential arrives on every request, so a session would add server state
                // and CSRF exposure for nothing.
                .csrf(ServerHttpSecurity.CsrfSpec::disable)
                .httpBasic(ServerHttpSecurity.HttpBasicSpec::disable)
                .formLogin(ServerHttpSecurity.FormLoginSpec::disable)
                .authorizeExchange(exchange -> exchange
                        .pathMatchers("/actuator/health", "/actuator/health/**").permitAll()
                        .anyExchange().access(
                                new TenantAuthorizationManager(new RouteScopeAuthorizationManager())))
                .exceptionHandling(handling -> handling.accessDeniedHandler(accessDeniedHandler))
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
     * {@link ApiKeyAuthenticationConverter} exactly — both sides call {@link
     * ApiKeyAuthenticationConverter#carriesKey} so they cannot drift apart. Keying off mere
     * presence would let a blank {@code X-API-Key:} suppress bearer
     * authentication for the whole request while the API-key converter also declined it, so
     * a request carrying a perfectly good token would be refused 401. An empty header would
     * become a kill switch for the bearer path, not a way to bypass authentication.
     */
    private ServerAuthenticationConverter bearerConverterDeferringToApiKey() {
        ServerBearerTokenAuthenticationConverter delegate =
                new ServerBearerTokenAuthenticationConverter();
        return exchange -> ApiKeyAuthenticationConverter.carriesKey(exchange)
                ? Mono.empty()
                : delegate.convert(exchange);
    }

    /**
     * Runs at the authentication position. What that buys: it runs before {@code
     * AuthorizationWebFilter}, so a key-authenticated request is authenticated by the time the
     * rule table runs — moving it after {@link SecurityWebFiltersOrder#AUTHORIZATION} fails
     * every key-authenticated route. Its position relative to the resource server's own
     * {@link AuthenticationWebFilter}, chained at the same {@link
     * SecurityWebFiltersOrder#AUTHENTICATION} position, is <strong>not</strong> load-bearing:
     * the two filters' converters are mutually exclusive (see {@link
     * #bearerConverterDeferringToApiKey()}), so which of them runs first cannot matter. What
     * makes the key decide is that deferral, not this filter's position.
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
     *       <td>authenticated as the key; the bearer token is not consulted, and the rule
     *       table then decides what the key may reach</td></tr>
     *   <tr><td>present, invalid</td><td>either</td>
     *       <td>401 — no fallthrough to the JWT path; this filter's failure handler,
     *       above, gives the refusal the platform's JSON error shape (the 401 itself is
     *       {@link AuthenticationWebFilter}'s own default)</td></tr>
     * </table>
     */
    private AuthenticationWebFilter apiKeyAuthenticationWebFilter(
            ApiKeyReactiveAuthenticationManager manager,
            ServerAuthenticationEntryPoint entryPoint) {

        AuthenticationWebFilter filter = new AuthenticationWebFilter(manager);
        filter.setServerAuthenticationConverter(new ApiKeyAuthenticationConverter());
        filter.setAuthenticationFailureHandler(
                new ServerAuthenticationEntryPointFailureHandler(entryPoint));
        // AuthenticationWebFilter's default requiresAuthenticationMatcher is anyExchange(),
        // so without this, an unauthenticated caller could attach an arbitrary X-API-Key to
        // the one route that needs no credential and still drive an introspection call (and
        // a Redis write) to AuthCore for a key value the caller alone picks — the negative
        // cache does not dampen this, since each distinct key value is a fresh cache entry.
        // Must track the pathMatchers(...).permitAll() list in securityWebFilterChain above
        // exactly: any path permitted there but not excluded here reopens this hole.
        filter.setRequiresAuthenticationMatcher(new NegatedServerWebExchangeMatcher(
                ServerWebExchangeMatchers.pathMatchers(
                        "/actuator/health", "/actuator/health/**")));
        return filter;
    }
}
