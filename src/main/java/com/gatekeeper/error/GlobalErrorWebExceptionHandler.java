package com.gatekeeper.error;

import com.gatekeeper.apikey.IntrospectionUnavailableException;
import com.gatekeeper.revocation.RevocationUnavailableException;
import org.springframework.boot.autoconfigure.web.WebProperties;
import org.springframework.boot.web.error.ErrorAttributeOptions;
import org.springframework.boot.webflux.autoconfigure.error.AbstractErrorWebExceptionHandler;
import org.springframework.boot.webflux.error.ErrorAttributes;
import org.springframework.context.ApplicationContext;
import org.springframework.core.annotation.Order;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.codec.ServerCodecConfigurer;
import org.springframework.stereotype.Component;
import org.springframework.web.reactive.function.server.RequestPredicates;
import org.springframework.web.reactive.function.server.RouterFunction;
import org.springframework.web.reactive.function.server.RouterFunctions;
import org.springframework.web.reactive.function.server.ServerRequest;
import org.springframework.web.reactive.function.server.ServerResponse;
import reactor.core.publisher.Mono;

/**
 * One JSON error shape across the platform. Without it a client gets an empty body from
 * the gateway and a JSON body from the services behind it for what is, to them, the same
 * failure.
 *
 * <p>Ordered ahead of Boot's own handler so this one wins. In practice Boot's own handler is
 * never even created: its {@code @Bean} method carries {@code @ConditionalOnMissingBean} on
 * its return type {@code ErrorWebExceptionHandler}, and this component — a bean of that same
 * type — is registered before autoconfiguration is evaluated, the way every
 * {@code @ConditionalOnMissingBean} back-off in Boot works. The explicit {@code @Order(-2)}
 * (one ahead of the {@code @Order(-1)} Boot would have used) is defence in depth for that,
 * not the thing actually doing the work — confirmed by reading both classes' bytecode with
 * {@code javap} rather than assumed.
 *
 * <p>This handler does not, by itself, catch the no-token case. Spring Security's own {@code
 * ServerAuthenticationEntryPoint} commits a 401 directly and never throws, so that request
 * never reaches this class at all — see {@link JsonServerAuthenticationEntryPoint}, wired in
 * {@code GatewaySecurityConfig}, which renders the identical {@link ErrorBody} shape for
 * that path instead.
 */
@Component
@Order(-2)
public class GlobalErrorWebExceptionHandler extends AbstractErrorWebExceptionHandler {

    public GlobalErrorWebExceptionHandler(ErrorAttributes errorAttributes,
                                          WebProperties webProperties,
                                          ApplicationContext applicationContext,
                                          ServerCodecConfigurer codecConfigurer) {
        super(errorAttributes, webProperties.getResources(), applicationContext);
        setMessageWriters(codecConfigurer.getWriters());
        setMessageReaders(codecConfigurer.getReaders());
    }

    @Override
    protected RouterFunction<ServerResponse> getRoutingFunction(ErrorAttributes errorAttributes) {
        return RouterFunctions.route(RequestPredicates.all(), this::render);
    }

    private Mono<ServerResponse> render(ServerRequest request) {
        Throwable error = getError(request);
        HttpStatus status = statusFor(request, error);

        ServerResponse.BodyBuilder builder = ServerResponse.status(status)
                .contentType(MediaType.APPLICATION_JSON);

        if (status == HttpStatus.UNAUTHORIZED) {
            // RFC 6750 requires it on a 401 from a bearer-token resource.
            // JsonServerAuthenticationEntryPoint already sets it on the path it owns (no
            // credential at all); omitting it here would mean the other two ways this
            // gateway says "unauthorized" - an unreachable JWKS, a rejected outbound header -
            // fail to tell the caller how to authenticate, contradicting that class's own
            // reasoning about the same header. Not unconditional: a 503 or 404 carrying
            // WWW-Authenticate would be wrong and confusing.
            builder = builder.header(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
        }

        if (status == HttpStatus.SERVICE_UNAVAILABLE) {
            // Tells the caller this is worth retrying, which is the whole reason this path is a
            // 503 and not a 401 — their credential may be perfectly good.
            builder = builder.header(HttpHeaders.RETRY_AFTER, "5");
        }

        // Only the revocation 503 carries a detail, so it can be told from M3's introspection 503.
        String detail = error instanceof RevocationUnavailableException ? RevocationUnavailableException.DETAIL : null;
        return builder.bodyValue(ErrorBody.of(status, request.path(), detail));
    }

    /**
     * Four failures reach here as raw runtime exceptions rather than anything Spring
     * Security recognises, and all four would otherwise read as a server fault.
     *
     * <p>An unreachable JWKS arrives as {@code IllegalStateException("Could not obtain the
     * keys", ...)} from the remote key source — {@code JwtReactiveAuthenticationManager}
     * maps only {@code JwtException}, so it passes through untouched. A claim carrying a
     * control character arrives as {@code IllegalArgumentException("Validation failed for
     * header '...'", ...)} from Netty's header validation, thrown inside the gateway's own
     * routing filter when it copies the stamped header onto the outbound request.
     *
     * <p>Neither is a server fault from the caller's side: in both cases the gateway
     * cannot establish who they are, so it refuses the credential. Answering 401 also
     * avoids advertising that the identity provider is unreachable.
     *
     * <p>The match on those two is on exception type <em>and</em> the fixed part of the
     * message each library uses for exactly this condition, deliberately narrower than "any
     * {@code IllegalStateException} or {@code IllegalArgumentException}". Those two types are
     * common enough that a genuine bug elsewhere in the gateway could easily throw one for
     * an unrelated reason — bad internal state, a rejected argument in code M4 adds later —
     * and a blanket catch here would relabel that bug as an authentication failure. A 401
     * is not paged on the way a 500 is, so a masked bug could sit unnoticed for a long
     * time. Both messages are confirmed against the actual stack traces this failure
     * produces (see the two exception-shape tests), not assumed from the description.
     *
     * <p>{@link IntrospectionUnavailableException} gets a bare type match instead, with no
     * message narrowing. The reasoning above for the other two does not transfer: it is a
     * type this gateway declares for itself and throws from exactly one place ({@code
     * IntrospectionClient.introspect}), for exactly one reason — AuthCore's introspection
     * call could not be completed. Unlike a JDK exception type, there is no ambient,
     * everyday use of it that an unrelated bug elsewhere could collide with, so narrowing
     * on message text as well would add ceremony without removing any real risk of
     * mislabelling something else. It maps to 503, not 401 — see its own Javadoc for why.
     *
     * <p>{@link RevocationUnavailableException} gets the same bare type match and the same 503, for
     * the same reasons: declared by this gateway, thrown from one place ({@code
     * RevocationCheckingJwtDecoder}) for one reason — whether the token is revoked could not be
     * established. A 401 would send a caller holding a very likely valid token to refresh it,
     * against an AuthCore that is itself stuck while Redis is down (the M6 design, section 4).
     */
    private HttpStatus statusFor(ServerRequest request, Throwable error) {
        if (isUnreachableJwks(error) || isRejectedOutboundHeader(error)) {
            return HttpStatus.UNAUTHORIZED;
        }
        if (error instanceof IntrospectionUnavailableException || error instanceof RevocationUnavailableException) {
            return HttpStatus.SERVICE_UNAVAILABLE;
        }

        int code = (int) getErrorAttributes(request, ErrorAttributeOptions.defaults())
                .getOrDefault("status", 500);
        HttpStatus resolved = HttpStatus.resolve(code);
        return resolved != null ? resolved : HttpStatus.INTERNAL_SERVER_ERROR;
    }

    /**
     * {@code NimbusReactiveJwtDecoder}'s fixed message when {@code
     * ReactiveRemoteJWKSource.getJWKSet()} fails for any reason — connection refused, DNS
     * failure, timeout, a non-2xx response, or malformed JSON from the JWKS endpoint. All of
     * these surface through the same unconditional, single-argument {@code
     * Mono#onErrorMap(Function)} wrapping the key-fetch pipeline (confirmed by reading the
     * decoder's bytecode: the mapper is {@code t -> new IllegalStateException("Could not
     * obtain the keys", t)} with no type check on {@code t}), so the message carries no
     * variable text and an exact match is safe without also inspecting the cause chain.
     */
    private static boolean isUnreachableJwks(Throwable error) {
        return error instanceof IllegalStateException
                && "Could not obtain the keys".equals(error.getMessage());
    }

    /**
     * Netty's {@code DefaultHeaders.validateValue} message when a header value fails
     * validation, prefix-matched because the message interpolates the header name (e.g.
     * {@code X-GK-Permissions}, but any {@code X-GK-*} header stamped from a verified claim
     * could in principle carry the same kind of poisoned value). Matching the prefix rather
     * than the full message, and not the specific header name, is deliberate: which header
     * triggered it does not change the response, only that this filter's header-copy step
     * is where it happened.
     */
    private static boolean isRejectedOutboundHeader(Throwable error) {
        return error instanceof IllegalArgumentException
                && error.getMessage() != null
                && error.getMessage().startsWith("Validation failed for header");
    }
}
