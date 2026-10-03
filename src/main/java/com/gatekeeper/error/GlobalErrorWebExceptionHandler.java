package com.gatekeeper.error;

import com.gatekeeper.apikey.IntrospectionUnavailableException;
import com.gatekeeper.revocation.RevocationUnavailableException;
import org.jspecify.annotations.Nullable;
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
import org.springframework.web.server.ResponseStatusException;
import reactor.core.publisher.Mono;

import java.net.ConnectException;

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
 *
 * <p>Each failure it recognises maps to one {@link Answer}: a status, a fixed {@code detail} and a
 * {@code Retry-After}. The M7 design, section 8, has the table.
 */
@Component
@Order(-2)
public class GlobalErrorWebExceptionHandler extends AbstractErrorWebExceptionHandler {

    /** AuthCore's key set could not be fetched. The M7 design, section 4. */
    public static final String KEYS_UNAVAILABLE = "KEYS_UNAVAILABLE";
    /** A downstream did not answer within its route's response timeout. The M7 design, section 5. */
    public static final String DOWNSTREAM_TIMEOUT = "DOWNSTREAM_TIMEOUT";
    /** A downstream could not be connected to. The M7 design, section 8. */
    public static final String DOWNSTREAM_UNREACHABLE = "DOWNSTREAM_UNREACHABLE";

    public GlobalErrorWebExceptionHandler(ErrorAttributes errorAttributes,
                                          WebProperties webProperties,
                                          ApplicationContext applicationContext,
                                          ServerCodecConfigurer codecConfigurer) {
        super(errorAttributes, webProperties.getResources(), applicationContext);
        setMessageWriters(codecConfigurer.getWriters());
        setMessageReaders(codecConfigurer.getReaders());
    }

    /** What the caller is told: status, the fixed {@code detail} if any, and {@code Retry-After} if any. */
    record Answer(HttpStatus status, @Nullable String detail, @Nullable String retryAfter) {
    }

    @Override
    protected RouterFunction<ServerResponse> getRoutingFunction(ErrorAttributes errorAttributes) {
        return RouterFunctions.route(RequestPredicates.all(), this::render);
    }

    private Mono<ServerResponse> render(ServerRequest request) {
        Throwable error = getError(request);
        Answer answer = answerFor(request, error);

        ServerResponse.BodyBuilder builder = ServerResponse.status(answer.status())
                .contentType(MediaType.APPLICATION_JSON);

        if (answer.status() == HttpStatus.UNAUTHORIZED) {
            // RFC 6750 requires it on a 401 from a bearer-token resource. Not unconditional: a 503
            // or 404 carrying WWW-Authenticate would be wrong and confusing.
            builder = builder.header(HttpHeaders.WWW_AUTHENTICATE, "Bearer");
        }
        if (answer.retryAfter() != null) {
            builder = builder.header(HttpHeaders.RETRY_AFTER, answer.retryAfter());
        }
        return builder.bodyValue(ErrorBody.of(answer.status(), request.path(), answer.detail()));
    }

    /**
     * Several failures reach here as raw exceptions rather than anything Spring Security or Boot
     * recognises, and each would otherwise read as a server fault.
     *
     * <p>A claim carrying a control character arrives as {@code IllegalArgumentException("Validation
     * failed for header '...'", ...)} from Netty's header validation, thrown inside the gateway's own
     * routing filter when it copies the stamped header onto the outbound request. The gateway cannot
     * establish who the caller is, so it refuses the credential: 401. The match is on type and the
     * fixed part of the message, deliberately narrower than any {@code IllegalArgumentException}: a
     * blanket catch would relabel an unrelated bug as an authentication failure, and a 401 is not
     * paged on the way a 500 is.
     *
     * <p>An unreachable key set arrives as {@code IllegalStateException("Could not obtain the keys",
     * ...)} from the remote key source, matched the same narrow way. Until M7 it was a 401, so as not to
     * advertise that the identity provider was down. Since M7 it is 503 {@link #KEYS_UNAVAILABLE}, like
     * the two other "a dependency could not answer" cases: the token is very likely valid, and a 401
     * would send the caller to discard it and refresh it against the very AuthCore that is unreachable
     * (the M7 design, section 4).
     *
     * <p>{@link IntrospectionUnavailableException} and {@link RevocationUnavailableException} get bare
     * type matches, with no message narrowing: each is a type this gateway declares for itself and
     * throws from exactly one place for exactly one reason, so there is no ambient use of it an
     * unrelated bug could collide with. Both are 503 — see their own Javadoc for why.
     *
     * <p>A downstream that exceeds its route's response timeout is 504 {@link #DOWNSTREAM_TIMEOUT}; a
     * downstream that cannot be connected to is 502 {@link #DOWNSTREAM_UNREACHABLE}. The latter is a bare
     * {@link ConnectException} match, which is safe: it covers a refused connection (Netty's
     * {@code AnnotatedConnectException}) and a connect timeout (Netty's {@code ConnectTimeoutException}),
     * both subclasses, and every other remote call in the gateway — introspection, the key set, Redis —
     * wraps its connect errors in its own exception before they could reach here.
     */
    private Answer answerFor(ServerRequest request, Throwable error) {
        if (isRejectedOutboundHeader(error)) {
            return new Answer(HttpStatus.UNAUTHORIZED, null, null);
        }
        if (isUnreachableJwks(error)) {
            return new Answer(HttpStatus.SERVICE_UNAVAILABLE, KEYS_UNAVAILABLE, "5");
        }
        if (error instanceof IntrospectionUnavailableException) {
            return new Answer(HttpStatus.SERVICE_UNAVAILABLE, null, "5");
        }
        if (error instanceof RevocationUnavailableException) {
            return new Answer(HttpStatus.SERVICE_UNAVAILABLE, RevocationUnavailableException.DETAIL, "5");
        }
        if (isDownstreamTimeout(error)) {
            return new Answer(HttpStatus.GATEWAY_TIMEOUT, DOWNSTREAM_TIMEOUT, null);
        }
        if (error instanceof ConnectException) {
            return new Answer(HttpStatus.BAD_GATEWAY, DOWNSTREAM_UNREACHABLE, null);
        }

        int code = (int) getErrorAttributes(request, ErrorAttributeOptions.defaults())
                .getOrDefault("status", 500);
        HttpStatus resolved = HttpStatus.resolve(code);
        HttpStatus status = resolved != null ? resolved : HttpStatus.INTERNAL_SERVER_ERROR;
        // Any other 503 still tells the caller it is worth retrying.
        return new Answer(status, null, status == HttpStatus.SERVICE_UNAVAILABLE ? "5" : null);
    }

    /**
     * Spring Cloud Gateway's routing filter, when a downstream exceeds the route's response timeout:
     * a 504 {@code ResponseStatusException} caused by the gateway's own {@code TimeoutException}
     * (verified in 5.0.2). Matched on both, so a 504 raised for another reason is not relabelled.
     */
    private static boolean isDownstreamTimeout(Throwable error) {
        return error instanceof ResponseStatusException status
                && status.getStatusCode().value() == HttpStatus.GATEWAY_TIMEOUT.value()
                && status.getCause() instanceof org.springframework.cloud.gateway.support.TimeoutException;
    }

    /**
     * {@code NimbusReactiveJwtDecoder}'s fixed message when the key-set fetch fails for any reason —
     * refused, timed out, a non-2xx response, or malformed JSON. All of these surface through the same
     * unconditional {@code onErrorMap} wrapping the fetch (verified in Spring Security 7.0.6, including
     * for M7's connect and response timeouts), so the message carries no variable text and an exact
     * match is safe.
     */
    private static boolean isUnreachableJwks(Throwable error) {
        return error instanceof IllegalStateException
                && "Could not obtain the keys".equals(error.getMessage());
    }

    /**
     * Netty's {@code DefaultHeaders.validateValue} message when a header value fails
     * validation, prefix-matched because the message interpolates the header name.
     */
    private static boolean isRejectedOutboundHeader(Throwable error) {
        return error instanceof IllegalArgumentException
                && error.getMessage() != null
                && error.getMessage().startsWith("Validation failed for header");
    }
}
