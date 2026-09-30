package com.gatekeeper.error;

import org.springframework.http.HttpStatus;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * The one JSON error shape the platform renders for a refused or failed request, shared by
 * {@link GlobalErrorWebExceptionHandler} (exceptions that reach the WebFlux error-handling
 * layer), {@link JsonServerAuthenticationEntryPoint} (the 401 Spring Security commits
 * directly) and {@link JsonServerAccessDeniedHandler} (the 403 it commits the same way), and
 * {@link TooManyRequestsWriter} (the rate limiter's 429).
 *
 * <p>Four call sites building the same shape independently is exactly how it drifts apart
 * over time, so the construction lives in one place.
 *
 * <p>{@code detail} is present only when a caller supplies one — today the 403, the 429 and the revocation 503 do.
 * ledger-service's {@code ErrorBody} has the identical overload, so the two services agree on
 * the field's name and on its absence when there is nothing to say.
 */
final class ErrorBody {

    private ErrorBody() {
    }

    static Map<String, Object> of(HttpStatus status, String path) {
        return of(status, path, null);
    }

    static Map<String, Object> of(HttpStatus status, String path, String detail) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", status.getReasonPhrase().toLowerCase(Locale.ROOT).replace(' ', '_'));
        body.put("status", status.value());
        body.put("path", path);
        if (detail != null) {
            body.put("detail", detail);
        }
        return body;
    }
}
