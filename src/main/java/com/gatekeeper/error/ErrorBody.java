package com.gatekeeper.error;

import org.springframework.http.HttpStatus;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;

/**
 * The one JSON error shape the platform renders for a refused or failed request, shared by
 * {@link GlobalErrorWebExceptionHandler} (exceptions that reach the WebFlux error-handling
 * layer) and {@link JsonServerAuthenticationEntryPoint} (the 401 Spring Security commits
 * directly, before an exception would ever reach that handler).
 *
 * <p>Two call sites building the same shape independently is exactly how it drifts apart
 * over time, so the construction lives in one place.
 */
final class ErrorBody {

    private ErrorBody() {
    }

    static Map<String, Object> of(HttpStatus status, String path) {
        Map<String, Object> body = new LinkedHashMap<>();
        body.put("error", status.getReasonPhrase().toLowerCase(Locale.ROOT).replace(' ', '_'));
        body.put("status", status.value());
        body.put("path", path);
        return body;
    }
}
