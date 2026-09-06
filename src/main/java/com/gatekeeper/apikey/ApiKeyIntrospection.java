package com.gatekeeper.apikey;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.time.Instant;
import java.util.Set;

/** What introspection answered, as cached. Mirrors AuthCore's response body. */
public record ApiKeyIntrospection(
        boolean active, String name, Set<String> scopes, Instant expiresAt) {

    @JsonCreator
    public ApiKeyIntrospection(
            @JsonProperty("active") boolean active,
            @JsonProperty("name") String name,
            @JsonProperty("scopes") Set<String> scopes,
            @JsonProperty("expiresAt") Instant expiresAt) {
        this.active = active;
        this.name = name;
        this.scopes = scopes == null ? Set.of() : Set.copyOf(scopes);
        this.expiresAt = expiresAt;
    }

    public static ApiKeyIntrospection inactive() {
        return new ApiKeyIntrospection(false, null, Set.of(), null);
    }
}
