package com.gatekeeper.apikey;

import org.junit.jupiter.api.Test;
import tools.jackson.databind.ObjectMapper;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * A plain unit test rather than folded into {@link RedisApiKeyCacheTest}: this pins what
 * {@link ApiKeyIntrospection}'s constructor does with a specific wire shape, which is a
 * property of the record itself and needs neither a Spring context nor Redis.
 */
class ApiKeyIntrospectionTest {

    final ObjectMapper objectMapper = new ObjectMapper();

    /**
     * AuthCore's response record is {@code @JsonInclude(NON_NULL)} and its {@code inactive()}
     * factory passes {@code scopes = null}, so the real body for an unknown, disabled, or
     * expired key is exactly {@code {"active":false}} — the {@code scopes} field is absent
     * entirely, not present-and-null. Every test elsewhere in this suite constructs
     * {@link ApiKeyIntrospection} directly with a non-null set, so none of them would catch a
     * regression in that default. It matters because Task 10's manager calls
     * {@code .scopes().contains(...)} with no null check.
     */
    @Test
    void defaultsScopesToEmptyWhenAbsentFromTheWireBody() {
        ApiKeyIntrospection introspection =
                objectMapper.readValue("{\"active\":false}", ApiKeyIntrospection.class);

        assertThat(introspection.scopes()).isNotNull().isEmpty();
    }
}
