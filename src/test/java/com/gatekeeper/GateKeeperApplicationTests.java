package com.gatekeeper;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.ApplicationContext;
import org.springframework.http.server.reactive.HttpHandler;
import org.springframework.security.web.server.SecurityWebFilterChain;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
class GateKeeperApplicationTests {

    @Autowired
    ApplicationContext context;

    /**
     * Asserts the application is reactive, not servlet. An {@link HttpHandler} bean exists
     * only in a WebFlux application — a Tomcat/servlet context has none. Checking for that
     * bean is stable across Boot's package reorganisations in a way that asserting on a
     * specific context class is not.
     */
    @Test
    void startsAsAReactiveApplicationOnNetty() {
        assertThat(context.getBeanNamesForType(HttpHandler.class)).isNotEmpty();
    }

    /**
     * Two chains do not conflict — Spring starts cleanly and {@code WebFilterChainProxy}
     * simply takes the first that matches, silently. A leftover test-scoped chain would
     * therefore never announce itself. This says so out loud instead.
     */
    @Test
    void onlyOneSecurityChainIsInPlay() {
        assertThat(context.getBeanNamesForType(SecurityWebFilterChain.class)).hasSize(1);
    }
}
