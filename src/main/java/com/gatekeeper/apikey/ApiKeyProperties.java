package com.gatekeeper.apikey;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "gatekeeper.api-key")
public record ApiKeyProperties(
        String introspectionUri,
        String gatewayKey,
        Duration cacheTtl,
        Duration negativeCacheTtl,
        Duration timeout) {
}
