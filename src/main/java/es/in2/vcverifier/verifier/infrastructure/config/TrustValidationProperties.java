package es.in2.vcverifier.verifier.infrastructure.config;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.time.Duration;

@ConfigurationProperties(prefix = "verifier.trust-validation")
public record TrustValidationProperties(
        String url,
        Duration timeout,
        Duration maxListAge
) {

    public static final Duration DEFAULT_TIMEOUT = Duration.ofSeconds(5);
    public static final Duration DEFAULT_MAX_LIST_AGE = Duration.ofHours(24);

    public TrustValidationProperties {
        timeout = timeout == null ? DEFAULT_TIMEOUT : timeout;
        maxListAge = maxListAge == null ? DEFAULT_MAX_LIST_AGE : maxListAge;
    }
}
