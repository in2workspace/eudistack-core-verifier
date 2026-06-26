package es.in2.vcverifier.shared.config.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "verifier.dome")
public record TenantDomeConfigProperties(
        Boolean legacyReadEnabled,
        Boolean bumpedReadEnabled
) {
    public boolean legacyReadEnabledOrDefault() {
        return legacyReadEnabled == null || legacyReadEnabled;
    }

    public boolean bumpedReadEnabledOrDefault() {
        return bumpedReadEnabled == null || bumpedReadEnabled;
    }
}
