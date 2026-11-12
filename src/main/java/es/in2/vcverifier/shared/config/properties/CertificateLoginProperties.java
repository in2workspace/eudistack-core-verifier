package es.in2.vcverifier.shared.config.properties;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.hibernate.validator.constraints.URL;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.Map;

@Validated
@ConfigurationProperties(prefix = "verifier.certificate-login")
public record CertificateLoginProperties(
        String secureOrigin,
        Map<String, @Valid Tenant> tenants
) {

    public static final int MIN_SECURE_ORIGIN_LENGTH = 32;
    public static final String SECURE_ORIGIN_VARIABLE = "VERIFIER_CERTIFICATELOGIN_SECUREORIGIN";

    public CertificateLoginProperties {
        tenants = tenants == null ? Map.of() : Map.copyOf(tenants);
        if (!tenants.isEmpty() && (secureOrigin == null || secureOrigin.length() < MIN_SECURE_ORIGIN_LENGTH)) {
            throw new IllegalStateException("Certificate login is configured for tenants " + tenants.keySet()
                    + " but " + SECURE_ORIGIN_VARIABLE + " is missing or shorter than "
                    + MIN_SECURE_ORIGIN_LENGTH + " characters");
        }
    }

    public record Tenant(
            @NotBlank @URL String loginOrigin
    ) {}
}
