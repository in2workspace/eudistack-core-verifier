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
        Map<String, @Valid Tenant> tenants
) {

    public CertificateLoginProperties {
        tenants = tenants == null ? Map.of() : Map.copyOf(tenants);
    }

    public record Tenant(
            @NotBlank String host,
            @NotBlank @URL String loginOrigin
    ) {}
}
