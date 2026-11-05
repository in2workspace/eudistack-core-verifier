package es.in2.vcverifier.shared.config.properties;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;
import org.hibernate.validator.constraints.URL;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.Map;
import java.util.Optional;

@Validated
@ConfigurationProperties(prefix = "verifier.certificate-login")
public record CertificateLoginProperties(
        Integer port,
        Map<String, @Valid Tenant> tenants
) {

    public static final int DEFAULT_PORT = 8081;

    public CertificateLoginProperties {
        port = port == null ? DEFAULT_PORT : port;
        tenants = tenants == null ? Map.of() : Map.copyOf(tenants);
    }

    public Optional<String> tenantForHost(String host) {
        if (host == null) {
            return Optional.empty();
        }
        return tenants.entrySet().stream()
                .filter(entry -> entry.getValue().host().equalsIgnoreCase(host))
                .map(Map.Entry::getKey)
                .findFirst();
    }

    public record Tenant(
            @NotBlank String host,
            @NotBlank @URL String loginOrigin
    ) {}
}
