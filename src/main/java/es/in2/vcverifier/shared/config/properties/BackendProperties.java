package es.in2.vcverifier.shared.config.properties;

import jakarta.validation.Valid;
import jakarta.validation.constraints.NotBlank;

import org.hibernate.validator.constraints.URL;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.List;

@Validated
@ConfigurationProperties(prefix = "verifier.backend")
public record BackendProperties(
        @NotBlank @URL String url,
        Identity identity,
        @Valid List<TrustFramework> trustFrameworks,
        LocalFiles localFiles,
        TokenExpiration tokenExpiration,
        Long loginTimeoutSeconds,
        Boolean fapiNonceRequired,
        X5cChainValidation x5cChainValidation
) {

    public record Identity(
            String didKey,
            String privateKey,
            String certificate) {}

    public record TokenExpiration(
            long accessTokenSeconds,
            long idTokenSeconds,
            long refreshTokenSeconds
    ) {
        public TokenExpiration {
            if (accessTokenSeconds <= 0) accessTokenSeconds = 900;
            if (idTokenSeconds <= 0) idTokenSeconds = 60;
            if (refreshTokenSeconds <= 0) refreshTokenSeconds = 43200;
        }
    }

    public record TrustFramework(
            @NotBlank String name,
            String trustedIssuersListUrl,
            String trustedServicesListUrl
    ) {}

    /**
     * Secure-by-default: x5c chain validation is always active.
     * Set bypass=true only as an operational escape hatch to restore legacy leaf-only behaviour.
     * Set aiaChasing.enabled=false to disable network fetching of intermediate CA certs.
     */
    public record X5cChainValidation(Boolean bypass, AiaChasing aiaChasing) {}

    public record AiaChasing(Boolean enabled) {}

    /**
     * Optional external filesystem paths. When set, the corresponding local provider
     * reads from the filesystem instead of the classpath, allowing injection via
     * Docker volumes, Kubernetes ConfigMaps, etc.
     */
    public record LocalFiles(
            String clientsPath,
            String trustedIssuersPath,
            String schemasDir,
            String ssoConfigPath
    ) {}

    // TODO: this is temporary while VCVerifier can handle only one trustFramework
    public TrustFramework getDOMETrustFrameworkByName() {
        if (trustFrameworks == null || trustFrameworks.isEmpty()) {
            return null;
        }
        return trustFrameworks.stream()
                .filter(tf -> tf.name().equalsIgnoreCase("DOME"))
                .findFirst()
                .orElse(null);
    }
}
