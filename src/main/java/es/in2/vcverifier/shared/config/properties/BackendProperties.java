package es.in2.vcverifier.shared.config.properties;

import jakarta.validation.constraints.NotBlank;
import org.hibernate.validator.constraints.URL;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "verifier.backend")
public record BackendProperties(
        @NotBlank @URL String url,
        Identity identity,
        LocalFiles localFiles,
        TokenExpiration tokenExpiration
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
            if (accessTokenSeconds <= 0) {
                accessTokenSeconds = 900;
            }
            if (idTokenSeconds <= 0) {
                idTokenSeconds = 60;
            }
            if (refreshTokenSeconds <= 0) {
                refreshTokenSeconds = 43200;
            }
        }
    }

    /**
     * Optional external filesystem paths. When set, the corresponding local provider
     * reads from the filesystem instead of the classpath, allowing injection via
     * Docker volumes, Kubernetes ConfigMaps, etc.
     */
    public record LocalFiles(
            String clientsPath,
            String trustedIssuersPath,
            String schemasDir
    ) {}
}
