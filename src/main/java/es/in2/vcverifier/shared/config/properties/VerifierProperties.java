package es.in2.vcverifier.shared.config.properties;

import jakarta.validation.constraints.NotBlank;
import org.hibernate.validator.constraints.URL;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "verifier")
public record VerifierProperties(
        @NotBlank @URL String url,
        String portalUrl,
        Identity identity,
        Token token,
        Files files
) {

    public record Identity(
            String didKey,
            String privateKey,
            String certificate) {}

    public record Token(
            long accessTokenTtl,
            long idTokenTtl,
            long refreshTokenTtl
    ) {
        public Token {
            if (accessTokenTtl <= 0) {
                accessTokenTtl = 900;
            }
            if (idTokenTtl <= 0) {
                idTokenTtl = 60;
            }
            if (refreshTokenTtl <= 0) {
                refreshTokenTtl = 43200;
            }
        }
    }

    /**
     * Optional external filesystem paths. When set, the corresponding local provider
     * reads from the filesystem instead of the classpath, allowing injection via
     * Docker volumes, Kubernetes ConfigMaps, etc.
     */
    public record Files(
            String clients,
            String trustedIssuers,
            String schemas,
            String dcql
    ) {}
}
