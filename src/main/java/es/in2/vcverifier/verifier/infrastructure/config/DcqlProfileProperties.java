package es.in2.vcverifier.verifier.infrastructure.config;

import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.List;
import java.util.Map;

@Validated
@ConfigurationProperties(prefix = "verifier.dcql")
public record DcqlProfileProperties(
        Map<String, DcqlProfile> profiles
) {

    public record DcqlProfile(
            List<CredentialEntry> credentials
    ) {}

    public record CredentialEntry(
            String id,
            String format,
            CredentialMeta meta
    ) {}

    public record CredentialMeta(
            List<String> vctValues,
            CredentialDefinition credentialDefinition
    ) {}

    public record CredentialDefinition(
            List<String> type
    ) {}
}
