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
            CredentialMeta meta,
            List<ClaimEntry> claims
    ) {}

    public record CredentialMeta(
            List<String> vctValues,
            CredentialDefinition credentialDefinition
    ) {}

    public record CredentialDefinition(
            List<String> type
    ) {}

    /**
     * A claim constraint for a credential entry. {@code path} segments use the literal
     * string {@code "*"} to mean "match against every element of the array at this
     * position" (e.g. {@code ["mandate", "power", "*", "function"]}) — a plain string is
     * used instead of a null path segment because Spring's relaxed YAML binding does not
     * reliably preserve null elements inside a bound List.
     */
    public record ClaimEntry(
            List<String> path,
            List<String> values
    ) {}
}
