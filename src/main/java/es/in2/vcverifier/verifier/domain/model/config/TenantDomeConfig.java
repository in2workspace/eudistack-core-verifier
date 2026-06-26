package es.in2.vcverifier.verifier.domain.model.config;

public record TenantDomeConfig(
        boolean legacyReadEnabled,
        boolean bumpedReadEnabled
) {
}
