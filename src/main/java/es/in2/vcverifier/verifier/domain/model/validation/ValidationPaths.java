package es.in2.vcverifier.verifier.domain.model.validation;

public record ValidationPaths(
        String validFromPath,
        String validUntilPath,
        RevocationPaths revocation
) {}
