package es.in2.vcverifier.verifier.domain.model.validation;

public record RevocationPaths(
        String statusIdPath,
        String statusTypePath,
        String statusPurposePath,
        String statusListCredentialPath,
        String statusListIndexPath
) {}
