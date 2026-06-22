package es.in2.vcverifier.verifier.domain.model.dispatch;

public record DispatchRule(
        String credentialConfigurationId,
        CredentialFormat format
) {
}
