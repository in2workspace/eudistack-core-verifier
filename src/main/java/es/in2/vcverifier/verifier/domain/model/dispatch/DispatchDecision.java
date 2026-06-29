package es.in2.vcverifier.verifier.domain.model.dispatch;

public record DispatchDecision(
        String credentialConfigurationId,
        CredentialFormat format,
        DispatchReason reason,
        boolean permitted
) {
    public static DispatchDecision permitted(String credentialConfigurationId, CredentialFormat format, DispatchReason reason) {
        return new DispatchDecision(credentialConfigurationId, format, reason, true);
    }

    public static DispatchDecision denied(String credentialConfigurationId, CredentialFormat format, DispatchReason reason) {
        return new DispatchDecision(credentialConfigurationId, format, reason, false);
    }
}
