package es.in2.vcverifier.oauth2.domain.audit;

import es.in2.vcverifier.oauth2.domain.model.OAuth2M2MAuditEvent;
import es.in2.vcverifier.shared.domain.model.audit.AuditEntry;
import es.in2.vcverifier.shared.domain.model.audit.AuditEventType;

import java.util.Map;
import java.util.Optional;

/**
 * Builds the {@code SystemAuthenticated} entry of a system asking for a token with its attestation (M2M).
 * The Verifier already reports each of those attempts as an {@link OAuth2M2MAuditEvent} with an outcome and
 * an internal reason; this is where they become the catalogue's result and reason. An attempt whose reason
 * the catalogue does not know is not reported rather than reported under an invented one.
 */
public final class SystemAuthenticationAuditEvents {

    private static final String OUTCOME_ACCEPT = "ACCEPT";
    private static final String OUTCOME_REJECT = "REJECT";
    private static final String REASON_INVALID_ATTESTATION = "InvalidAttestation";
    private static final String REASON_ATTESTATION_REVOKED = "AttestationRevoked";
    private static final String REASON_INTERNAL_ERROR = "InternalError";

    private SystemAuthenticationAuditEvents() {
    }

    public static Optional<AuditEntry> of(OAuth2M2MAuditEvent event) {
        if (event.getClientId() == null || event.getClientId().isBlank()) {
            return Optional.empty();
        }
        String resource = "system-client:" + event.getClientId();
        Map<String, Object> details = Map.of("client_id", event.getClientId());
        if (OUTCOME_ACCEPT.equals(event.getOutcome())) {
            return Optional.of(AuditEntry.success(AuditEventType.SYSTEM_AUTHENTICATED, resource, details));
        }
        if (!OUTCOME_REJECT.equals(event.getOutcome())) {
            return Optional.empty();
        }
        return catalogueReasonOf(event.getReason())
                .map(reason -> AuditEntry.forReason(AuditEventType.SYSTEM_AUTHENTICATED, resource, reason, details));
    }

    private static Optional<String> catalogueReasonOf(String internalReason) {
        if (internalReason == null) {
            return Optional.empty();
        }
        return switch (internalReason) {
            case "credential_type_not_eligible", "invalid_proof_of_possession", "issuer_not_trusted",
                 "credential_expired", "credential_not_active", "credential_validation_failed",
                 "tenant_mismatch", "tenant_not_derivable", "request_tenant_not_derivable" ->
                    Optional.of(REASON_INVALID_ATTESTATION);
            case "credential_revoked" -> Optional.of(REASON_ATTESTATION_REVOKED);
            case "external_dependency_failure" -> Optional.of(REASON_INTERNAL_ERROR);
            default -> Optional.empty();
        };
    }
}
