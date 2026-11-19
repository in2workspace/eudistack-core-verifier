package es.in2.vcverifier.verifier.domain.model.audit;

import es.in2.vcverifier.shared.domain.model.SessionOrigin;
import es.in2.vcverifier.shared.domain.model.audit.AuditResult;

import java.util.Map;
import java.util.Objects;

public record IamSessionAudit(
        String tenant,
        String correlationId,
        String oidcClientId,
        SessionOrigin sessionOrigin,
        AuditResult result,
        AuditedPerson holder,
        Map<String, Object> identityClaims
) {

    public static final String TOKEN_ISSUANCE_FAILED = "TokenIssuanceFailed";

    public IamSessionAudit {
        Objects.requireNonNull(correlationId, "correlationId");
        Objects.requireNonNull(oidcClientId, "oidcClientId");
        Objects.requireNonNull(sessionOrigin, "sessionOrigin");
        Objects.requireNonNull(holder, "holder");
        if (result != AuditResult.SUCCESS && result != AuditResult.FAILURE) {
            throw new IllegalArgumentException("IamSessionEstablished is Success or Failure");
        }
        identityClaims = result != AuditResult.SUCCESS ? null
                : identityClaims == null ? Map.of() : Map.copyOf(identityClaims);
    }

    public String reason() {
        return result == AuditResult.FAILURE ? TOKEN_ISSUANCE_FAILED : null;
    }

    @Override
    public String toString() {
        return "IamSessionAudit[clientId=" + oidcClientId + ", origin=" + sessionOrigin + ", result=" + result + "]";
    }
}
