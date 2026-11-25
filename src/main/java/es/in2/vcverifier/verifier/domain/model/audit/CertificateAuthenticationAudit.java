package es.in2.vcverifier.verifier.domain.model.audit;

import es.in2.vcverifier.shared.domain.model.AssuranceLevel;
import es.in2.vcverifier.shared.domain.model.ClientCertificate;
import es.in2.vcverifier.shared.domain.model.audit.AuditResult;
import es.in2.vcverifier.verifier.domain.model.CertificateLoginReason;

import java.util.Objects;

public record CertificateAuthenticationAudit(
        String tenant,
        String correlationId,
        String oidcClientId,
        CertificateLoginReason reason,
        String certificateIssuer,
        String certificateFingerprint,
        AssuranceLevel assuranceLevel,
        String amr,
        AuditedPerson holder
) {

    public CertificateAuthenticationAudit {
        Objects.requireNonNull(oidcClientId, "oidcClientId");
        Objects.requireNonNull(correlationId, "correlationId");
        if (reason == CertificateLoginReason.LOGIN_NOT_FOUND || reason == CertificateLoginReason.INTERNAL_ERROR) {
            throw new IllegalArgumentException("No CertificateAuthentication for " + reason.value());
        }
    }

    public static CertificateAuthenticationAudit success(String tenant, String correlationId, String oidcClientId,
                                                         ClientCertificate certificate, AssuranceLevel level,
                                                         String amr, AuditedPerson holder) {
        Objects.requireNonNull(certificate, "certificate");
        Objects.requireNonNull(level, "level");
        Objects.requireNonNull(holder, "holder");
        return new CertificateAuthenticationAudit(tenant, correlationId, oidcClientId, null,
                certificate.issuer(), certificate.fingerprintSha256(), level, amr, holder);
    }

    public static CertificateAuthenticationAudit rejected(String tenant, String correlationId, String oidcClientId,
                                                          CertificateLoginReason reason, ClientCertificate certificate) {
        Objects.requireNonNull(reason, "reason");
        return new CertificateAuthenticationAudit(tenant, correlationId, oidcClientId, reason,
                certificate == null ? null : certificate.issuer(),
                certificate == null ? null : certificate.fingerprintSha256(),
                null, null, null);
    }

    public AuditResult result() {
        if (reason == null) {
            return AuditResult.SUCCESS;
        }
        return reason == CertificateLoginReason.VALIDATION_UNAVAILABLE ? AuditResult.FAILURE : AuditResult.DENIED;
    }

    @Override
    public String toString() {
        return "CertificateAuthenticationAudit[clientId=" + oidcClientId + ", result=" + result()
                + ", reason=" + (reason == null ? null : reason.value()) + "]";
    }
}
