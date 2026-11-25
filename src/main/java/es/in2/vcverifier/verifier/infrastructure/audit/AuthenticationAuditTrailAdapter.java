package es.in2.vcverifier.verifier.infrastructure.audit;

import es.in2.vcverifier.shared.domain.model.audit.AuditEntry;
import es.in2.vcverifier.shared.domain.model.audit.AuditResult;
import es.in2.vcverifier.shared.domain.port.AuditTrailPort;
import es.in2.vcverifier.shared.infrastructure.audit.RejectionThrottle;
import es.in2.vcverifier.verifier.domain.model.audit.AuthenticationAuditEntries;
import es.in2.vcverifier.verifier.domain.model.audit.CertificateAuthenticationAudit;
import es.in2.vcverifier.verifier.domain.model.audit.IamSessionAudit;
import es.in2.vcverifier.verifier.domain.port.AuthenticationAuditPort;
import es.in2.vcverifier.verifier.infrastructure.logging.AuthenticationAuditLogger;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
@RequiredArgsConstructor
public class AuthenticationAuditTrailAdapter implements AuthenticationAuditPort {

    private final AuthenticationAuditLogger logger;
    private final AuditTrailPort auditTrail;
    private final RejectionThrottle rejectionThrottle = new RejectionThrottle();

    @Override
    public void certificateAuthentication(CertificateAuthenticationAudit event) {
        logger.certificateAuthentication(event);
        if (event.result() != AuditResult.SUCCESS
                && !rejectionThrottle.allow(event.tenant() + "|" + event.oidcClientId() + "|" + event.reason().value())) {
            return;
        }
        stage(AuthenticationAuditEntries.of(event));
    }

    @Override
    public void iamSessionEstablished(IamSessionAudit event) {
        logger.iamSessionEstablished(event);
        stage(AuthenticationAuditEntries.of(event));
    }

    private void stage(AuditEntry entry) {
        try {
            auditTrail.stageBestEffort(entry);
        } catch (RuntimeException e) {
            log.warn("event=authentication_audit_stage_failed event_type={} error={}",
                    entry.type().catalogName(), e.getClass().getSimpleName());
        }
    }
}
