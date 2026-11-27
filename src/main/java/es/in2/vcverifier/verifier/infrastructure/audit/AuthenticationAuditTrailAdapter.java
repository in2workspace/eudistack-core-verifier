package es.in2.vcverifier.verifier.infrastructure.audit;

import es.in2.vcverifier.shared.config.TenantDomainFilter;
import es.in2.vcverifier.shared.domain.model.audit.AuditEntry;
import es.in2.vcverifier.shared.domain.model.audit.AuditEventType;
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
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.util.function.Supplier;

import static es.in2.vcverifier.shared.domain.model.audit.AuditEventType.CERTIFICATE_AUTHENTICATION;
import static es.in2.vcverifier.shared.domain.model.audit.AuditEventType.IAM_SESSION_ESTABLISHED;
import static es.in2.vcverifier.shared.domain.util.LogSanitizer.sanitize;

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
            log.warn("event=authentication_audit_throttled event_type={} tenant={} clientId={} reason={} correlation_id={}",
                    CERTIFICATE_AUTHENTICATION.catalogName(), sanitize(event.tenant()), sanitize(event.oidcClientId()),
                    event.reason().value(), event.correlationId());
            return;
        }
        stage(CERTIFICATE_AUTHENTICATION, () -> AuthenticationAuditEntries.of(event));
    }

    @Override
    public void iamSessionEstablished(IamSessionAudit event) {
        logger.iamSessionEstablished(event);
        String requestTenant = requestTenant();
        if (event.tenant() != null && requestTenant != null && !event.tenant().equals(requestTenant)) {
            log.warn("event=authentication_audit_tenant_mismatch event_type={} client_tenant={} request_tenant={} "
                            + "clientId={} correlation_id={}",
                    IAM_SESSION_ESTABLISHED.catalogName(), sanitize(event.tenant()), sanitize(requestTenant),
                    sanitize(event.oidcClientId()), event.correlationId());
            return;
        }
        stage(IAM_SESSION_ESTABLISHED, () -> AuthenticationAuditEntries.of(event));
    }

    private static String requestTenant() {
        if (RequestContextHolder.getRequestAttributes() instanceof ServletRequestAttributes attributes) {
            return TenantDomainFilter.getCurrentTenant(attributes.getRequest());
        }
        return null;
    }

    private void stage(AuditEventType type, Supplier<AuditEntry> entry) {
        try {
            auditTrail.stageBestEffort(entry.get());
        } catch (RuntimeException e) {
            log.warn("event=authentication_audit_stage_failed event_type={} error={}",
                    type.catalogName(), e.getClass().getSimpleName());
        }
    }
}
