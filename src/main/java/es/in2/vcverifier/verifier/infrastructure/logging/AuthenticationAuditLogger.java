package es.in2.vcverifier.verifier.infrastructure.logging;

import es.in2.vcverifier.shared.domain.model.audit.AuditResult;
import es.in2.vcverifier.verifier.domain.model.audit.CertificateAuthenticationAudit;
import es.in2.vcverifier.verifier.domain.model.audit.IamSessionAudit;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class AuthenticationAuditLogger {

    static final String CERTIFICATE_AUTHENTICATION = "CertificateAuthentication";
    static final String IAM_SESSION_ESTABLISHED = "IamSessionEstablished";
    private static final String NONE = "-";

    public void certificateAuthentication(CertificateAuthenticationAudit event) {
        write(CERTIFICATE_AUTHENTICATION, event.correlationId(), event.result(),
                event.reason() == null ? null : event.reason().value());
    }

    public void iamSessionEstablished(IamSessionAudit event) {
        write(IAM_SESSION_ESTABLISHED, event.correlationId(), event.result(), event.reason());
    }

    private static void write(String type, String correlationId, AuditResult result, String reason) {
        log.info("event=audit event_type={} correlation_id={} result={} reason={}",
                type, correlationId, resultName(result), reason == null ? NONE : reason);
    }

    private static String resultName(AuditResult result) {
        return switch (result) {
            case SUCCESS -> "Success";
            case DENIED -> "Denied";
            case FAILURE -> "Failure";
        };
    }
}
