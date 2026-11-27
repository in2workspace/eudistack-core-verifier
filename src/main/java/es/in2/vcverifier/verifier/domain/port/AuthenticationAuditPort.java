package es.in2.vcverifier.verifier.domain.port;

import es.in2.vcverifier.verifier.domain.model.audit.CertificateAuthenticationAudit;
import es.in2.vcverifier.verifier.domain.model.audit.IamSessionAudit;

public interface AuthenticationAuditPort {

    void certificateAuthentication(CertificateAuthenticationAudit event);

    void iamSessionEstablished(IamSessionAudit event);
}
