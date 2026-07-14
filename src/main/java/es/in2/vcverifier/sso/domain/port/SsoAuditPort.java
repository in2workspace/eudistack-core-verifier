package es.in2.vcverifier.sso.domain.port;

import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;

public interface SsoAuditPort {

    /**
     * Records an SSO audit event.
     * @param event
     */
    void publish(SsoAuditEvent event);

}
