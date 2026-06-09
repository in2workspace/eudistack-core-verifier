package es.in2.vcverifier.sso.domain.port;

import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;

public interface SsoAuditPort {

    /**
     * Registra un evento de auditoría de SSO.
     * @param event
     */
    void publish(SsoAuditEvent event);

}
