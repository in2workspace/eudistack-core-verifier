package es.in2.vcverifier.oauth2.domain.port;

import es.in2.vcverifier.oauth2.domain.model.OAuth2M2MAuditEvent;

public interface OAuth2M2MAuditPort {

    void publish(OAuth2M2MAuditEvent event);

}
