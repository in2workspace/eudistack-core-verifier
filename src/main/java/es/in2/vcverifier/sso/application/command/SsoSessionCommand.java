package es.in2.vcverifier.sso.application.command;

import es.in2.vcverifier.shared.domain.model.AuthenticationResult;

public record SsoSessionCommand(
        String tenant,
        String sub,
        String clientId,
        String correlationId,
        AuthenticationResult authentication
) {
    public SsoSessionCommand(String tenant, String sub, String clientId, String correlationId) {
        this(tenant, sub, clientId, correlationId, null);
    }
}