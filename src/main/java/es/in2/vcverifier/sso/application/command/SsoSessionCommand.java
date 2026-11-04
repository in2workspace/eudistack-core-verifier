package es.in2.vcverifier.sso.application.command;

import es.in2.vcverifier.shared.domain.model.AuthenticationResult;

public record SsoSessionCommand(
        String tenant,
        String sub,
        String clientId,
        String correlationId,
        AuthenticationResult authentication,
        String browserSessionId
) {
    public SsoSessionCommand(String tenant, String sub, String clientId, String correlationId,
                             AuthenticationResult authentication) {
        this(tenant, sub, clientId, correlationId, authentication, null);
    }

    public SsoSessionCommand(String tenant, String sub, String clientId, String correlationId) {
        this(tenant, sub, clientId, correlationId, null, null);
    }
}