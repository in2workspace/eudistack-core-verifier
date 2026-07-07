package es.in2.vcverifier.sso.application.command;

import es.in2.vcverifier.sso.domain.model.SsoSessionId;

/**
 * Comando de entrada de {@code TerminateSsoSessionWorkflow} (US-06, Single Logout).
 *
 * @param tenant             tenant resuelto por {@code TenantDomainFilter}
 * @param sessionId          identificador de la sesión SSO a terminar (de la cookie)
 * @param initiatorClientId  client_id del aplicativo que inició el RP-Initiated Logout
 * @param correlationId      identificador de correlación para trazabilidad de auditoría
 */
public record TerminateSsoSessionCommand(
        String tenant,
        SsoSessionId sessionId,
        String initiatorClientId,
        String correlationId
) {}
