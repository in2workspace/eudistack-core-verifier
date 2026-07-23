package es.in2.vcverifier.sso.application.command;

import es.in2.vcverifier.sso.domain.model.SsoSessionId;

/**
 * Comando de entrada de {@code TerminateSsoSessionWorkflow} (US-06, Single Logout).
 *
 * @param tenant             tenant resuelto por {@code TenantDomainFilter}
 * @param sessionId          identificador de la sesión SSO a terminar (de la cookie)
 * @param initiatorClientId  client_id del aplicativo que inició el RP-Initiated Logout
 * @param correlationId      identificador de correlación para trazabilidad de auditoría
 * @param holderHash         AC-06: {@code holder_hash} de la sesión terminada (resuelto por
 *                            {@code SsoSessionLogoutHandler} antes de invocar el workflow).
 *                            Nullable si la sesión no se pudo resolver (p. ej. ya ausente).
 */
public record TerminateSsoSessionCommand(
        String tenant,
        SsoSessionId sessionId,
        String initiatorClientId,
        String correlationId,
        String holderHash
) {}
