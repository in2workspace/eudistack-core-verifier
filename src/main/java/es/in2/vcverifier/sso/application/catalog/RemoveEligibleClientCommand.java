package es.in2.vcverifier.sso.application.catalog;

/**
 * Comando de entrada para eliminar un cliente del catálogo SSO de un tenant.
 *
 * {@code tenant} se obtiene del contexto autenticado (Authentication / TenantDomainFilter),
 * nunca de un campo libre en el cuerpo de la petición.
 */
public record RemoveEligibleClientCommand(
        String tenant,
        String clientId
) {}
