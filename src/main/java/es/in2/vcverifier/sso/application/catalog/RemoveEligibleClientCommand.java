package es.in2.vcverifier.sso.application.catalog;

/**
 * Comando de entrada para eliminar un cliente del catálogo SSO del tenant.
 *
 * <p>{@code tenant} debe poblarse desde el contexto autenticado (principal),
 * nunca desde un campo libre de la petición HTTP, para evitar escalada de privilegios
 * entre tenants.
 */
public record RemoveEligibleClientCommand(
        String tenant,
        String clientId
) {

    public RemoveEligibleClientCommand {
        if (tenant == null || tenant.isBlank()) {
            throw new IllegalArgumentException("RemoveEligibleClientCommand.tenant must not be blank");
        }
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalArgumentException("RemoveEligibleClientCommand.clientId must not be blank");
        }
        tenant   = tenant.trim();
        clientId = clientId.trim();
    }
}
