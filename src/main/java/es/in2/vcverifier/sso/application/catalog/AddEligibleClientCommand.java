package es.in2.vcverifier.sso.application.catalog;

/**
 * Comando de entrada para añadir un cliente al catálogo SSO del tenant.
 *
 * <p>{@code tenant} debe poblarse desde el contexto autenticado (principal),
 * nunca desde un campo libre de la petición HTTP, para evitar escalada de privilegios
 * entre tenants.
 */
public record AddEligibleClientCommand(
        String tenant,
        String clientId
) {

    public AddEligibleClientCommand {
        if (tenant == null || tenant.isBlank()) {
            throw new IllegalArgumentException("AddEligibleClientCommand.tenant must not be blank");
        }
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalArgumentException("AddEligibleClientCommand.clientId must not be blank");
        }
        tenant   = tenant.trim();
        clientId = clientId.trim();
    }
}
