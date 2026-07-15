package es.in2.vcverifier.sso.application.command;

public record RevokeTenantSessionsCommand(
        String tenantId,
        String correlationId
) {

    public RevokeTenantSessionsCommand {
        if (tenantId == null || tenantId.isBlank()) {
            throw new IllegalArgumentException("RevokeTenantSessionsCommand.tenantId must not be blank");
        }
        if (correlationId == null || correlationId.isBlank()) {
            throw new IllegalArgumentException("RevokeTenantSessionsCommand.correlationId must not be blank");
        }
        tenantId      = tenantId.trim();
        correlationId = correlationId.trim();
    }
}
