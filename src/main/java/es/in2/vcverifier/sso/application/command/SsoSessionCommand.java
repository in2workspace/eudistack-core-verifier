package es.in2.vcverifier.sso.application.command;


public record SsoSessionCommand(
        String tenant,
        String sub,
        String clientId,
        String correlationId
) {}
