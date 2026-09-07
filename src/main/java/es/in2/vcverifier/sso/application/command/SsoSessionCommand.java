package es.in2.vcverifier.sso.application.command;

public record SsoSessionCommand(
        String tenant,
        String sub,
        String clientId,
        String correlationId,
        // EUD-149: claims de la credencial verificada, serializadas como JSON — null si el
        // caller no tiene una credencial que snapshotear (p.ej. flujos que no ejercitan SSO).
        // EstablishSsoSessionWorkflow la cifra y persiste junto a la sesión para que una
        // reutilización silenciosa posterior pueda emitir tokens sin volver a pedirla.
        String credentialJson
) {
    public SsoSessionCommand(String tenant, String sub, String clientId, String correlationId) {
        this(tenant, sub, clientId, correlationId, null);
    }
}