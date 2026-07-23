package es.in2.vcverifier.sso.domain.model;

/**
 * Value object que identifica el destino de una notificación de Single Logout (US-06):
 * un aplicativo callee del tenant con {@code backchannel_logout_uri} declarado.
 * <p>
 * Solo se construye cuando el callee tiene canal declarado; la ausencia de canal
 * (skip, AC-04) se resuelve antes de crear un {@code LogoutTarget}, no dentro de este VO.
 */
public record LogoutTarget(String clientId, String backchannelLogoutUri) {

    public LogoutTarget {
        if (clientId == null || clientId.isBlank()) {
            throw new IllegalArgumentException("LogoutTarget.clientId must not be blank");
        }
        if (backchannelLogoutUri == null || backchannelLogoutUri.isBlank()) {
            throw new IllegalArgumentException("LogoutTarget.backchannelLogoutUri must not be blank");
        }
    }

    public static LogoutTarget of(String clientId, String backchannelLogoutUri) {
        return new LogoutTarget(clientId, backchannelLogoutUri);
    }
}