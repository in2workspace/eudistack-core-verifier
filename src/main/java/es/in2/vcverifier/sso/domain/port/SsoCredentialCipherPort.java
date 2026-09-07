package es.in2.vcverifier.sso.domain.port;

import java.util.Optional;

/**
 * EUD-149 production-readiness: cifra/descifra el snapshot de claims de credencial que
 * {@code EstablishSsoSessionWorkflow} persiste junto a la fila {@code sso_session}, para que
 * {@code ReuseSsoSessionWorkflowImpl} pueda emitir un {@code id_token}/code en una reutilización
 * silenciosa (sin re-presentación de VP) sin depender de una caché en memoria local a la
 * instancia — el fallo original: una reutilización que aterriza en una réplica distinta a la que
 * estableció la sesión encontraba siempre un cache miss y caía a {@code login_required} en
 * silencio, aunque la fila en Postgres siguiera {@code ACTIVE} y válida.
 * <p>
 * {@code tenant} y {@code sessionId} se usan como AAD (additional authenticated data): el
 * ciphertext queda criptográficamente atado a esa sesión y tenant concretos, así que no puede
 * descifrarse (ni siquiera con la clave correcta) si se intenta reutilizar bajo un {@code tenant}
 * o {@code sessionId} distinto — una capa de refuerzo adicional sobre el filtro {@code WHERE
 * tenant = ?} de {@code SsoSessionJdbcRepository}.
 */
public interface SsoCredentialCipherPort {

    /**
     * @param tenant tenant de la sesión (AAD).
     * @param sessionId identificador opaco de la sesión (AAD).
     * @param plaintextJson claims de la credencial verificada, serializadas como JSON.
     * @return ciphertext opaco listo para persistir en {@code sso_session.credential_snapshot}.
     */
    byte[] encrypt(String tenant, String sessionId, String plaintextJson);

    /**
     * @return el JSON en claro, o {@code Optional.empty()} si el ciphertext es {@code null},
     * está corrupto, fue cifrado con otra clave, o no corresponde a este {@code tenant}/
     * {@code sessionId} (AAD mismatch) — nunca lanza.
     */
    Optional<String> decrypt(String tenant, String sessionId, byte[] ciphertext);
}
