package es.in2.vcverifier.verifier.domain.port;

/**
 * Evento de negocio canónico de verificación (conv-observability §3).
 *
 * <p>El tenant NO se pasa por parámetro (a diferencia de {@code SsoMetricsPort}): ninguno de los
 * dos call sites lo recibe, y hacer que la capa {@code application} alcance el
 * {@code HttpServletRequest} rompería la disciplina hexagonal. El adaptador lo resuelve del
 * contexto de request.
 */
public interface CredentialVerificationLoggerPort {

    /** Una credencial presentada superó la verificación completa — {@code outcome=ok}. */
    void logVerifiedOk(String configurationId);

    /** Una credencial presentada no superó la verificación — {@code outcome=error}. */
    void logVerifiedError(String configurationId, Throwable error);
}
