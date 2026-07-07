package es.in2.vcverifier.sso.domain.port;

import es.in2.vcverifier.sso.domain.model.SsoSession;
import es.in2.vcverifier.sso.domain.model.SsoSessionId;

import java.time.Instant;
import java.util.List;
import java.util.Optional;

public interface SsoSessionRepositoryPort {

    /**
     * Persiste el aggregate completo
     * @param session
     * @return
     */
    SsoSession save(SsoSession session);


    /**
     * Obtiene una sesión activa para un tenant y holder concreto.
     * @param tenant
     * @param holderHash
     * @return
     */
    Optional<SsoSession> findActiveByTenantAndHolder(
            String tenant,
            String holderHash
    );


    /**
     * Cierra sesión activa en BD
     * @param tenant
     * @param holderHash
     */
    void supersedeActive(
            String tenant,
            String holderHash
    );

    /**
     * Obtiene una sesión activa por su identificador y tenant.
     */
    Optional<SsoSession> findActiveById(
            SsoSessionId sessionId,
            String tenant
    );

    /**
     * Actualiza el timestamp de último uso de una sesión activa.
     */
    void updateLastUsedAt(
            SsoSessionId sessionId,
            String tenant,
            Instant now
    );

    /**
     * Busca una sesión por ID sin filtro de tenant.
     * Usado exclusivamente para detectar intentos de acceso cross-tenant (AC-04).
     */
    Optional<SsoSession> findById(SsoSessionId sessionId);

    /**
     * US-06 (Single Logout) — transición idempotente {@code ACTIVE -> TERMINATED}.
     * UPDATE condicional {@code WHERE state='ACTIVE'}: devuelve el número de filas afectadas,
     * usado por el workflow para distinguir invalidación real (1) de no-op (0, EC-01:
     * sesión ya terminada o ausente).
     */
    int terminateActive(
            SsoSessionId sessionId,
            String tenant
    );

    /**
     * US-06 (Single Logout) — ADR-108: calcula los aplicativos callee a notificar por Back-Channel
     * Logout, a partir del rastreo de actividad {@code sso_session_client} clavado por sesión
     * (no por holder: hay una sola sesión activa por holder y clavar por sesión evita arrastrar
     * filas de una sesión previa superseded). Reemplaza el placeholder inicial
     * {@code findActiveClientsByTenantAndHolder}, que no tenía fuente de datos real.
     */
    List<String> findClientsBySession(
            SsoSessionId sessionId,
            String tenant
    );

    /**
     * US-06 (Single Logout) — ADR-108: registra (upsert idempotente) que {@code clientId} ha usado
     * la sesión SSO indicada. Poblado de forma aditiva por {@code EstablishSsoSessionWorkflow}
     * (US-02, iniciador) y {@code ReuseSsoSessionWorkflowImpl} (US-03, cada reutilización
     * {@code ALLOWED}). Best-effort: un fallo no debe bloquear el establecimiento/reutilización.
     */
    void recordClientActivity(
            SsoSessionId sessionId,
            String tenant,
            String clientId
    );

}
