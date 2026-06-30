package es.in2.vcverifier.sso.domain.port;

import es.in2.vcverifier.sso.domain.model.SsoSession;
import es.in2.vcverifier.sso.domain.model.SsoSessionId;

import java.util.Optional;
import java.time.Instant;

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


}
