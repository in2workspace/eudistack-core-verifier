package es.in2.vcverifier.sso.domain.port;

import es.in2.vcverifier.sso.domain.model.SsoSession;
import java.util.Optional;

public interface SsoSessionRepositoryPort {

    /**
     * Persiste el aggregate completo
     * @param session
     * @return
     */
    SsoSession save(SsoSession session);


    /**
     * Obtiene una sesión activa para un tentant y holder concreto.
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



}
