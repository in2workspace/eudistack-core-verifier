package es.in2.vcverifier.sso.domain.port;

import es.in2.vcverifier.sso.domain.model.SsoEligibleClient;

import java.util.List;

public interface SsoCatalogRepositoryPort {

    /**
     * Devuelve todos los clientes del catálogo SSO del tenant.
     * Lista vacía si el tenant no tiene ninguno registrado.
     */
    List<SsoEligibleClient> listClients(String tenant);

    /**
     * Añade el cliente al catálogo del tenant si no existe (idempotente, EC-04).
     *
     * @return true si fue añadido; false si ya existía (no-op).
     */
    boolean addIfAbsent(String tenant, SsoEligibleClient client);

    /**
     * Elimina el cliente del catálogo del tenant si existe (idempotente).
     *
     * @return true si fue eliminado; false si no existía (no-op).
     */
    boolean removeIfPresent(String tenant, SsoEligibleClient client);
}
