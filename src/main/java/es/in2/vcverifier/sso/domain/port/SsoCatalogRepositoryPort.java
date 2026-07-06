package es.in2.vcverifier.sso.domain.port;

import es.in2.vcverifier.sso.domain.model.SsoEligibleClient;

public interface SsoCatalogRepositoryPort {

    /**
     * Añade un cliente al catálogo SSO del tenant.
     * Idempotente: si el cliente ya existe devuelve {@code false} sin duplicar.
     *
     * @return {@code true} si el cliente fue añadido, {@code false} si ya estaba presente
     */
    boolean addClient(String tenant, SsoEligibleClient client);

    /**
     * Elimina un cliente del catálogo SSO del tenant.
     * Idempotente: si el cliente no existe devuelve {@code false} sin fallar.
     *
     * @return {@code true} si el cliente fue eliminado, {@code false} si no existía
     */
    boolean removeClient(String tenant, SsoEligibleClient client);
}
