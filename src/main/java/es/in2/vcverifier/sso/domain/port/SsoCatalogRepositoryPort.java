package es.in2.vcverifier.sso.domain.port;

import es.in2.vcverifier.sso.domain.model.SsoEligibleClient;

public interface SsoCatalogRepositoryPort {

    /**
     * Adds a client to the tenant's SSO catalog.
     * Idempotent: if the client already exists it returns {@code false} without duplicating.
     *
     * @return {@code true} if the client was added, {@code false} if it was already present
     */
    boolean addClient(String tenant, SsoEligibleClient client);

    /**
     * Removes a client from the tenant's SSO catalog.
     * Idempotent: if the client does not exist it returns {@code false} without failing.
     *
     * @return {@code true} if the client was removed, {@code false} if it did not exist
     */
    boolean removeClient(String tenant, SsoEligibleClient client);
}
