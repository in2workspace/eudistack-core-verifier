package es.in2.vcverifier.sso.domain.model;

import java.util.Collection;
import java.util.Objects;
import java.util.Optional;
import java.util.Set;

/**
 * Value object que agrupa el conjunto de clientes elegibles para SSO de un tenant.
 * AC-03 fail-closed: catálogo vacío o client_id no reconocido devuelven false en contains.
 */
public final class TenantSsoCatalog {

    private final Set<SsoEligibleClient> clients;

    private TenantSsoCatalog(Set<SsoEligibleClient> clients) {
        this.clients = Set.copyOf(clients);
    }

    public static TenantSsoCatalog of(Collection<SsoEligibleClient> clients) {
        Objects.requireNonNull(clients, "clients must not be null");
        return new TenantSsoCatalog(Set.copyOf(clients));
    }

    public static TenantSsoCatalog empty() {
        return new TenantSsoCatalog(Set.of());
    }

    /**
     * AC-03: devuelve false si el clientId es nulo, en blanco o no figura en el catálogo.
     * La normalización (trim) la aplica SsoEligibleClient.of, punto único EC-04.
     */
    public boolean contains(String clientId) {
        if (clientId == null || clientId.isBlank()) {
            return false;
        }
        return clients.contains(SsoEligibleClient.of(clientId));
    }

    /**
     * US-06 (AD-4/DELTA-01 fallback source): recupera la entrada completa (incl.
     * {@code backchannelLogoutUri}) de un client_id del catálogo. Vacío si no está presente.
     */
    public Optional<SsoEligibleClient> findByClientId(String clientId) {
        if (clientId == null || clientId.isBlank()) {
            return Optional.empty();
        }
        return clients.stream()
                .filter(c -> c.equals(SsoEligibleClient.of(clientId)))
                .findFirst();
    }

    public boolean isEmpty() {
        return clients.isEmpty();
    }

    public int size() {
        return clients.size();
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TenantSsoCatalog that)) return false;
        return Objects.equals(clients, that.clients);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clients);
    }

    @Override
    public String toString() {
        return "TenantSsoCatalog{clients=" + clients + "}";
    }
}
