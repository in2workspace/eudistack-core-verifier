package es.in2.vcverifier.sso.domain.model;

import java.util.Collection;
import java.util.Objects;
import java.util.Set;
import java.util.stream.Collectors;

public final class TenantSsoCatalog {

    private final Set<SsoEligibleClient> clients;

    private TenantSsoCatalog(Set<SsoEligibleClient> clients) {
        this.clients = Set.copyOf(clients);
    }

    public static TenantSsoCatalog of(Collection<String> rawClientIds) {
        Objects.requireNonNull(rawClientIds, "TenantSsoCatalog rawClientIds must not be null");
        Set<SsoEligibleClient> clients = rawClientIds.stream()
                .map(SsoEligibleClient::of)
                .collect(Collectors.toSet());
        return new TenantSsoCatalog(clients);
    }

    public static TenantSsoCatalog empty() {
        return new TenantSsoCatalog(Set.of());
    }

    /** AC-03: catálogo vacío devuelve false (fail-closed). */
    public boolean contains(String clientId) {
        if (clients.isEmpty() || clientId == null || clientId.isBlank()) {
            return false;
        }
        return clients.contains(SsoEligibleClient.of(clientId));
    }

    @Override
    public boolean equals(Object o) {
        if (this == o) return true;
        if (!(o instanceof TenantSsoCatalog that)) return false;
        return clients.equals(that.clients);
    }

    @Override
    public int hashCode() {
        return Objects.hash(clients);
    }

    @Override
    public String toString() {
        return "TenantSsoCatalog{size=" + clients.size() + "}";
    }
}
