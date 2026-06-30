package es.in2.vcverifier.sso.domain.model;

import java.util.Objects;

/**
 * Value Object que representa un client_id elegible para reutilización SSO.
 * Punto único de normalización (trim) y validación de formato (EC-04).
 */
public record SsoEligibleClient(String clientId) {

    public SsoEligibleClient {
        Objects.requireNonNull(clientId, "SsoEligibleClient clientId must not be null");
        clientId = clientId.trim();
        if (clientId.isEmpty()) {
            throw new IllegalArgumentException("SsoEligibleClient clientId must not be blank");
        }
    }

    public static SsoEligibleClient of(String clientId) {
        return new SsoEligibleClient(clientId);
    }
}
