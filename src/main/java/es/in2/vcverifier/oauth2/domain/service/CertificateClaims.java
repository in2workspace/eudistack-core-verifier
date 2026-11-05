package es.in2.vcverifier.oauth2.domain.service;

import es.in2.vcverifier.shared.domain.model.CertificateIdentity;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

public final class CertificateClaims {

    public static final String PERSONAL_ADMINISTRATIVE_NUMBER = "personal_administrative_number";

    private CertificateClaims() {
    }

    public static Map<String, Object> forScopes(CertificateIdentity identity, Collection<String> scopes) {
        Map<String, Object> claims = new LinkedHashMap<>();
        if (scopes.contains(OidcScopes.PROFILE)) {
            putIfPresent(claims, StandardClaimNames.GIVEN_NAME, identity.givenName());
            putIfPresent(claims, StandardClaimNames.FAMILY_NAME, identity.surname());
            putIfPresent(claims, StandardClaimNames.NAME, identity.commonName());
        }
        if (scopes.contains(OidcScopes.EMAIL)) {
            putIfPresent(claims, StandardClaimNames.EMAIL, identity.email());
        }
        if (scopes.contains(PERSONAL_ADMINISTRATIVE_NUMBER)) {
            putIfPresent(claims, PERSONAL_ADMINISTRATIVE_NUMBER, identity.personalAdministrativeNumber());
        }
        return claims;
    }

    private static void putIfPresent(Map<String, Object> claims, String name, String value) {
        if (value != null && !value.isBlank()) {
            claims.put(name, value);
        }
    }
}
