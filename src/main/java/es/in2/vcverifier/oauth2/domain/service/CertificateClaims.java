package es.in2.vcverifier.oauth2.domain.service;

import es.in2.vcverifier.shared.domain.model.CertificateIdentity;
import org.springframework.security.oauth2.core.oidc.OidcScopes;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

public final class CertificateClaims {

    public static final String PERSONAL_ADMINISTRATIVE_NUMBER = "personal_administrative_number";

    private static final String NUMBER_SEPARATOR = " - ";

    private CertificateClaims() {
    }

    public static Map<String, Object> forScopes(CertificateIdentity identity, Collection<String> scopes) {
        Map<String, Object> claims = new LinkedHashMap<>();
        if (scopes.contains(OidcScopes.PROFILE)) {
            putIfPresent(claims, StandardClaimNames.GIVEN_NAME, identity.givenName());
            putIfPresent(claims, StandardClaimNames.FAMILY_NAME, identity.surname());
            putIfPresent(claims, StandardClaimNames.NAME, displayName(identity));
        }
        if (scopes.contains(OidcScopes.EMAIL)) {
            putIfPresent(claims, StandardClaimNames.EMAIL, identity.email());
        }
        if (scopes.contains(PERSONAL_ADMINISTRATIVE_NUMBER)) {
            putIfPresent(claims, PERSONAL_ADMINISTRATIVE_NUMBER, identity.personalAdministrativeNumber());
        }
        return claims;
    }

    private static String displayName(CertificateIdentity identity) {
        if (hasText(identity.givenName()) && hasText(identity.surname())) {
            return identity.givenName() + " " + identity.surname();
        }
        return withoutNumber(identity.commonName(), identity.personalAdministrativeNumber());
    }

    private static String withoutNumber(String commonName, String number) {
        if (commonName == null || number == null) {
            return commonName;
        }
        int separator = commonName.lastIndexOf(NUMBER_SEPARATOR);
        if (separator < 0 || !commonName.substring(separator).contains(number)) {
            return commonName;
        }
        return commonName.substring(0, separator).trim();
    }

    private static boolean hasText(String value) {
        return value != null && !value.isBlank();
    }

    private static void putIfPresent(Map<String, Object> claims, String name, String value) {
        if (hasText(value)) {
            claims.put(name, value);
        }
    }
}
