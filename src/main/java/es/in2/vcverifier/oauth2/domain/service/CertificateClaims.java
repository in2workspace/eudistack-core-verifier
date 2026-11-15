package es.in2.vcverifier.oauth2.domain.service;

import es.in2.vcverifier.shared.domain.model.CertificateIdentity;

import java.util.Collection;
import java.util.LinkedHashMap;
import java.util.Map;

public final class CertificateClaims {

    public static final String PERSONAL_ADMINISTRATIVE_NUMBER = "personal_administrative_number";

    private static final String PROFILE_SCOPE = "profile";
    private static final String EMAIL_SCOPE = "email";
    private static final String GIVEN_NAME = "given_name";
    private static final String FAMILY_NAME = "family_name";
    private static final String NAME = "name";
    private static final String EMAIL = "email";

    private static final String NUMBER_SEPARATOR = " - ";

    private CertificateClaims() {
    }

    public static Map<String, Object> forScopes(CertificateIdentity identity, Collection<String> scopes) {
        Map<String, Object> claims = new LinkedHashMap<>();
        if (scopes.contains(PROFILE_SCOPE)) {
            putIfPresent(claims, GIVEN_NAME, identity.givenName());
            putIfPresent(claims, FAMILY_NAME, identity.surname());
            putIfPresent(claims, NAME, displayName(identity));
        }
        if (scopes.contains(EMAIL_SCOPE)) {
            putIfPresent(claims, EMAIL, identity.email());
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
