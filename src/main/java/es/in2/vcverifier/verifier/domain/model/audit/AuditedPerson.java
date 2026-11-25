package es.in2.vcverifier.verifier.domain.model.audit;

import es.in2.vcverifier.shared.domain.model.CertificateIdentity;

import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

public record AuditedPerson(String identifier, String name, String email) {

    public static final AuditedPerson UNKNOWN = new AuditedPerson(null, null, null);

    private static final String PERSONAL_ADMINISTRATIVE_NUMBER_CLAIM = "personal_administrative_number";
    private static final String NAME_CLAIM = "name";
    private static final String GIVEN_NAME_CLAIM = "given_name";
    private static final String FAMILY_NAME_CLAIM = "family_name";
    private static final String EMAIL_CLAIM = "email";
    private static final Set<String> PROTOCOL_CLAIMS = Set.of("iss", "sub", "aud", "exp", "iat", "nbf", "jti",
            "nonce", "auth_time", "acr", "amr", "sid", "azp", "at_hash", "c_hash", "scope", "client_id");
    private static final Set<String> CREDENTIAL_CLAIMS = Set.of("vc_json", "vc", "credential_type");

    public static AuditedPerson of(CertificateIdentity identity) {
        if (identity == null) {
            return UNKNOWN;
        }
        String name = joined(identity.givenName(), identity.surname());
        return new AuditedPerson(identity.personalAdministrativeNumber(),
                name == null ? identity.commonName() : name, identity.email());
    }

    public static AuditedPerson of(Map<String, Object> idTokenClaims) {
        if (idTokenClaims == null) {
            return UNKNOWN;
        }
        String name = text(idTokenClaims.get(NAME_CLAIM));
        return new AuditedPerson(text(idTokenClaims.get(PERSONAL_ADMINISTRATIVE_NUMBER_CLAIM)),
                name == null ? joined(text(idTokenClaims.get(GIVEN_NAME_CLAIM)), text(idTokenClaims.get(FAMILY_NAME_CLAIM))) : name,
                text(idTokenClaims.get(EMAIL_CLAIM)));
    }

    public static Map<String, Object> identityClaims(Map<String, Object> idTokenClaims) {
        if (idTokenClaims == null) {
            return Map.of();
        }
        return idTokenClaims.entrySet().stream()
                .filter(claim -> isIdentityValue(claim.getValue())
                        && !PROTOCOL_CLAIMS.contains(claim.getKey())
                        && !CREDENTIAL_CLAIMS.contains(claim.getKey()))
                .collect(Collectors.toUnmodifiableMap(Map.Entry::getKey, Map.Entry::getValue));
    }

    private static boolean isIdentityValue(Object value) {
        return value instanceof String || value instanceof Number || value instanceof Boolean;
    }

    private static String joined(String first, String second) {
        String value = ((first == null ? "" : first) + " " + (second == null ? "" : second)).trim();
        return value.isEmpty() ? null : value;
    }

    private static String text(Object value) {
        return value instanceof String string && !string.isBlank() ? string : null;
    }

    @Override
    public String toString() {
        return "AuditedPerson[redacted]";
    }
}
