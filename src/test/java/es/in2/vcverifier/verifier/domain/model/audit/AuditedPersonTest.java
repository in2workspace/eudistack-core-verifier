package es.in2.vcverifier.verifier.domain.model.audit;

import es.in2.vcverifier.shared.domain.model.CertificateIdentity;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class AuditedPersonTest {

    @Test
    void ofCertificateIdentity_joinsGivenNameAndSurname() {
        AuditedPerson person = AuditedPerson.of(new CertificateIdentity("JOSE ANTONIO", "GARCIA FERNANDEZ",
                "GARCIA FERNANDEZ JOSE ANTONIO - 12345678Z", "jose@example.com", "ES", "12345678Z"));

        assertThat(person).isEqualTo(new AuditedPerson("12345678Z", "JOSE ANTONIO GARCIA FERNANDEZ", "jose@example.com"));
    }

    @Test
    void ofCertificateIdentity_withoutGivenNameOrSurname_usesTheCommonName() {
        AuditedPerson person = AuditedPerson.of(new CertificateIdentity(null, null, "GARCIA FERNANDEZ JOSE ANTONIO",
                null, "ES", "12345678Z"));

        assertThat(person.name()).isEqualTo("GARCIA FERNANDEZ JOSE ANTONIO");
    }

    @Test
    void ofCertificateIdentity_null_isUnknown() {
        assertThat(AuditedPerson.of((CertificateIdentity) null)).isSameAs(AuditedPerson.UNKNOWN);
    }

    @Test
    void ofIdTokenClaims_prefersTheFullName() {
        AuditedPerson person = AuditedPerson.of(Map.<String, Object>of("personal_administrative_number", "12345678Z",
                "name", "Jose Antonio Garcia", "given_name", "Jose", "family_name", "Garcia", "email", "jose@example.com"));

        assertThat(person).isEqualTo(new AuditedPerson("12345678Z", "Jose Antonio Garcia", "jose@example.com"));
    }

    @Test
    void ofIdTokenClaims_withoutName_joinsGivenAndFamilyName() {
        AuditedPerson person = AuditedPerson.of(Map.<String, Object>of("given_name", "Jose", "family_name", "Garcia"));

        assertThat(person).isEqualTo(new AuditedPerson(null, "Jose Garcia", null));
    }

    @Test
    void ofIdTokenClaims_ignoresBlankAndNonTextValues() {
        AuditedPerson person = AuditedPerson.of(Map.<String, Object>of("personal_administrative_number", 12345678,
                "name", " ", "email", ""));

        assertThat(person).isEqualTo(new AuditedPerson(null, null, null));
    }

    @Test
    void ofIdTokenClaims_null_isUnknown() {
        assertThat(AuditedPerson.of((Map<String, Object>) null)).isSameAs(AuditedPerson.UNKNOWN);
    }

    @Test
    void identityClaims_dropProtocolClaimsAndNullValues() {
        Map<String, Object> claims = new HashMap<>(Map.of("iss", "https://verifier", "sub", "b2f1c3", "aud", "portal",
                "acr", "high", "amr", "hwk", "nonce", "n-1", "given_name", "Jose", "email", "jose@example.com"));
        claims.put("family_name", null);

        assertThat(AuditedPerson.identityClaims(claims))
                .containsOnly(Map.entry("given_name", "Jose"), Map.entry("email", "jose@example.com"));
    }

    @Test
    void identityClaims_dropTheCredentialItCameFrom() {
        Map<String, Object> claims = Map.of("given_name", "Jose", "vc_json", "{\"type\":[\"LEARCredentialEmployee\"]}",
                "vc", Map.of("type", "LEARCredentialEmployee"), "credential_type", "LEARCredentialEmployee");

        assertThat(AuditedPerson.identityClaims(claims)).containsOnly(Map.entry("given_name", "Jose"));
    }

    @Test
    void identityClaims_dropStructuredValuesSuchAsTheMandate() {
        Map<String, Object> claims = Map.of("email", "jose@example.com",
                "mandatee", Map.of("email", "jose@example.com"), "mandator", Map.of("organization", "ACME"),
                "power", List.of(Map.of("function", "Onboarding")));

        assertThat(AuditedPerson.identityClaims(claims)).containsOnly(Map.entry("email", "jose@example.com"));
    }

    @Test
    void identityClaims_keepScalarValues() {
        Map<String, Object> claims = Map.of("given_name", "Jose", "age_over_18", true, "birth_year", 1980);

        assertThat(AuditedPerson.identityClaims(claims)).containsOnly(Map.entry("given_name", "Jose"),
                Map.entry("age_over_18", true), Map.entry("birth_year", 1980));
    }

    @Test
    void identityClaims_null_isEmpty() {
        assertThat(AuditedPerson.identityClaims(null)).isEmpty();
    }

    @Test
    void toString_isRedacted() {
        assertThat(new AuditedPerson("12345678Z", "Jose", "jose@example.com").toString())
                .doesNotContain("12345678Z", "Jose", "jose@example.com");
    }
}
