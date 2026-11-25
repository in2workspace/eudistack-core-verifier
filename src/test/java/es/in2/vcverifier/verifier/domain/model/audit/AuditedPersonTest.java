package es.in2.vcverifier.verifier.domain.model.audit;

import es.in2.vcverifier.shared.domain.model.CertificateIdentity;
import org.junit.jupiter.api.Test;

import java.util.HashMap;
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
    void identityClaims_null_isEmpty() {
        assertThat(AuditedPerson.identityClaims(null)).isEmpty();
    }

    @Test
    void toString_isRedacted() {
        assertThat(new AuditedPerson("12345678Z", "Jose", "jose@example.com").toString())
                .doesNotContain("12345678Z", "Jose", "jose@example.com");
    }
}
