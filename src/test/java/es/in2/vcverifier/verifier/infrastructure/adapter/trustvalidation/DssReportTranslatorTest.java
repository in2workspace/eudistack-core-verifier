package es.in2.vcverifier.verifier.infrastructure.adapter.trustvalidation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.vcverifier.shared.domain.model.AssuranceLevel;
import es.in2.vcverifier.verifier.domain.model.CertificateLoginReason;
import es.in2.vcverifier.verifier.domain.model.CertificateTrust;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;

import java.time.Duration;
import java.time.Instant;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;

class DssReportTranslatorTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Instant NOW = Instant.parse("2026-10-22T12:00:00Z");
    private static final Duration MAX_LIST_AGE = Duration.ofHours(24);

    @Test
    void passed_qualifiedSignatureWithQscd_isHighWithHardwareKey() {
        assertThat(translate(report("PASSED", null, "QC for eSig with QSCD"), false))
                .isEqualTo(new CertificateTrust.Trusted(AssuranceLevel.HIGH, List.of("hwk")));
    }

    @Test
    void passed_qualifiedSignatureWithoutQscd_isSubstantialWithSoftwareKey() {
        assertThat(translate(report("PASSED", null, "QC for eSig"), false))
                .isEqualTo(new CertificateTrust.Trusted(AssuranceLevel.SUBSTANTIAL, List.of("swk")));
    }

    @Test
    void passed_qualifiedSignatureWithOrganizationIdentifier_isNotANaturalPerson() {
        assertThat(translate(report("PASSED", null, "QC for eSig with QSCD"), true))
                .isEqualTo(rejected(CertificateLoginReason.CERTIFICATE_NOT_NATURAL_PERSON));
    }

    @ParameterizedTest
    @CsvSource({"QC for eSeal with QSCD", "QC for eSeal"})
    void passed_qualifiedSeal_isNotANaturalPerson(String qualification) {
        assertThat(translate(report("PASSED", null, qualification), false))
                .isEqualTo(rejected(CertificateLoginReason.CERTIFICATE_NOT_NATURAL_PERSON));
    }

    @ParameterizedTest
    @CsvSource({"QC for WSA", "Cert for eSig", "N/A", "''"})
    void passed_withoutQualifiedSignature_isNotQualified(String qualification) {
        assertThat(translate(report("PASSED", null, qualification), false))
                .isEqualTo(rejected(CertificateLoginReason.CERTIFICATE_NOT_QUALIFIED));
    }

    @ParameterizedTest
    @CsvSource({"INDETERMINATE, REVOKED_NO_POE", "INDETERMINATE, REVOKED_CA_NO_POE", "FAILED, REVOKED"})
    void revocation_isRevoked(String indication, String subIndication) {
        assertThat(translate(report(indication, subIndication, "QC for eSig with QSCD"), false))
                .isEqualTo(rejected(CertificateLoginReason.CERTIFICATE_REVOKED));
    }

    @ParameterizedTest
    @CsvSource({
            "FAILED, EXPIRED",
            "FAILED, NOT_YET_VALID",
            "INDETERMINATE, OUT_OF_BOUNDS_NO_POE",
            "INDETERMINATE, OUT_OF_BOUNDS_NOT_REVOKED"
    })
    void expiryOrFutureStart_isExpired(String indication, String subIndication) {
        assertThat(translate(report(indication, subIndication, "QC for eSig with QSCD"), false))
                .isEqualTo(rejected(CertificateLoginReason.CERTIFICATE_EXPIRED));
    }

    @Test
    void failed_forAnotherReason_isNotQualified() {
        assertThat(translate(report("FAILED", "CHAIN_CONSTRAINTS_FAILURE", "QC for eSig with QSCD"), false))
                .isEqualTo(rejected(CertificateLoginReason.CERTIFICATE_NOT_QUALIFIED));
    }

    @Test
    void indeterminate_chainReachingNoTrustedList_isNotQualified() {
        assertThat(translate(report("INDETERMINATE", "NO_CERTIFICATE_CHAIN_FOUND", "N/A"), false))
                .isEqualTo(rejected(CertificateLoginReason.CERTIFICATE_NOT_QUALIFIED));
    }

    @ParameterizedTest
    @CsvSource({"CERTIFICATE_CHAIN_GENERAL_FAILURE", "TRY_LATER", "''"})
    void indeterminate_forAnotherReason_isUnavailable(String subIndication) {
        assertThat(translate(report("INDETERMINATE", subIndication, "QC for eSig with QSCD"), false))
                .isEqualTo(rejected(CertificateLoginReason.VALIDATION_UNAVAILABLE));
    }

    @Test
    void listsLoadedMoreThan24HoursAgo_areUnavailableEvenWhenPassed() {
        ObjectNode reports = report("PASSED", null, "QC for eSig with QSCD");
        reports.putObject("diagnosticData").putArray("TrustedList")
                .add(MAPPER.createObjectNode().put("LastLoading", "2026-10-22T10:00:00Z"))
                .add(MAPPER.createObjectNode().put("LastLoading", "2026-10-21T11:59:00Z"));

        assertThat(translate(reports, false)).isEqualTo(rejected(CertificateLoginReason.VALIDATION_UNAVAILABLE));
    }

    @Test
    void listsLoadedWithinTheLast24Hours_doNotChangeTheResult() {
        ObjectNode reports = report("PASSED", null, "QC for eSig with QSCD");
        reports.putObject("diagnosticData").putArray("TrustedList")
                .add(MAPPER.createObjectNode().put("LastLoading", "2026-10-21T12:30:00Z"));

        assertThat(translate(reports, false)).isInstanceOf(CertificateTrust.Trusted.class);
    }

    @Test
    void listWithoutLastLoading_isUnavailable() {
        ObjectNode reports = report("PASSED", null, "QC for eSig with QSCD");
        reports.putObject("diagnosticData").putArray("TrustedList").add(MAPPER.createObjectNode());

        assertThat(translate(reports, false)).isEqualTo(rejected(CertificateLoginReason.VALIDATION_UNAVAILABLE));
    }

    @Test
    void reportWithoutCertificate_isUnavailable() {
        assertThat(translate(MAPPER.createObjectNode(), false))
                .isEqualTo(rejected(CertificateLoginReason.VALIDATION_UNAVAILABLE));
    }

    private static CertificateTrust translate(JsonNode reports, boolean organizationIdentifier) {
        return DssReportTranslator.translate(reports, organizationIdentifier, NOW, MAX_LIST_AGE);
    }

    private static ObjectNode report(String indication, String subIndication, String qualification) {
        ObjectNode reports = MAPPER.createObjectNode();
        ObjectNode certificate = reports.putObject("simpleCertificateReport").putObject("Certificate");
        certificate.put("Indication", indication);
        certificate.put("SubIndication", subIndication);
        certificate.put("qualificationAtValidation", qualification);
        return reports;
    }

    private static CertificateTrust rejected(CertificateLoginReason reason) {
        return new CertificateTrust.Rejected(reason);
    }
}
