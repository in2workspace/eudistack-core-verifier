package es.in2.vcverifier.verifier.infrastructure.adapter.trustvalidation;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.vcverifier.shared.domain.model.AssuranceLevel;
import es.in2.vcverifier.verifier.domain.model.CertificateLoginReason;
import es.in2.vcverifier.verifier.domain.model.CertificateTrust;

import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Set;

final class DssReportTranslator {

    private static final String PASSED = "PASSED";
    private static final String FAILED = "FAILED";
    private static final String INDETERMINATE = "INDETERMINATE";
    private static final String NO_CERTIFICATE_CHAIN_FOUND = "NO_CERTIFICATE_CHAIN_FOUND";
    private static final Set<String> REVOCATION = Set.of("REVOKED", "REVOKED_NO_POE", "REVOKED_CA_NO_POE");
    private static final Set<String> EXPIRY = Set.of(
            "EXPIRED", "NOT_YET_VALID", "OUT_OF_BOUNDS_NO_POE", "OUT_OF_BOUNDS_NOT_REVOKED");
    private static final String QUALIFIED_SEAL = "QC for eSeal";
    private static final String QUALIFIED_SIGNATURE = "QC for eSig";
    private static final String QUALIFIED_SIGNATURE_WITH_QSCD = "QC for eSig with QSCD";
    private static final List<String> HARDWARE_KEY = List.of("hwk");
    private static final List<String> SOFTWARE_KEY = List.of("swk");

    private DssReportTranslator() {
    }

    static CertificateTrust translate(JsonNode reports, boolean subjectHasOrganizationIdentifier,
                                      Instant now, Duration maxListAge) {
        JsonNode certificate = reports.path("simpleCertificateReport").path("Certificate");
        if (certificate.isMissingNode() || certificate.isNull()) {
            return rejected(CertificateLoginReason.VALIDATION_UNAVAILABLE);
        }
        if (listsAreStale(reports.path("diagnosticData").path("TrustedList"), now, maxListAge)) {
            return rejected(CertificateLoginReason.VALIDATION_UNAVAILABLE);
        }

        String indication = text(certificate.path("Indication"));
        String subIndication = text(certificate.path("SubIndication"));
        if (REVOCATION.contains(subIndication)) {
            return rejected(CertificateLoginReason.CERTIFICATE_REVOKED);
        }
        if (EXPIRY.contains(subIndication)) {
            return rejected(CertificateLoginReason.CERTIFICATE_EXPIRED);
        }
        return switch (indication) {
            case PASSED -> fromQualification(text(certificate.path("qualificationAtValidation")),
                    subjectHasOrganizationIdentifier);
            case FAILED -> rejected(CertificateLoginReason.CERTIFICATE_NOT_QUALIFIED);
            case INDETERMINATE -> rejected(NO_CERTIFICATE_CHAIN_FOUND.equals(subIndication)
                    ? CertificateLoginReason.CERTIFICATE_NOT_QUALIFIED
                    : CertificateLoginReason.VALIDATION_UNAVAILABLE);
            default -> rejected(CertificateLoginReason.VALIDATION_UNAVAILABLE);
        };
    }

    private static CertificateTrust fromQualification(String qualification, boolean subjectHasOrganizationIdentifier) {
        if (qualification.startsWith(QUALIFIED_SEAL)) {
            return rejected(CertificateLoginReason.CERTIFICATE_NOT_NATURAL_PERSON);
        }
        if (!qualification.startsWith(QUALIFIED_SIGNATURE)) {
            return rejected(CertificateLoginReason.CERTIFICATE_NOT_QUALIFIED);
        }
        if (subjectHasOrganizationIdentifier) {
            return rejected(CertificateLoginReason.CERTIFICATE_NOT_NATURAL_PERSON);
        }
        return qualification.startsWith(QUALIFIED_SIGNATURE_WITH_QSCD)
                ? new CertificateTrust.Trusted(AssuranceLevel.HIGH, HARDWARE_KEY)
                : new CertificateTrust.Trusted(AssuranceLevel.SUBSTANTIAL, SOFTWARE_KEY);
    }

    private static boolean listsAreStale(JsonNode trustedLists, Instant now, Duration maxListAge) {
        if (!trustedLists.isArray()) {
            return false;
        }
        for (JsonNode trustedList : trustedLists) {
            Instant lastLoading = parseInstant(text(trustedList.path("LastLoading")));
            if (lastLoading == null || lastLoading.plus(maxListAge).isBefore(now)) {
                return true;
            }
        }
        return false;
    }

    private static String text(JsonNode node) {
        return node.isTextual() ? node.asText() : "";
    }

    private static Instant parseInstant(String value) {
        if (value.isBlank()) {
            return null;
        }
        try {
            return Instant.parse(value);
        } catch (DateTimeParseException _) {
            return null;
        }
    }

    private static CertificateTrust rejected(CertificateLoginReason reason) {
        return new CertificateTrust.Rejected(reason);
    }
}
