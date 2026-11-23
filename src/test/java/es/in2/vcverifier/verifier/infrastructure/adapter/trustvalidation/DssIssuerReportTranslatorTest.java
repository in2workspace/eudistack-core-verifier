package es.in2.vcverifier.verifier.infrastructure.adapter.trustvalidation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.vcverifier.verifier.domain.model.IssuerTrust;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import java.io.InputStream;
import java.time.Duration;
import java.time.Instant;

import static org.assertj.core.api.Assertions.assertThat;

class DssIssuerReportTranslatorTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();
    private static final Instant NOW = Instant.parse("2026-11-23T12:00:00Z");
    private static final Duration MAX_LIST_AGE = Duration.ofHours(24);
    private static final String TYPE = "learcredential.employee.sd.1";
    private static final String ISSUER = "VATES-B00000000";

    private ObjectNode report;

    @BeforeEach
    void loadTheRealDssReport() throws Exception {
        try (InputStream in = getClass().getResourceAsStream("/dss/issuer-in-issuers-list.json")) {
            report = (ObjectNode) MAPPER.readTree(in);
        }
    }

    @Test
    void translate_issuerOfTheIssuersListWithAServiceForTheType_isTrustedWithTheOrigin() {
        IssuerTrust trust = DssIssuerReportTranslator.translate(report, TYPE, ISSUER, NOW, MAX_LIST_AGE);

        assertThat(trust).isEqualTo(new IssuerTrust.Trusted(ISSUER,
                "http://uri.eudistack.net/19602/SvcType/EAA/learcredential.employee.sd.1/Issuance",
                "file:/lists/eaa-providers.jws", DssIssuerReportTranslator.ISSUERS_LIST_TYPE, 1));
    }

    @Test
    void translate_issuerDeclaredWithTheDidElsiPrefix_isTrusted() {
        assertThat(DssIssuerReportTranslator.translate(report, TYPE, "did:elsi:" + ISSUER, NOW, MAX_LIST_AGE))
                .isInstanceOf(IssuerTrust.Trusted.class);
    }

    @Test
    void translate_typeWithoutAServiceOfTheEntity_isNotTrusted() {
        assertThat(DssIssuerReportTranslator.translate(report, "learcredential.machine.sd.1", ISSUER, NOW, MAX_LIST_AGE))
                .isInstanceOf(IssuerTrust.NotTrusted.class);
    }

    @Test
    void translate_attestationDeclaringAnotherIssuer_isNotTrusted() {
        assertThat(DssIssuerReportTranslator.translate(report, TYPE, "VATES-A15456585", NOW, MAX_LIST_AGE))
                .isInstanceOf(IssuerTrust.NotTrusted.class);
    }

    @Test
    void translate_entityOfAListThatIsNotTheIssuersList_isNotTrusted() {
        ((ObjectNode) report.at("/diagnosticData/ListOfTrustedEntities/0"))
                .put("Type", "http://uri.eudistack.net/19602/LoTEType/WalletProvidersList");

        assertThat(DssIssuerReportTranslator.translate(report, TYPE, ISSUER, NOW, MAX_LIST_AGE))
                .isInstanceOf(IssuerTrust.NotTrusted.class);
    }

    @Test
    void translate_validChainWithoutAnyEntityOfAList_isNotTrusted() {
        ((ObjectNode) report.at("/diagnosticData/Certificate/0")).putNull("TrustedEntity");

        assertThat(DssIssuerReportTranslator.translate(report, TYPE, ISSUER, NOW, MAX_LIST_AGE))
                .isInstanceOf(IssuerTrust.NotTrusted.class);
    }

    @Test
    void translate_issuersListOlderThanTheMaximumAge_isUnavailable() {
        assertThat(DssIssuerReportTranslator.translate(report, TYPE, ISSUER, NOW.plus(Duration.ofDays(2)), MAX_LIST_AGE))
                .isInstanceOf(IssuerTrust.Unavailable.class);
    }

    @Test
    void translate_failedChain_isNotTrusted() {
        assertThat(translateWith("FAILED", "NOT_YET_VALID")).isInstanceOf(IssuerTrust.NotTrusted.class);
    }

    @Test
    void translate_chainThatReachesNoList_isNotTrusted() {
        assertThat(translateWith("INDETERMINATE", "NO_CERTIFICATE_CHAIN_FOUND"))
                .isInstanceOf(IssuerTrust.NotTrusted.class);
    }

    @Test
    void translate_revokedIssuerCertificate_isNotTrusted() {
        assertThat(translateWith("INDETERMINATE", "REVOKED_NO_POE")).isInstanceOf(IssuerTrust.NotTrusted.class);
    }

    @Test
    void translate_otherIndeterminateResult_isUnavailable() {
        assertThat(translateWith("INDETERMINATE", "TRY_LATER")).isInstanceOf(IssuerTrust.Unavailable.class);
    }

    @Test
    void translate_reportWithoutCertificateResult_isUnavailable() {
        JsonNode empty = MAPPER.createObjectNode();

        assertThat(DssIssuerReportTranslator.translate(empty, TYPE, ISSUER, NOW, MAX_LIST_AGE))
                .isInstanceOf(IssuerTrust.Unavailable.class);
    }

    @Test
    void translate_entityIdentifierOnlyInRegistrationIdentifier_isNotTrusted() {
        ObjectNode entity = (ObjectNode) report.at("/diagnosticData/Certificate/0/TrustedEntity/0");
        entity.putArray("TradeName");
        ((ArrayNode) entity.withArray("RegistrationIdentifier")).add(ISSUER);

        assertThat(DssIssuerReportTranslator.translate(report, TYPE, ISSUER, NOW, MAX_LIST_AGE))
                .isInstanceOf(IssuerTrust.NotTrusted.class);
    }

    private IssuerTrust translateWith(String indication, String subIndication) {
        ObjectNode certificate = (ObjectNode) report.at("/simpleCertificateReport/Certificate");
        certificate.put("Indication", indication);
        certificate.put("SubIndication", subIndication);
        return DssIssuerReportTranslator.translate(report, TYPE, ISSUER, NOW, MAX_LIST_AGE);
    }
}
