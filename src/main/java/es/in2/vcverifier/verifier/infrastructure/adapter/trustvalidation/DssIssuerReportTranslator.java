package es.in2.vcverifier.verifier.infrastructure.adapter.trustvalidation;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.MissingNode;
import es.in2.vcverifier.verifier.domain.model.IssuerTrust;

import java.time.Duration;
import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.Set;

final class DssIssuerReportTranslator {

    static final String ISSUERS_LIST_TYPE = "http://uri.eudistack.net/19602/LoTEType/EAAProvidersList";
    private static final String SERVICE_TYPE_PREFIX = "http://uri.eudistack.net/19602/SvcType/EAA/";
    private static final String SERVICE_TYPE_SUFFIX = "/Issuance";
    private static final String DID_ELSI_PREFIX = "did:elsi:";

    private static final String PASSED = "PASSED";
    private static final String FAILED = "FAILED";
    private static final String INDETERMINATE = "INDETERMINATE";
    private static final Set<String> NOT_TRUSTED_SUB_INDICATIONS = Set.of(
            "NO_CERTIFICATE_CHAIN_FOUND", "REVOKED", "REVOKED_NO_POE", "REVOKED_CA_NO_POE",
            "EXPIRED", "NOT_YET_VALID", "OUT_OF_BOUNDS_NO_POE", "OUT_OF_BOUNDS_NOT_REVOKED");

    private DssIssuerReportTranslator() {
    }

    static String serviceTypeFor(String credentialConfigurationId) {
        return SERVICE_TYPE_PREFIX + credentialConfigurationId + SERVICE_TYPE_SUFFIX;
    }

    static IssuerTrust translate(JsonNode reports, String credentialConfigurationId, String declaredIssuer,
                                 Instant now, Duration maxListAge) {
        JsonNode certificate = reports.path("simpleCertificateReport").path("Certificate");
        if (!certificate.isObject()) {
            return new IssuerTrust.Unavailable("DSS report without certificate result");
        }
        String indication = text(certificate.path("Indication"));
        String subIndication = text(certificate.path("SubIndication"));
        return switch (indication) {
            case PASSED -> fromTrustedEntities(reports.path("diagnosticData"), credentialConfigurationId,
                    declaredIssuer, now, maxListAge);
            case FAILED -> new IssuerTrust.NotTrusted("Issuer chain is not valid: " + subIndication);
            case INDETERMINATE -> NOT_TRUSTED_SUB_INDICATIONS.contains(subIndication)
                    ? new IssuerTrust.NotTrusted("Issuer chain is not valid: " + subIndication)
                    : new IssuerTrust.Unavailable("Issuer chain validation is indeterminate: " + subIndication);
            default -> new IssuerTrust.Unavailable("Unexpected DSS indication: " + indication);
        };
    }

    private static IssuerTrust fromTrustedEntities(JsonNode diagnosticData, String credentialConfigurationId,
                                                   String declaredIssuer, Instant now, Duration maxListAge) {
        String expectedServiceType = serviceTypeFor(credentialConfigurationId);
        String expectedIssuer = stripDidElsiPrefix(declaredIssuer);
        String notWellSignedReason = null;
        String unusableListReason = null;
        for (JsonNode certificate : diagnosticData.path("Certificate")) {
            for (JsonNode entity : certificate.path("TrustedEntity")) {
                JsonNode list = listById(diagnosticData, text(entity.path("LoTE")));
                if (list == null || !ISSUERS_LIST_TYPE.equals(text(list.path("Type")))) {
                    continue;
                }
                String entityIdentifier = matchingTradeName(entity, expectedIssuer);
                if (entityIdentifier == null || !hasService(entity, expectedServiceType)) {
                    continue;
                }
                JsonNode parent = parentOf(diagnosticData, list);
                String signatureReason = notWellSignedReason(list, parent);
                if (signatureReason != null) {
                    notWellSignedReason = signatureReason;
                    continue;
                }
                String reason = unusableReason(list, parent, now, maxListAge);
                if (reason != null) {
                    unusableListReason = reason;
                    continue;
                }
                return new IssuerTrust.Trusted(entityIdentifier, expectedServiceType, text(list.path("Url")),
                        text(list.path("Type")), list.path("SequenceNumber").isInt()
                                ? list.path("SequenceNumber").asInt() : null);
            }
        }
        if (notWellSignedReason != null) {
            return new IssuerTrust.NotTrusted(notWellSignedReason);
        }
        return unusableListReason != null
                ? new IssuerTrust.Unavailable(unusableListReason)
                : new IssuerTrust.NotTrusted("Issuer is not an entity of the issuers list with a service for "
                        + credentialConfigurationId);
    }

    private static JsonNode parentOf(JsonNode diagnosticData, JsonNode list) {
        String parentId = text(list.path("parent"));
        return parentId.isEmpty() ? MissingNode.getInstance() : listById(diagnosticData, parentId);
    }

    private static String notWellSignedReason(JsonNode list, JsonNode parent) {
        if (!isWellSigned(list)) {
            return "List not well signed: " + text(list.path("Url"));
        }
        if (parent != null && !parent.isMissingNode() && !isWellSigned(parent)) {
            return "List not well signed: " + text(parent.path("Url"));
        }
        return null;
    }

    private static boolean isWellSigned(JsonNode list) {
        return list.path("WellSigned").asBoolean(false);
    }

    private static String unusableReason(JsonNode list, JsonNode parent, Instant now, Duration maxListAge) {
        String reason = unusableListReason(list, now, maxListAge);
        if (reason != null) {
            return reason;
        }
        if (parent == null) {
            return "The list of lists of " + text(list.path("Url")) + " is not in the report";
        }
        return parent.isMissingNode() ? null : unusableListReason(parent, now, maxListAge);
    }

    private static String unusableListReason(JsonNode list, Instant now, Duration maxListAge) {
        String url = text(list.path("Url"));
        Instant nextUpdate = parseInstant(text(list.path("NextUpdate")));
        if (nextUpdate == null || nextUpdate.isBefore(now)) {
            return "The list " + url + " is past its next update";
        }
        if (isStale(list, now, maxListAge)) {
            return "The list " + url + " was loaded more than " + maxListAge + " ago";
        }
        return null;
    }

    private static JsonNode listById(JsonNode diagnosticData, String id) {
        for (JsonNode list : diagnosticData.path("ListOfTrustedEntities")) {
            if (!id.isEmpty() && id.equals(text(list.path("Id")))) {
                return list;
            }
        }
        return null;
    }

    private static String matchingTradeName(JsonNode entity, String expectedIssuer) {
        if (expectedIssuer == null || expectedIssuer.isBlank()) {
            return null;
        }
        for (JsonNode tradeName : entity.path("TradeName")) {
            String value = text(tradeName.path("value"));
            if (expectedIssuer.equals(value)) {
                return value;
            }
        }
        return null;
    }

    private static boolean hasService(JsonNode entity, String expectedServiceType) {
        for (JsonNode service : entity.path("TrustedEntityService")) {
            if (expectedServiceType.equals(text(service.path("ServiceType")))) {
                return true;
            }
        }
        return false;
    }

    private static boolean isStale(JsonNode list, Instant now, Duration maxListAge) {
        Instant lastLoading = parseInstant(text(list.path("LastLoading")));
        return lastLoading == null || lastLoading.plus(maxListAge).isBefore(now);
    }

    private static String stripDidElsiPrefix(String value) {
        return value != null && value.startsWith(DID_ELSI_PREFIX) ? value.substring(DID_ELSI_PREFIX.length()) : value;
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
}
