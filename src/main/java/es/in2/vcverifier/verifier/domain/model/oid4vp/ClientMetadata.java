package es.in2.vcverifier.verifier.domain.model.oid4vp;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;

import java.util.List;
import java.util.Map;

/**
 * OID4VP section 5.1 — client_metadata for the Authorization Request.
 * Declares the VP formats the Verifier supports.
 */
@JsonInclude(JsonInclude.Include.NON_NULL)
public record ClientMetadata(
        @JsonProperty("vpFormatsSupported") Map<String, FormatAlgorithms> vpFormatsSupported,

        @JsonProperty("clientName") String clientName,
        @JsonProperty("logoUri") String logoUri,
        @JsonProperty("clientUri") String clientUri,
        @JsonProperty("policyUri") String policyUri,
        @JsonProperty("tosUri") String tosUri,
        @JsonProperty("contacts") List<String> contacts,

        // --- i18n Support (BCP 47) ---
        @JsonProperty("localizedClaims") Map<String,Object> localizedClaims
) {

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record FormatAlgorithms(
            @JsonProperty("sdJwtAlgValues") List<String> sdJwtAlgValues,
            @JsonProperty("kbJwtAlgValues") List<String> kbJwtAlgValues,
            @JsonProperty("algValuesSupported") List<String> algValuesSupported
    ) {}

    /**
     * Default client_metadata with ES256 support for SD-JWT and JWT VC formats.
     */
    public static ClientMetadata defaultMetadata() {
        return new ClientMetadata(
                Map.of(
                        "dc+sd-jwt", new FormatAlgorithms(List.of("ES256"), List.of("ES256"), null),
                        "jwt_vc_json", new FormatAlgorithms(null, null, List.of("ES256"))
                ),
                "", // clientName
                "", // logoUri
                "", // clientUri
                "", // policyUri
                "", // tosUri
                List.of(), // contacts
                Map.of()  // localizedClaims
        );
    }
}
