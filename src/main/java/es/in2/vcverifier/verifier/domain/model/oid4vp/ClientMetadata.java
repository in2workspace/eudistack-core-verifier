package es.in2.vcverifier.verifier.domain.model.oid4vp;

import com.fasterxml.jackson.annotation.JsonAnyGetter;
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
        @JsonProperty("vp_formats_supported") Map<String, FormatAlgorithms> vpFormatsSupported,

        // --- RFC 7591 Display Fields ---
        @JsonProperty("client_name") String clientName,
        @JsonProperty("logo_uri") String logoUri,
        @JsonProperty("client_uri") String clientUri,
        @JsonProperty("policy_uri") String policyUri,
        @JsonProperty("tos_uri") String tosUri,
        @JsonProperty("contacts") List<String> contacts,

        // --- i18n Support (BCP 47) ---
        @JsonAnyGetter Map<String,Object> localizedClaims
) {

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record FormatAlgorithms(
            @JsonProperty("sd-jwt_alg_values") List<String> sdJwtAlgValues,
            @JsonProperty("kb-jwt_alg_values") List<String> kbJwtAlgValues,
            @JsonProperty("alg_values_supported") List<String> algValuesSupported
    ) {}

    /**
     * Default client_metadata with ES256 support for SD-JWT and JWT VC formats.
     */
    public static ClientMetadata defaultMetadata() {
        return new ClientMetadata(Map.of(
                "dc+sd-jwt", new FormatAlgorithms(
                        List.of("ES256"), List.of("ES256"), null),
                "jwt_vc_json", new FormatAlgorithms(
                        null, null, List.of("ES256"))
        ));
    }
}
