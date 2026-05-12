package es.in2.vcverifier.verifier.domain.model.oid4vp;

import com.fasterxml.jackson.annotation.JsonAlias;
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
        @JsonAlias("vpFormatsSupported")
        @JsonProperty("vp_formats_supported") Map<String, FormatAlgorithms> vpFormatsSupported,

        @JsonAlias("clientName")
        @JsonProperty("client_name") String clientName,

        @JsonAlias("logoUri")
        @JsonProperty("logo_uri") String logoUri,

        @JsonAlias("logoDarkUri")
        @JsonProperty("logo_dark_uri") String logoDarkUri,

        @JsonAlias("clientUri")
        @JsonProperty("client_uri") String clientUri,

        @JsonAlias("policyUri")
        @JsonProperty("policy_uri") String policyUri,

        @JsonAlias("tosUri")
        @JsonProperty("tos_uri") String tosUri,

        @JsonProperty("contacts") List<String> contacts,

        // --- i18n Support (BCP 47) ---
        @JsonAlias("localizedClaims")
        @JsonProperty("localized_claims") Map<String,Object> localizedClaims
) {

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record FormatAlgorithms(
            @JsonAlias("sdJwtAlgValues")
            @JsonProperty("sd-jwt_alg_values") List<String> sdJwtAlgValues,

            @JsonAlias("kbJwtAlgValues")
            @JsonProperty("kb-jwt_alg_values") List<String> kbJwtAlgValues,

            @JsonAlias("algValuesSupported")
            @JsonProperty("alg_values_supported") List<String> algValuesSupported
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
                null,
                null,
                null,
                null,
                null,
                null,
                null,
                null
        );
    }
}
