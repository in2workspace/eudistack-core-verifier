package es.in2.vcverifier.verifier.domain.model.oid4vp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class ClientMetadataTest {

    private final ObjectMapper objectMapper = new ObjectMapper();

    @Test
    @DisplayName("defaultMetadata() creates structure with dc+sd-jwt and jwt_vc_json formats")
    void defaultMetadata_createsCorrectStructure() {
        ClientMetadata metadata = ClientMetadata.defaultMetadata();

        assertThat(metadata.vpFormatsSupported()).containsKeys("dc+sd-jwt", "jwt_vc_json");

        ClientMetadata.FormatAlgorithms sdJwt = metadata.vpFormatsSupported().get("dc+sd-jwt");
        assertThat(sdJwt.sdJwtAlgValues()).containsExactly("ES256");
        assertThat(sdJwt.kbJwtAlgValues()).containsExactly("ES256");
        assertThat(sdJwt.algValuesSupported()).isNull();

        ClientMetadata.FormatAlgorithms jwtVc = metadata.vpFormatsSupported().get("jwt_vc_json");
        assertThat(jwtVc.sdJwtAlgValues()).isNull();
        assertThat(jwtVc.kbJwtAlgValues()).isNull();
        assertThat(jwtVc.algValuesSupported()).containsExactly("ES256");
    }

    @Test
    @DisplayName("JSON serialization produces correct property names per OID4VP spec")
    void defaultMetadata_serializesWithCorrectJsonKeys() throws Exception {
        ClientMetadata metadata = ClientMetadata.defaultMetadata();

        String json = objectMapper.writeValueAsString(metadata);
        JsonNode root = objectMapper.readTree(json);

        assertThat(root.has("vp_formats_supported")).isTrue();

        JsonNode formats = root.get("vp_formats_supported");
        assertThat(formats.has("dc+sd-jwt")).isTrue();
        assertThat(formats.has("jwt_vc_json")).isTrue();

        JsonNode sdJwt = formats.get("dc+sd-jwt");
        assertThat(sdJwt.get("sd-jwt_alg_values").get(0).asText()).isEqualTo("ES256");
        assertThat(sdJwt.get("kb-jwt_alg_values").get(0).asText()).isEqualTo("ES256");

        JsonNode jwtVc = formats.get("jwt_vc_json");
        assertThat(jwtVc.get("alg_values_supported").get(0).asText()).isEqualTo("ES256");
    }

    @Test
    @DisplayName("JSON serialization omits null fields (NON_NULL policy)")
    void defaultMetadata_omitsNullFieldsInJson() throws Exception {
        ClientMetadata metadata = ClientMetadata.defaultMetadata();

        String json = objectMapper.writeValueAsString(metadata);
        JsonNode root = objectMapper.readTree(json);

        JsonNode sdJwt = root.get("vp_formats_supported").get("dc+sd-jwt");
        assertThat(sdJwt.has("alg_values_supported")).isFalse();

        JsonNode jwtVc = root.get("vp_formats_supported").get("jwt_vc_json");
        assertThat(jwtVc.has("sd-jwt_alg_values")).isFalse();
        assertThat(jwtVc.has("kb-jwt_alg_values")).isFalse();
    }
}
