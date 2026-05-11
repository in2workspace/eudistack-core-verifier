package es.in2.vcverifier.verifier.domain.model.oid4vp;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.autoconfigure.pulsar.PulsarProperties;

import java.util.List;
import java.util.Map;

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
        ClientMetadata metadata = new ClientMetadata(
                Map.of("dc+sd-jwt", new ClientMetadata.FormatAlgorithms(List.of("ES256"), List.of("ES256"), null)),
                "Test Client",
                "https://example.com/logo.png",
                "https://example.com/logo-dark.png",
                "https://example.com",
                "https://example.com/policy",
                "https://example.com/tos",
                List.of("contact@example.com"),
                Map.of("client_name#es", "Cliente de prueba")
        );
        String json = objectMapper.writeValueAsString(metadata);
        JsonNode root = objectMapper.readTree(json);

        assertThat(root.has("vp_formats_supported")).isTrue();

        JsonNode formats = root.get("vp_formats_supported");
        assertThat(formats.has("dc+sd-jwt")).isTrue();

        JsonNode sdJwt = formats.get("dc+sd-jwt");
        assertThat(sdJwt.get("sd-jwt_alg_values").get(0).asText()).isEqualTo("ES256");
        assertThat(sdJwt.get("kb-jwt_alg_values").get(0).asText()).isEqualTo("ES256");

        assertThat(root.get("client_name").asText()).isEqualTo("Test Client");
        assertThat(root.get("logo_uri").asText()).isEqualTo("https://example.com/logo.png");
        assertThat(root.get("logo_dark_uri").asText()).isEqualTo("https://example.com/logo-dark.png");
        assertThat(root.get("client_uri").asText()).isEqualTo("https://example.com");
        assertThat(root.get("policy_uri").asText()).isEqualTo("https://example.com/policy");
        assertThat(root.get("tos_uri").asText()).isEqualTo("https://example.com/tos");
        assertThat(root.get("contacts").get(0).asText()).isEqualTo("contact@example.com");
        assertThat(root.get("localized_claims").has("client_name#es")).isTrue();
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

        assertThat(root.has("client_name")).isFalse();
        assertThat(root.has("client_uri")).isFalse();
        assertThat(root.has("logo_uri")).isFalse();
    }
}
