package es.in2.vcverifier.oauth2.domain.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import lombok.Builder;

@Builder
public record AuthorizationRequest(
        @JsonProperty("response_type") String responseType,
        @JsonProperty("response_mode") String responseMode,
        @JsonProperty("response_uri") String responseUri,
        @JsonProperty("scope") String scope,
        @JsonProperty("client_id") String clientId,
        @JsonProperty("client_id_scheme") String clientIdScheme,
        @JsonProperty("nonce") String nonce,
        @JsonProperty("state") String state,
        @JsonProperty("presentation_definition")
        String presentationDefinition,
        @JsonProperty("presentation_definition_uri")
        String presentationDefinitionUri
) {
}
