package es.in2.vcverifier.shared.domain.model;

import com.fasterxml.jackson.annotation.JsonProperty;
import io.swagger.v3.oas.annotations.media.Schema;
import lombok.Builder;

import java.util.List;

@Schema(description = "JSON Web Key Set")
@Builder
public record CustomJWKS(
        @JsonProperty("keys") List<CustomJWK> keys
) {}
