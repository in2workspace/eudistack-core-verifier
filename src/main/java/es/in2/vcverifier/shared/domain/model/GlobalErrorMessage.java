package es.in2.vcverifier.shared.domain.model;

import com.fasterxml.jackson.annotation.JsonInclude;
import io.swagger.v3.oas.annotations.media.Schema;

@Schema(description = "Error response following RFC 7807")
@JsonInclude(JsonInclude.Include.NON_NULL)
public record GlobalErrorMessage(
        String type,
        String title,
        int status,
        String detail,
        String instance
) {
}
