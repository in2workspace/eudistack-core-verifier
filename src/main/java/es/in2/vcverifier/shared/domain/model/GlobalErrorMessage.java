package es.in2.vcverifier.shared.domain.model;

import com.fasterxml.jackson.annotation.JsonInclude;

@JsonInclude(JsonInclude.Include.NON_NULL)
public record GlobalErrorMessage(
        String type,
        String title,
        int status,
        String detail,
        String instance
) {
}
