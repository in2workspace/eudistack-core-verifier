package es.in2.vcverifier.shared.config.properties;

import jakarta.validation.constraints.NotBlank;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

@Validated
@ConfigurationProperties(prefix = "spring.application")
public record SpringApplicationProperties(
        @NotBlank String name
) {
}
