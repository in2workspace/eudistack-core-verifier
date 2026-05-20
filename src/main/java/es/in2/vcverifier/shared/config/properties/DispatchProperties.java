package es.in2.vcverifier.shared.config.properties;

import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchRule;
import jakarta.validation.Valid;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

@Validated
@ConfigurationProperties(prefix = "verifier.dispatch")
public record DispatchProperties(
        @Valid Map<String, List<DispatchRule>> rules
) {

    public List<DispatchRule> legacyRules() {
        return rules == null ? List.of() : rules.getOrDefault("legacy", List.of());
    }

    public List<DispatchRule> bumpedRules() {
        return rules == null ? List.of() : rules.getOrDefault("bumped", List.of());
    }

    public List<DispatchRule> allRules() {
        return Stream.concat(legacyRules().stream(), bumpedRules().stream()).toList();
    }
}
