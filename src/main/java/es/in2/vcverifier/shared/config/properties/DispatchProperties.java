package es.in2.vcverifier.shared.config.properties;

import jakarta.validation.Valid;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.validation.annotation.Validated;

import java.util.List;
import java.util.Map;
import java.util.stream.Stream;

@Validated
@ConfigurationProperties(prefix = "verifier.dispatch")
public record DispatchProperties(
        @Valid Map<String, List<DispatchRuleProperties>> rules
) {

    public List<DispatchRuleProperties> legacyRules() {
        return rules == null ? List.of() : rules.getOrDefault("legacy", List.of());
    }

    public List<DispatchRuleProperties> bumpedRules() {
        return rules == null ? List.of() : rules.getOrDefault("bumped", List.of());
    }

    public List<DispatchRuleProperties> allRules() {
        return Stream.concat(legacyRules().stream(), bumpedRules().stream()).toList();
    }

    public record DispatchRuleProperties(
            String credentialConfigurationId,
            String format
    ) {
    }
}
