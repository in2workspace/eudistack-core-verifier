package es.in2.vcverifier.shared.config;

import es.in2.vcverifier.shared.config.properties.SpringApplicationProperties;
import io.micrometer.core.instrument.MeterRegistry;
import lombok.RequiredArgsConstructor;
import org.springframework.boot.actuate.autoconfigure.metrics.MeterRegistryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
@RequiredArgsConstructor
public class MicrometerMetricsConfig {

    private final SpringApplicationProperties springApplicationProperties;

    @Bean
    public MeterRegistryCustomizer<MeterRegistry> commonTagsCustomizer() {
        return registry -> registry.config().commonTags(
                "application", springApplicationProperties.name(),
                "component", "verifier-backend"
        );
    }
}
