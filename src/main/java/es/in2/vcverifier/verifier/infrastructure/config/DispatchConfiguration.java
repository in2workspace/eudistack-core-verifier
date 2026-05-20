package es.in2.vcverifier.verifier.infrastructure.config;

import es.in2.vcverifier.shared.config.properties.DispatchProperties;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchRule;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import java.util.List;

@Configuration
public class DispatchConfiguration {

    @Bean
    public List<DispatchRule> dispatchRules(DispatchProperties dispatchProperties) {
        return dispatchProperties.allRules();
    }
}
