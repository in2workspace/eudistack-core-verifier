package es.in2.vcverifier.oauth2.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.web.authentication.AuthenticationSuccessHandler;
import org.springframework.security.web.authentication.SavedRequestAwareAuthenticationSuccessHandler;

@Configuration
public class Oid4vpHandlerConfig {

    @Bean
    public AuthenticationSuccessHandler oid4vpSuccessHandler() {
        return new SavedRequestAwareAuthenticationSuccessHandler();
    }
}
