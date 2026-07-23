package es.in2.vcverifier.oauth2.infrastructure.config;

import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;

/**
 * Kept as its own zero-dependency {@code @Configuration} class, separate from
 * {@link AuthorizationServerConfig}: {@code OAuth2AuthorizationService} is needed by
 * {@code AuthorizationResponseProcessorServiceImpl}, which {@code ReuseSsoSessionWorkflowImpl}
 * depends on, which {@code AuthorizationServerConfig} itself needs to build its
 * {@code CustomAuthorizationRequestConverter} — declaring the bean inside
 * {@code AuthorizationServerConfig} would create a circular bean-creation dependency
 * (Spring must fully construct a {@code @Configuration} instance, including all its
 * constructor-injected fields, before any of its own {@code @Bean} methods can run).
 */
@Configuration
public class OAuth2AuthorizationServiceConfig {

    @Bean
    public OAuth2AuthorizationService oAuth2AuthorizationService() {
        return new InMemoryOAuth2AuthorizationService();
    }
}