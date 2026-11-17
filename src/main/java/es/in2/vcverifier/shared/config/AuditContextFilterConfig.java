package es.in2.vcverifier.shared.config;

import com.eudistack.auditoria.context.AuditContextFilter;
import com.eudistack.auditoria.port.AuditContextResolver;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.core.Ordered;

/**
 * Opens the audit context before Spring Security's filter chain. The starter's own filter runs last, after
 * the chain, but the Verifier authenticates clients and calls the registries inside it (the token endpoint),
 * so those facts would have no context. The resolver runs lazily, so the tenant filter and the
 * authentication are already in place when it is first needed.
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnBooleanProperty("auditoria.publisher.enabled")
class AuditContextFilterConfig {

    @Bean
    FilterRegistrationBean<AuditContextFilter> auditContextFilter(AuditContextResolver resolver) {
        FilterRegistrationBean<AuditContextFilter> registration =
                new FilterRegistrationBean<>(new AuditContextFilter(resolver));
        registration.setOrder(Ordered.HIGHEST_PRECEDENCE + 20);
        return registration;
    }
}
