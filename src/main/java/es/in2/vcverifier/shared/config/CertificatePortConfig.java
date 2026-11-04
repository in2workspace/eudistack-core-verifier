package es.in2.vcverifier.shared.config;

import es.in2.vcverifier.shared.config.properties.CertificateLoginProperties;
import org.apache.catalina.connector.Connector;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CertificatePortConfig {

    @Bean
    public WebServerFactoryCustomizer<TomcatServletWebServerFactory> certificatePortConnector(
            CertificateLoginProperties certificateLoginProperties) {
        return factory -> {
            Connector connector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
            connector.setPort(certificateLoginProperties.port());
            factory.addAdditionalTomcatConnectors(connector);
        };
    }
}
