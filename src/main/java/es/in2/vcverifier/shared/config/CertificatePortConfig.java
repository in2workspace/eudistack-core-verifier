package es.in2.vcverifier.shared.config;

import org.apache.catalina.connector.Connector;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;
import org.springframework.boot.web.server.WebServerFactoryCustomizer;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class CertificatePortConfig {

    @Bean
    public WebServerFactoryCustomizer<TomcatServletWebServerFactory> certificatePortConnector(
            @Value("${verifier.certificate-login.port:8081}") int certificatePort) {
        return factory -> {
            Connector connector = new Connector(TomcatServletWebServerFactory.DEFAULT_PROTOCOL);
            connector.setPort(certificatePort);
            factory.addAdditionalTomcatConnectors(connector);
        };
    }
}
