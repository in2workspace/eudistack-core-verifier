package es.in2.vcverifier.shared.config;

import es.in2.vcverifier.shared.config.properties.CertificateLoginProperties;
import org.apache.catalina.connector.Connector;
import org.junit.jupiter.api.Test;
import org.springframework.boot.web.embedded.tomcat.TomcatServletWebServerFactory;

import static org.assertj.core.api.Assertions.assertThat;

class CertificatePortConfigTest {

    @Test
    void certificatePortConnector_addsAConnectorOnTheCertificatePort() {
        TomcatServletWebServerFactory factory = new TomcatServletWebServerFactory(8080);

        new CertificatePortConfig().certificatePortConnector(new CertificateLoginProperties(8081, null)).customize(factory);

        assertThat(factory.getAdditionalTomcatConnectors())
                .extracting(Connector::getPort)
                .containsExactly(8081);
        assertThat(factory.getPort()).isEqualTo(8080);
    }
}
