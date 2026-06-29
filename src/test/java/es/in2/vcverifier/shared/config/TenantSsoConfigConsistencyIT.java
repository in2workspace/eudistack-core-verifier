package es.in2.vcverifier.shared.config;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import es.in2.vcverifier.oauth2.infrastructure.adapter.TenantSsoConfigYamlAdapter;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfigYamlData;
import es.in2.vcverifier.shared.domain.model.TenantSsoEntry;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigProvider;
import es.in2.vcverifier.verifier.domain.service.ClientRegistryProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.ContextConfiguration;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.io.IOException;
import java.io.InputStream;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;


@SpringBootTest
@AutoConfigureMockMvc(addFilters = false)
@ActiveProfiles("test")
@ContextConfiguration(classes = {
        TenantSsoConfigYamlAdapter.class,
        TenantSsoConfigConsistencyIT.TestConfig.class
})
public class TenantSsoConfigConsistencyIT {

    @Autowired
    private TenantSsoConfigPort tenantSsoConfigPort;

    @Autowired
    private TenantSsoConfigYamlAdapter tenantSsoConfigYamlAdapter;

    @Autowired
    private MockMvc mockMvc;

    @Mock
    private HttpServletResponse response;

    @Mock
    private FilterChain chain;

    @Autowired
    private TenantSsoConfigProvider tenantSsoConfigProvider;

    @Mock
    private HttpServletRequest request;

    @MockitoBean
    ClientRegistryProvider clientRegistryProvider;



    @DisplayName("SSO se deshabilita cuando ssoEnabled=true pero falta rootDomain")
    @Test
    void shouldDisableSsoWhenRootDomainIsMissing() {

        tenantSsoConfigYamlAdapter.refresh();

        TenantSsoConfig config =
                tenantSsoConfigPort.getByTenant("sandbox")
                        .orElseThrow();

        assertTrue(config.ssoEnabled());
    }


    @DisplayName("Verifica que una config con sso.enabled: true pero sin rootDomain resulta SSO no habilitado, y emite" +
            "un log estructurado")
    @Test
    void shouldEmitSsoConfigInconsistentLog() {

        Logger logger = (Logger) LoggerFactory.getLogger(TenantSsoConfigYamlAdapter.class);

        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();

        // limpiar otros appenders heredados (IMPORTANTE en Spring Boot)
        logger.addAppender(appender);

        try {
            tenantSsoConfigYamlAdapter.refresh();

            boolean found = appender.list.stream()
                    .anyMatch(event ->
                            event.getFormattedMessage() != null &&
                                    event.getFormattedMessage().contains("sso_config_inconsistent")
                    );

            assertTrue(found, "No se encontró el log sso_config_inconsistent");

        } finally {
            logger.detachAppender(appender);
            appender.stop();
        }
    }


    @TestConfiguration
    static class TestConfig {

        @Bean
        public TenantSsoConfigProvider tenantSsoConfigProvider() {
            return new TenantSsoConfigProvider() {
                @Override
                public TenantSsoConfigYamlData retrieve() {

                    // Carga real desde classpath
                    ObjectMapper mapper = new ObjectMapper(new YAMLFactory());

                    try (InputStream is =
                                 getClass().getClassLoader().getResourceAsStream("sso-config.yaml")) {

                        es.in2.vcverifier.oauth2.infrastructure.config.TenantSsoConfigYamlData infraData =
                                mapper.readValue(is, es.in2.vcverifier.oauth2.infrastructure.config.TenantSsoConfigYamlData.class);

                        // Convert infrastructure model to domain model
                        var domainEntries = infraData.tenants().stream()
                                .map(e -> new TenantSsoEntry(e.tenant(), e.rootDomain(), e.ssoEnabled(), e.eligibleClients(), e.ttlAbsolute(), e.ttlIdle()))
                                .toList();

                        return new TenantSsoConfigYamlData(domainEntries);

                    } catch (IOException e) {
                        throw new RuntimeException(e);
                    }
                }
            };
        }
    }


}