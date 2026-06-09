package es.in2.vcverifier.shared.config;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import es.in2.vcverifier.oauth2.infrastructure.adapter.TenantSsoConfigYamlAdapter;
import es.in2.vcverifier.oauth2.infrastructure.config.TenantSsoConfigYamlData;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigProvider;
import es.in2.vcverifier.verifier.domain.service.ClientRegistryProvider;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
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
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;


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

    @Mock
    private HttpServletRequest request;

    private SecurityHeadersFilter securityHeadersFilter;

    @MockitoBean
    ClientRegistryProvider clientRegistryProvider;

    @BeforeEach
    void setUp() {
        securityHeadersFilter = new SecurityHeadersFilter();
    }

    private final ObjectMapper objectMapper = new ObjectMapper();



    @DisplayName("Verifica que una config con sso.enabled: true pero sin rootDomain resulta SSO no habilitado")
    @Test
    void shouldDisableSsoWhenRootDomainIsMissing() {

        tenantSsoConfigYamlAdapter.refresh();

        TenantSsoConfig config =
                tenantSsoConfigPort.getByTenant("sandbox")
                        .orElseThrow();

        assertFalse(config.ssoEnabled());
    }


    @DisplayName("Verifica que una config con sso.enabled: true pero sin rootDomain resulta SSO no habilitado, y emite" +
            "un log estructurado")
    @Test
    void shouldEmitSsoConfigInconsistentLog() {

        Logger logger = (Logger) LoggerFactory.getLogger(TenantSsoConfigYamlAdapter.class);

        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();

        // limpiar otros appenders heredados (IMPORTANTE en Spring Boot)
        logger.detachAndStopAllAppenders();
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


    @DisplayName("Verifica que una config con sso.enabled: true pero sin rootDomain el flujo OID4VP legacy " +
            "sigue funcionando con normalidad.")
    @Test
    void shouldKeepLegacyOid4vpFlowWorking() throws ServletException, IOException {

        when(request.getRequestURI())
                .thenReturn("/oid4vp/authorize");

        when(request.getContextPath())
                .thenReturn("");

        when(request.getHeader("X-Forwarded-Host"))
                .thenReturn("legacy.eudistack.net");

        securityHeadersFilter.doFilter(request, response, chain);

        verify(chain).doFilter(request, response);
    }


    @TestConfiguration
    static class TestConfig {

        @Bean(name = "tenantSsoConfigYamlProvider")
        public TenantSsoConfigProvider provider() {
            return new TenantSsoConfigProvider() {
                @Override
                public TenantSsoConfigYamlData retrieve() {
                    try (InputStream is =
                                 getClass().getClassLoader().getResourceAsStream("sso-config.yaml")) {

                        return new ObjectMapper(new YAMLFactory())
                                .readValue(is, TenantSsoConfigYamlData.class);

                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                }
            };
        }
    }


}