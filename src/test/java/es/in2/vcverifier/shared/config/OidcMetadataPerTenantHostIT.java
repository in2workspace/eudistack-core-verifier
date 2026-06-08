package es.in2.vcverifier.shared.config;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigProvider;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigYamlData;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import java.io.InputStream;

import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest
@AutoConfigureMockMvc
class OidcMetadataPerTenantHostIT {

    @Autowired
    private MockMvc mockMvc;

    @MockitoBean
    private TenantSsoConfigProvider tenantSsoConfigProvider;

    @MockitoBean
    private RegisteredClientRepository registeredClientRepository;

    @BeforeEach
    void setup() {
        when(tenantSsoConfigProvider.retrieve())
                .thenReturn(loadYaml());
    }

    private TenantSsoConfigYamlData loadYaml() {
        try {
            ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
            try (InputStream is = getClass().getClassLoader().getResourceAsStream("sso-config.yaml")) {
                es.in2.vcverifier.oauth2.infrastructure.config.TenantSsoConfigYamlData infraData =
                        mapper.readValue(is, es.in2.vcverifier.oauth2.infrastructure.config.TenantSsoConfigYamlData.class);

                // Convert infrastructure model to domain model
                var domainEntries = infraData.tenants().stream()
                        .map(e -> new es.in2.vcverifier.shared.domain.port.TenantSsoEntry(e.tenant(), e.rootDomain(), e.ssoEnabled()))
                        .toList();

                return new TenantSsoConfigYamlData(domainEntries);
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    void shouldReturnIssuerBasedOnForwardedHost() throws Exception {
        mockMvc.perform(get("/.well-known/openid-configuration")
                        .header("X-Forwarded-Host", "idp.tenant-a.com")
                        .header("X-Forwarded-Proto", "https"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value("https://idp.tenant-a.com"));
    }


    @Test
    @DisplayName("Con el host legacy de eudistack → el issuer sigue siendo el de eudistack, sin regresión.")
    void shouldReturnIssuerForLegacyHost() throws Exception {
        mockMvc.perform(get("/.well-known/openid-configuration")
                        .header("X-Forwarded-Host", "legacy.eudistack.net")
                        .header("X-Forwarded-Proto", "https"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value("https://legacy.eudistack.net"));
    }


    @Test
    @DisplayName("Dos tenants con dominios distintos en el mismo test → cada uno obtiene su propio issuer, " +
            "sin colisión.")
    void multipleTenantsDoNotCollide() throws Exception {

        mockMvc.perform(get("/.well-known/openid-configuration")
                        .header("X-Forwarded-Host", "idp.a.com")
                        .header("X-Forwarded-Proto", "https"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value("https://idp.a.com"));

        mockMvc.perform(get("/.well-known/openid-configuration")
                        .header("X-Forwarded-Host", "idp.b.com")
                        .header("X-Forwarded-Proto", "https"))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.issuer").value("https://idp.b.com"));
    }
}