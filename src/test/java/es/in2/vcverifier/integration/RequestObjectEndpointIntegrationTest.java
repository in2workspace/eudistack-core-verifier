package es.in2.vcverifier.integration;

import es.in2.vcverifier.oauth2.domain.model.AuthorizationRequestJWT;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.verifier.domain.service.TenantConfigPort;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.content;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@SpringBootTest(
        properties = {
                "spring.flyway.enabled=false"
        }
)
@AutoConfigureMockMvc
@ActiveProfiles("test")
class RequestObjectEndpointIntegrationTest {

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private CacheStore<AuthorizationRequestJWT> cacheStoreForAuthorizationRequestJWT;

    @MockitoBean
    private RegisteredClientRepository registeredClientRepository;

    @MockitoBean
    private TenantConfigPort tenantConfigPort;

    @Test
    @DisplayName("GET /oid4vp/r/{id} serves the cached request object without authentication and consumes it")
    void shortRequestObjectEndpoint_unauthenticated_returnsCachedJwtOnce() throws Exception {
        cacheStoreForAuthorizationRequestJWT.add("QlmI53Bf",
                AuthorizationRequestJWT.builder().authRequest("signed.request.object").build());

        mockMvc.perform(get("/oid4vp/r/QlmI53Bf"))
                .andExpect(status().isOk())
                .andExpect(content().string("signed.request.object"));

        assertThat(cacheStoreForAuthorizationRequestJWT.getIfPresent("QlmI53Bf")).isNull();
    }
}
