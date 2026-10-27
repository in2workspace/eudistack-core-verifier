package es.in2.vcverifier.integration;

import es.in2.vcverifier.oauth2.domain.model.AuthorizationRequestJWT;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.verifier.domain.service.TenantConfigPort;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
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

    @ParameterizedTest(name = "GET {0}'{id}' serves the cached request object without authentication and consumes it")
    @ValueSource(strings = {"/oid4vp/r/", "/oid4vp/auth-request/"})
    @DisplayName("Request-object endpoint serves the cached JWT once, without authentication")
    void requestObjectEndpoint_unauthenticated_returnsCachedJwtOnce(String path) throws Exception {
        cacheStoreForAuthorizationRequestJWT.add("QlmI53Bf",
                AuthorizationRequestJWT.builder().authRequest("signed.request.object").build());

        mockMvc.perform(get(path + "QlmI53Bf"))
                .andExpect(status().isOk())
                .andExpect(content().string("signed.request.object"));

        assertThat(cacheStoreForAuthorizationRequestJWT.getIfPresent("QlmI53Bf")).isNull();
    }

    @ParameterizedTest(name = "GET {0}'{id}' answers 404 for an unknown or already consumed id")
    @ValueSource(strings = {"/oid4vp/r/", "/oid4vp/auth-request/"})
    @DisplayName("Request-object endpoint answers 404 for an unknown or consumed id")
    void requestObjectEndpoint_unknownId_returnsNotFound(String path) throws Exception {
        mockMvc.perform(get(path + "unknown1"))
                .andExpect(status().isNotFound());
    }
}
