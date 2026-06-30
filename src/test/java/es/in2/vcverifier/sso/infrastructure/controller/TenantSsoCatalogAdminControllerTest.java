package es.in2.vcverifier.sso.infrastructure.controller;

import es.in2.vcverifier.shared.config.TenantDomainFilter;
import es.in2.vcverifier.sso.application.catalog.AddEligibleClientCommand;
import es.in2.vcverifier.sso.application.catalog.ManageTenantSsoCatalogService;
import es.in2.vcverifier.sso.application.catalog.RemoveEligibleClientCommand;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.MediaType;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

import java.util.List;

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.delete;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.jsonPath;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.status;

@ExtendWith(MockitoExtension.class)
class TenantSsoCatalogAdminControllerTest {

    @Mock
    ManageTenantSsoCatalogService catalogService;

    private MockMvc mockMvc;

    private static final String TENANT = "tenant-a";
    private static final String BASE_URL = "/tenant/sso/eligible-clients";

    @BeforeEach
    void setUp() {
        TenantSsoCatalogAdminController controller =
                new TenantSsoCatalogAdminController(catalogService);
        mockMvc = MockMvcBuilders.standaloneSetup(controller).build();
    }

    // =========================================================
    // GET /tenant/sso/eligible-clients
    // =========================================================

    @Test
    void listEligibleClients_returns200_withClientList() throws Exception {
        when(catalogService.listEligibleClients(TENANT))
                .thenReturn(List.of("client-1", "client-2"));

        mockMvc.perform(get(BASE_URL)
                        .requestAttr(TenantDomainFilter.TENANT_ATTRIBUTE, TENANT))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.eligible_clients").isArray())
                .andExpect(jsonPath("$.eligible_clients[0]").value("client-1"))
                .andExpect(jsonPath("$.eligible_clients[1]").value("client-2"));
    }

    @Test
    void listEligibleClients_returns200_withEmptyList_whenNoneRegistered() throws Exception {
        when(catalogService.listEligibleClients(TENANT)).thenReturn(List.of());

        mockMvc.perform(get(BASE_URL)
                        .requestAttr(TenantDomainFilter.TENANT_ATTRIBUTE, TENANT))
                .andExpect(status().isOk())
                .andExpect(jsonPath("$.eligible_clients").isArray())
                .andExpect(jsonPath("$.eligible_clients").isEmpty());
    }

    @Test
    void listEligibleClients_returns403_whenTenantNotInContext() throws Exception {
        // ES-03: sin tenant en el contexto → 403 (nunca parámetro libre)
        mockMvc.perform(get(BASE_URL))
                .andExpect(status().isForbidden());
    }

    // =========================================================
    // POST /tenant/sso/eligible-clients
    // =========================================================

    @Test
    void addEligibleClient_returns200_andDelegatesCommand() throws Exception {
        mockMvc.perform(post(BASE_URL)
                        .requestAttr(TenantDomainFilter.TENANT_ATTRIBUTE, TENANT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"client_id\":\"new-client\"}"))
                .andExpect(status().isOk());

        verify(catalogService).addEligibleClient(
                new AddEligibleClientCommand(TENANT, "new-client"));
    }

    @Test
    void addEligibleClient_returns200_idempotent_whenClientAlreadyExists() throws Exception {
        // El servicio absorbe el no-op; el controlador devuelve 200 igualmente
        mockMvc.perform(post(BASE_URL)
                        .requestAttr(TenantDomainFilter.TENANT_ATTRIBUTE, TENANT)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"client_id\":\"existing-client\"}"))
                .andExpect(status().isOk());
    }

    @Test
    void addEligibleClient_returns403_whenTenantNotInContext() throws Exception {
        mockMvc.perform(post(BASE_URL)
                        .contentType(MediaType.APPLICATION_JSON)
                        .content("{\"client_id\":\"new-client\"}"))
                .andExpect(status().isForbidden());
    }

    // =========================================================
    // DELETE /tenant/sso/eligible-clients/{clientId}
    // =========================================================

    @Test
    void removeEligibleClient_returns204_andDelegatesCommand() throws Exception {
        mockMvc.perform(delete(BASE_URL + "/my-client")
                        .requestAttr(TenantDomainFilter.TENANT_ATTRIBUTE, TENANT))
                .andExpect(status().isNoContent());

        verify(catalogService).removeEligibleClient(
                new RemoveEligibleClientCommand(TENANT, "my-client"));
    }

    @Test
    void removeEligibleClient_returns204_idempotent_whenClientDoesNotExist() throws Exception {
        // El servicio absorbe el no-op; el controlador devuelve 204 igualmente
        mockMvc.perform(delete(BASE_URL + "/absent-client")
                        .requestAttr(TenantDomainFilter.TENANT_ATTRIBUTE, TENANT))
                .andExpect(status().isNoContent());
    }

    @Test
    void removeEligibleClient_returns403_whenTenantNotInContext() throws Exception {
        mockMvc.perform(delete(BASE_URL + "/my-client"))
                .andExpect(status().isForbidden());
    }
}
