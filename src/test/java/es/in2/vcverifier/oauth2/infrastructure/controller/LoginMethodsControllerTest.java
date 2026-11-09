package es.in2.vcverifier.oauth2.infrastructure.controller;

import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.oauth2.application.workflow.LoginMethodsWorkflow;
import es.in2.vcverifier.oauth2.application.workflow.LoginMethodsWorkflow.LoginMethods;
import es.in2.vcverifier.oauth2.application.workflow.LoginMethodsWorkflow.WalletRequestResult;
import es.in2.vcverifier.shared.config.TenantDomainFilter;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;

import java.net.URI;
import java.util.List;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LoginMethodsControllerTest {

    private static final String TENANT = "cgcom";
    private static final String HIGH = "http://eidas.europa.eu/LoA/high";
    private static final String METHODS_PATH = "/verifier/api/login/methods";
    private static final String WALLET_PATH = "/verifier/api/login/wallet";

    @Mock
    private LoginMethodsWorkflow loginMethodsWorkflow;

    @InjectMocks
    private LoginMethodsController controller;

    private HttpServletRequest request;

    @BeforeEach
    void setUp() {
        request = mock(HttpServletRequest.class);
        lenient().when(request.getAttribute(TenantDomainFilter.TENANT_ATTRIBUTE)).thenReturn(TENANT);
        lenient().when(request.getRequestURI()).thenReturn(METHODS_PATH);
    }

    @Test
    void methods_openLogin_returnsTheMethodsAndTheEssentialLevel() {
        when(loginMethodsWorkflow.loginMethods("s1", TENANT))
                .thenReturn(Optional.of(new LoginMethods(List.of("x509", "wallet"), HIGH)));

        ResponseEntity<Object> response = controller.methods("s1", request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody())
                .isEqualTo(new LoginMethodsController.LoginMethodsResponse(List.of("x509", "wallet"), HIGH));
    }

    @Test
    void methods_unknownLogin_returnsLoginNotFound() {
        when(loginMethodsWorkflow.loginMethods("unknown", TENANT)).thenReturn(Optional.empty());

        ResponseEntity<Object> response = controller.methods("unknown", request);

        assertProblem(response, HttpStatus.NOT_FOUND, "login_not_found", "Login not found", METHODS_PATH);
    }

    @Test
    void wallet_created_returnsTheWalletRequest() {
        when(loginMethodsWorkflow.startWallet("s1", TENANT))
                .thenReturn(new WalletRequestResult.Created("openid4vp://request", 95));

        ResponseEntity<Object> response = controller.wallet("s1", request);

        assertThat(response.getStatusCode()).isEqualTo(HttpStatus.OK);
        assertThat(response.getBody())
                .isEqualTo(new LoginMethodsController.WalletRequestResponse("openid4vp://request", 95));
    }

    @Test
    void wallet_unknownLogin_returnsLoginNotFound() {
        when(loginMethodsWorkflow.startWallet("unknown", TENANT)).thenReturn(new WalletRequestResult.LoginNotFound());
        when(request.getRequestURI()).thenReturn(WALLET_PATH);

        ResponseEntity<Object> response = controller.wallet("unknown", request);

        assertProblem(response, HttpStatus.NOT_FOUND, "login_not_found", "Login not found", WALLET_PATH);
    }

    @Test
    void wallet_notOffered_returnsMethodNotOffered() {
        when(loginMethodsWorkflow.startWallet("s1", TENANT)).thenReturn(new WalletRequestResult.MethodNotOffered());
        when(request.getRequestURI()).thenReturn(WALLET_PATH);

        ResponseEntity<Object> response = controller.wallet("s1", request);

        assertProblem(response, HttpStatus.CONFLICT, "method_not_offered", "Method not offered", WALLET_PATH);
    }

    @Test
    void responses_useTheFieldNamesOfTheContract() throws Exception {
        ObjectMapper objectMapper = new ObjectMapper();

        assertThat(objectMapper.writeValueAsString(
                new LoginMethodsController.LoginMethodsResponse(List.of("x509", "wallet"), HIGH)))
                .isEqualTo("{\"methods\":[\"x509\",\"wallet\"],\"essential_level\":\"" + HIGH + "\"}");
        assertThat(objectMapper.writeValueAsString(
                new LoginMethodsController.LoginMethodsResponse(List.of("wallet"), null)))
                .isEqualTo("{\"methods\":[\"wallet\"]}");
        assertThat(objectMapper.writeValueAsString(
                new LoginMethodsController.WalletRequestResponse("openid4vp://request", 95)))
                .isEqualTo("{\"authRequest\":\"openid4vp://request\",\"expires_in\":95}");
    }

    private static void assertProblem(ResponseEntity<Object> response, HttpStatus status, String type, String title,
                                      String instance) {
        assertThat(response.getStatusCode()).isEqualTo(status);
        assertThat(response.getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_PROBLEM_JSON);
        assertThat(response.getBody()).isInstanceOfSatisfying(ProblemDetail.class, problem -> {
            assertThat(problem.getType()).isEqualTo(URI.create(type));
            assertThat(problem.getTitle()).isEqualTo(title);
            assertThat(problem.getStatus()).isEqualTo(status.value());
            assertThat(problem.getDetail()).isNotBlank();
            assertThat(problem.getInstance()).isEqualTo(URI.create(instance));
        });
    }
}
