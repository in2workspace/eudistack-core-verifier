package es.in2.vcverifier.verifier.infrastructure.controller;

import es.in2.vcverifier.shared.config.CertificateLoginFilter;
import es.in2.vcverifier.shared.config.TenantDomainFilter;
import es.in2.vcverifier.verifier.application.workflow.CertificateLoginWorkflow;
import es.in2.vcverifier.verifier.application.workflow.CertificateLoginWorkflow.Outcome;
import es.in2.vcverifier.verifier.domain.model.CertificateLoginReason;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.CsvSource;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;

import java.net.URI;
import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertificateLoginControllerTest {

    private static final String HEADER = ":MIIB:";
    private static final List<String> CHAIN = List.of(":MIIC:", ":MIID:");

    @Mock
    private CertificateLoginWorkflow workflow;

    @InjectMocks
    private CertificateLoginController controller;

    @Test
    void certificate_completedLogin_returnsTheRedirectUri() {
        when(workflow.login("s-1", "cgcom", HEADER, CHAIN)).thenReturn(new Outcome.Completed("https://portal.example.com/cb?code=c"));

        ResponseEntity<Object> response = controller.certificate(
                new CertificateLoginController.CertificateLoginRequest("s-1"), request());

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody())
                .isEqualTo(new CertificateLoginController.CertificateLoginResponse("https://portal.example.com/cb?code=c"));
        verify(workflow).login("s-1", "cgcom", HEADER, CHAIN);
    }

    @ParameterizedTest
    @CsvSource({
            "CERTIFICATE_MISSING, 401, certificate_missing, No certificate",
            "LOGIN_NOT_FOUND, 404, login_not_found, Login not found",
            "VALIDATION_UNAVAILABLE, 503, trust_validation_unavailable, Trust validation unavailable",
            "LEVEL_NOT_MET, 403, level_not_met, Level not met",
            "CERTIFICATE_NOT_NATURAL_PERSON, 403, certificate_not_natural_person, Certificate not accepted",
            "CERTIFICATE_NOT_QUALIFIED, 403, certificate_not_qualified, Certificate not accepted",
            "CERTIFICATE_REVOKED, 403, certificate_revoked, Certificate not accepted",
            "CERTIFICATE_EXPIRED, 403, certificate_expired, Certificate not accepted"
    })
    void certificate_rejectedLogin_returnsAProblemWithItsCode(CertificateLoginReason reason, int status,
                                                              String type, String title) {
        when(workflow.login("s-1", "cgcom", HEADER, CHAIN)).thenReturn(new Outcome.Rejected(reason));

        ResponseEntity<Object> response = controller.certificate(
                new CertificateLoginController.CertificateLoginRequest("s-1"), request());

        assertThat(response.getStatusCode().value()).isEqualTo(status);
        assertThat(response.getHeaders().getContentType()).isEqualTo(MediaType.APPLICATION_PROBLEM_JSON);
        assertThat(response.getBody()).isInstanceOfSatisfying(ProblemDetail.class, problem -> {
            assertThat(problem.getType()).isEqualTo(URI.create(type));
            assertThat(problem.getTitle()).isEqualTo(title);
            assertThat(problem.getStatus()).isEqualTo(status);
            assertThat(problem.getDetail()).isNotBlank();
            assertThat(problem.getInstance()).isEqualTo(URI.create("/verifier/api/login/certificate"));
        });
    }

    @Test
    void certificate_trustValidationUnavailable_tellsWhenToRetry() {
        when(workflow.login("s-1", "cgcom", HEADER, CHAIN))
                .thenReturn(new Outcome.Rejected(CertificateLoginReason.VALIDATION_UNAVAILABLE));

        ResponseEntity<Object> response = controller.certificate(
                new CertificateLoginController.CertificateLoginRequest("s-1"), request());

        assertThat(response.getHeaders().getFirst(HttpHeaders.RETRY_AFTER))
                .isEqualTo(CertificateLoginController.RETRY_AFTER_SECONDS);
    }

    @Test
    void certificate_rejectedCertificate_doesNotTellWhenToRetry() {
        when(workflow.login("s-1", "cgcom", HEADER, CHAIN))
                .thenReturn(new Outcome.Rejected(CertificateLoginReason.CERTIFICATE_REVOKED));

        ResponseEntity<Object> response = controller.certificate(
                new CertificateLoginController.CertificateLoginRequest("s-1"), request());

        assertThat(response.getHeaders().containsKey(HttpHeaders.RETRY_AFTER)).isFalse();
    }

    @Test
    void certificate_withoutBody_passesNoState() {
        when(workflow.login(null, "cgcom", HEADER, CHAIN)).thenReturn(new Outcome.Rejected(CertificateLoginReason.LOGIN_NOT_FOUND));

        assertThat(controller.certificate(null, request()).getStatusCode().value()).isEqualTo(404);
    }

    @Test
    void certificate_withoutChain_passesAnEmptyChain() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/verifier/api/login/certificate");
        request.setAttribute(TenantDomainFilter.TENANT_ATTRIBUTE, "cgcom");
        request.addHeader(CertificateLoginFilter.CLIENT_CERT_HEADER, HEADER);
        when(workflow.login("s-1", "cgcom", HEADER, List.of()))
                .thenReturn(new Outcome.Rejected(CertificateLoginReason.CERTIFICATE_REVOKED));

        controller.certificate(new CertificateLoginController.CertificateLoginRequest("s-1"), request);

        verify(workflow).login("s-1", "cgcom", HEADER, List.of());
    }

    private static MockHttpServletRequest request() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/verifier/api/login/certificate");
        request.setAttribute(TenantDomainFilter.TENANT_ATTRIBUTE, "cgcom");
        request.addHeader(CertificateLoginFilter.CLIENT_CERT_HEADER, HEADER);
        request.addHeader(CertificateLoginFilter.CLIENT_CERT_CHAIN_HEADER, CHAIN.get(0));
        request.addHeader(CertificateLoginFilter.CLIENT_CERT_CHAIN_HEADER, CHAIN.get(1));
        return request;
    }
}
