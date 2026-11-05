package es.in2.vcverifier.verifier.infrastructure.controller;

import es.in2.vcverifier.shared.config.CertificatePortFilter;
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
import org.springframework.http.ResponseEntity;
import org.springframework.mock.web.MockHttpServletRequest;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertificateLoginControllerTest {

    private static final String HEADER = "-----BEGIN%20CERTIFICATE-----";

    @Mock
    private CertificateLoginWorkflow workflow;

    @InjectMocks
    private CertificateLoginController controller;

    @Test
    void certificate_completedLogin_returnsTheRedirectUri() {
        when(workflow.login("s-1", "cgcom", HEADER)).thenReturn(new Outcome.Completed("https://portal.example.com/cb?code=c"));

        ResponseEntity<Object> response = controller.certificate(
                new CertificateLoginController.CertificateLoginRequest("s-1"), request());

        assertThat(response.getStatusCode().value()).isEqualTo(200);
        assertThat(response.getBody())
                .isEqualTo(new CertificateLoginController.CertificateLoginResponse("https://portal.example.com/cb?code=c"));
        verify(workflow).login("s-1", "cgcom", HEADER);
    }

    @ParameterizedTest
    @CsvSource({
            "CERTIFICATE_MISSING, 401, CertificateMissing",
            "LOGIN_NOT_FOUND, 404, LoginNotFound",
            "VALIDATION_UNAVAILABLE, 503, ValidationUnavailable",
            "LEVEL_NOT_MET, 403, LevelNotMet",
            "CERTIFICATE_NOT_NATURAL_PERSON, 403, CertificateNotNaturalPerson",
            "CERTIFICATE_NOT_QUALIFIED, 403, CertificateNotQualified",
            "CERTIFICATE_REVOKED, 403, CertificateRevoked",
            "CERTIFICATE_EXPIRED, 403, CertificateExpired"
    })
    void certificate_rejectedLogin_returnsItsStatusAndReason(CertificateLoginReason reason, int status, String body) {
        when(workflow.login("s-1", "cgcom", HEADER)).thenReturn(new Outcome.Rejected(reason));

        ResponseEntity<Object> response = controller.certificate(
                new CertificateLoginController.CertificateLoginRequest("s-1"), request());

        assertThat(response.getStatusCode().value()).isEqualTo(status);
        assertThat(response.getBody()).isEqualTo(new CertificateLoginController.ErrorResponse(body));
    }

    @Test
    void certificate_withoutBody_passesNoState() {
        when(workflow.login(null, "cgcom", HEADER)).thenReturn(new Outcome.Rejected(CertificateLoginReason.LOGIN_NOT_FOUND));

        assertThat(controller.certificate(null, request()).getStatusCode().value()).isEqualTo(404);
    }

    private static MockHttpServletRequest request() {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/verifier/api/login/certificate");
        request.setAttribute(TenantDomainFilter.TENANT_ATTRIBUTE, "cgcom");
        request.addHeader(CertificatePortFilter.MTLS_CLIENT_CERT_HEADER, HEADER);
        return request;
    }
}
