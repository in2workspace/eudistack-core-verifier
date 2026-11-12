package es.in2.vcverifier.verifier.infrastructure.controller;

import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.vcverifier.shared.config.CertificateLoginFilter;
import es.in2.vcverifier.shared.config.TenantDomainFilter;
import es.in2.vcverifier.verifier.application.workflow.CertificateLoginWorkflow;
import es.in2.vcverifier.verifier.application.workflow.CertificateLoginWorkflow.Outcome;
import es.in2.vcverifier.verifier.domain.model.CertificateLoginReason;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ProblemDetail;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

import java.net.URI;

@RestController
@RequestMapping("/api/login")
@RequiredArgsConstructor
@Tag(name = "Login", description = "Login with the client certificate of the TLS connection")
public class CertificateLoginController {

    static final String RETRY_AFTER_SECONDS = "30";
    private static final String CERTIFICATE_NOT_ACCEPTED = "Certificate not accepted";

    private final CertificateLoginWorkflow certificateLoginWorkflow;

    public record CertificateLoginRequest(String state) {
    }

    public record CertificateLoginResponse(@JsonProperty("redirect_uri") String redirectUri) {
    }

    private record Problem(HttpStatus status, String type, String title, String detail) {
    }

    @Operation(summary = "Authenticate the person with the client certificate of the TLS connection",
            description = "Completes the open login of the state when the certificate is a valid qualified "
                    + "certificate of a natural person that meets the level the application requires as essential.")
    @ApiResponse(responseCode = "200", description = "Login completed; the login screen goes to redirect_uri")
    @ApiResponse(responseCode = "401", description = "No client certificate in the connection")
    @ApiResponse(responseCode = "403", description = "Certificate rejected, or level not met")
    @ApiResponse(responseCode = "404", description = "No open login for this state in the tenant, or it does not offer the certificate")
    @ApiResponse(responseCode = "503", description = "The trust validation service is not available")
    @PostMapping(path = "/certificate", consumes = MediaType.APPLICATION_JSON_VALUE,
            produces = {MediaType.APPLICATION_JSON_VALUE, MediaType.APPLICATION_PROBLEM_JSON_VALUE})
    public ResponseEntity<Object> certificate(@RequestBody CertificateLoginRequest body, HttpServletRequest request) {
        Outcome outcome = certificateLoginWorkflow.login(
                body == null ? null : body.state(),
                TenantDomainFilter.getCurrentTenant(request),
                request.getHeader(CertificateLoginFilter.MTLS_CLIENT_CERT_HEADER));
        return switch (outcome) {
            case Outcome.Completed(String redirectUri) -> ResponseEntity.ok(new CertificateLoginResponse(redirectUri));
            case Outcome.Rejected(CertificateLoginReason reason) -> rejected(problem(reason), request);
        };
    }

    private static ResponseEntity<Object> rejected(Problem problem, HttpServletRequest request) {
        ProblemDetail body = ProblemDetail.forStatusAndDetail(problem.status(), problem.detail());
        body.setType(URI.create(problem.type()));
        body.setTitle(problem.title());
        body.setInstance(URI.create(request.getRequestURI()));
        ResponseEntity.BodyBuilder response = ResponseEntity.status(problem.status())
                .contentType(MediaType.APPLICATION_PROBLEM_JSON);
        if (problem.status() == HttpStatus.SERVICE_UNAVAILABLE) {
            response.header(HttpHeaders.RETRY_AFTER, RETRY_AFTER_SECONDS);
        }
        return response.body(body);
    }

    private static Problem problem(CertificateLoginReason reason) {
        return switch (reason) {
            case CERTIFICATE_MISSING -> new Problem(HttpStatus.UNAUTHORIZED, "certificate_missing",
                    "No certificate", "No client certificate was presented.");
            case LOGIN_NOT_FOUND -> new Problem(HttpStatus.NOT_FOUND, "login_not_found",
                    "Login not found", "There is no open login for this state.");
            case VALIDATION_UNAVAILABLE -> new Problem(HttpStatus.SERVICE_UNAVAILABLE, "trust_validation_unavailable",
                    "Trust validation unavailable", "The certificate cannot be checked right now.");
            case LEVEL_NOT_MET -> new Problem(HttpStatus.FORBIDDEN, "level_not_met",
                    "Level not met", "The certificate does not meet the level the application requires.");
            case CERTIFICATE_NOT_NATURAL_PERSON -> new Problem(HttpStatus.FORBIDDEN, "certificate_not_natural_person",
                    CERTIFICATE_NOT_ACCEPTED, "The certificate is not a certificate of a natural person.");
            case CERTIFICATE_NOT_QUALIFIED -> new Problem(HttpStatus.FORBIDDEN, "certificate_not_qualified",
                    CERTIFICATE_NOT_ACCEPTED, "The certificate is not a qualified certificate.");
            case CERTIFICATE_REVOKED -> new Problem(HttpStatus.FORBIDDEN, "certificate_revoked",
                    CERTIFICATE_NOT_ACCEPTED, "The certificate is revoked or suspended.");
            case CERTIFICATE_EXPIRED -> new Problem(HttpStatus.FORBIDDEN, "certificate_expired",
                    CERTIFICATE_NOT_ACCEPTED, "The certificate is expired or not yet valid.");
        };
    }
}
