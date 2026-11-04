package es.in2.vcverifier.verifier.infrastructure.controller;

import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.vcverifier.shared.config.CertificatePortFilter;
import es.in2.vcverifier.shared.config.TenantDomainFilter;
import es.in2.vcverifier.verifier.application.workflow.CertificateLoginWorkflow;
import es.in2.vcverifier.verifier.application.workflow.CertificateLoginWorkflow.Outcome;
import es.in2.vcverifier.verifier.domain.model.CertificateLoginReason;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestBody;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RestController;

@RestController
@RequestMapping("/api/login")
@RequiredArgsConstructor
@Tag(name = "Login", description = "Login with the client certificate of the TLS connection")
public class CertificateLoginController {

    private final CertificateLoginWorkflow certificateLoginWorkflow;

    public record CertificateLoginRequest(String state) {
    }

    public record CertificateLoginResponse(@JsonProperty("redirect_uri") String redirectUri) {
    }

    public record ErrorResponse(String reason) {
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
            produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Object> certificate(@RequestBody CertificateLoginRequest body, HttpServletRequest request) {
        Outcome outcome = certificateLoginWorkflow.login(
                body == null ? null : body.state(),
                TenantDomainFilter.getCurrentTenant(request),
                request.getHeader(CertificatePortFilter.MTLS_CLIENT_CERT_HEADER));
        return switch (outcome) {
            case Outcome.Completed completed -> ResponseEntity.ok(new CertificateLoginResponse(completed.redirectUri()));
            case Outcome.Rejected rejected -> ResponseEntity.status(status(rejected.reason()))
                    .body(new ErrorResponse(rejected.reason().value()));
        };
    }

    private static HttpStatus status(CertificateLoginReason reason) {
        return switch (reason) {
            case CERTIFICATE_MISSING -> HttpStatus.UNAUTHORIZED;
            case LOGIN_NOT_FOUND -> HttpStatus.NOT_FOUND;
            case VALIDATION_UNAVAILABLE -> HttpStatus.SERVICE_UNAVAILABLE;
            case LEVEL_NOT_MET, CERTIFICATE_NOT_NATURAL_PERSON, CERTIFICATE_NOT_QUALIFIED,
                 CERTIFICATE_REVOKED, CERTIFICATE_EXPIRED -> HttpStatus.FORBIDDEN;
        };
    }
}
