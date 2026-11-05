package es.in2.vcverifier.oauth2.infrastructure.controller;

import com.fasterxml.jackson.annotation.JsonInclude;
import com.fasterxml.jackson.annotation.JsonProperty;
import es.in2.vcverifier.oauth2.application.workflow.LoginMethodsWorkflow;
import es.in2.vcverifier.oauth2.application.workflow.LoginMethodsWorkflow.WalletRequestResult;
import es.in2.vcverifier.shared.config.TenantDomainFilter;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.List;

@RestController
@RequestMapping("/api/login")
@RequiredArgsConstructor
@Tag(name = "Login", description = "Login methods offered by the login screen")
public class LoginMethodsController {

    private static final String LOGIN_NOT_FOUND = "LoginNotFound";
    private static final String METHOD_NOT_OFFERED = "MethodNotOffered";

    private final LoginMethodsWorkflow loginMethodsWorkflow;

    @JsonInclude(JsonInclude.Include.NON_NULL)
    public record LoginMethodsResponse(
            List<String> methods,
            @JsonProperty("essential_level") String essentialLevel) {
    }

    public record WalletRequestResponse(
            String authRequest,
            @JsonProperty("expires_in") long expiresIn) {
    }

    public record ErrorResponse(String reason) {
    }

    @Operation(summary = "List the methods offered in an open login")
    @ApiResponse(responseCode = "200", description = "Methods offered, in the order of the client registration")
    @ApiResponse(responseCode = "404", description = "No open login for this state in the tenant")
    @GetMapping("/methods")
    public ResponseEntity<Object> methods(
            @Parameter(description = "The state of the open login", required = true) @RequestParam String state,
            HttpServletRequest request) {
        return loginMethodsWorkflow.loginMethods(state, TenantDomainFilter.getCurrentTenant(request))
                .<ResponseEntity<Object>>map(login ->
                        ResponseEntity.ok(new LoginMethodsResponse(login.methods(), login.essentialLevel())))
                .orElseGet(() -> error(HttpStatus.NOT_FOUND, LOGIN_NOT_FOUND));
    }

    @Operation(summary = "Create the wallet request of an open login",
            description = "Creates the OID4VP request for the login when the person chooses the wallet. "
                    + "Calling it again returns the same request while it is valid.")
    @ApiResponse(responseCode = "200", description = "Wallet request, shown as a QR code or opened on the same device")
    @ApiResponse(responseCode = "404", description = "No open login for this state in the tenant")
    @ApiResponse(responseCode = "409", description = "The login does not offer the wallet method")
    @PostMapping("/wallet")
    public ResponseEntity<Object> wallet(
            @Parameter(description = "The state of the open login", required = true) @RequestParam String state,
            HttpServletRequest request) {
        WalletRequestResult result = loginMethodsWorkflow.startWallet(state, TenantDomainFilter.getCurrentTenant(request));
        return switch (result) {
            case WalletRequestResult.Created created ->
                    ResponseEntity.ok(new WalletRequestResponse(created.authRequest(), created.expiresIn()));
            case WalletRequestResult.LoginNotFound _ -> error(HttpStatus.NOT_FOUND, LOGIN_NOT_FOUND);
            case WalletRequestResult.MethodNotOffered _ -> error(HttpStatus.CONFLICT, METHOD_NOT_OFFERED);
        };
    }

    private static ResponseEntity<Object> error(HttpStatus status, String reason) {
        return ResponseEntity.status(status).body(new ErrorResponse(reason));
    }
}
