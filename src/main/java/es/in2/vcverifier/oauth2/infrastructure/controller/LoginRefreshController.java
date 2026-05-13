package es.in2.vcverifier.oauth2.infrastructure.controller;

import es.in2.vcverifier.verifier.application.workflow.AuthorizationRequestRefreshWorkflow;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;

import java.util.Map;
import java.util.NoSuchElementException;

@Slf4j
@RestController
@RequestMapping("/api/login")
@RequiredArgsConstructor
@Validated
@Tag(name = "Login", description = "SSE-based login events")
public class LoginRefreshController {

    private final AuthorizationRequestRefreshWorkflow authorizationRequestRefreshWorkflow;

    @Operation(
            summary = "Refresh the QR authorization request",
            description = "Generates a new openid4vp authorization request URL for the given session state, "
                    + "allowing the QR code to be refreshed without restarting the login flow.")
    @ApiResponse(responseCode = "200", description = "New authRequest URL")
    @ApiResponse(responseCode = "404", description = "Session not found or expired")
    @PostMapping(value = "/refresh", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, String>> refresh(
            @Parameter(description = "OAuth2 state parameter", required = true)
            @RequestParam @NotBlank @Size(max = 128) String state) {
        try {
            AuthorizationRequestRefreshWorkflow.Result result = authorizationRequestRefreshWorkflow.refresh(state);
            return ResponseEntity.ok(Map.of("authRequest", result.openid4vpUrl()));
        } catch (NoSuchElementException e) {
            log.warn("Refresh QR: session not found or expired for state={}", state.substring(0, Math.min(8, state.length())));
            return ResponseEntity.notFound().build();
        }
    }
}
