package es.in2.vcverifier.oauth2.infrastructure.controller;

import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.verifier.application.workflow.AuthorizationRequestBuildWorkflow;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.MediaType;
import org.springframework.http.ResponseEntity;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.util.Map;
import java.util.NoSuchElementException;

@Slf4j
@RestController
@RequestMapping("/api/login")
@RequiredArgsConstructor
@Tag(name = "Login", description = "SSE-based login events")
public class LoginRefreshController {

    private final CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest;
    private final RegisteredClientRepository registeredClientRepository;
    private final AuthorizationRequestBuildWorkflow authorizationRequestBuildWorkflow;

    @Operation(
            summary = "Refresh the QR authorization request",
            description = "Generates a new openid4vp authorization request URL for the given session state, "
                    + "allowing the QR code to be refreshed without restarting the login flow.")
    @ApiResponse(responseCode = "200", description = "New authRequest URL")
    @ApiResponse(responseCode = "404", description = "Session not found or expired")
    @PostMapping(value = "/refresh", produces = MediaType.APPLICATION_JSON_VALUE)
    public ResponseEntity<Map<String, String>> refresh(
            @Parameter(description = "OAuth2 state parameter", required = true)
            @RequestParam String state) {
        try {
            OAuth2AuthorizationRequest authorizationRequest = cacheStoreForOAuth2AuthorizationRequest.get(state);
            String clientId = authorizationRequest.getClientId();
            String scope = String.join(" ", authorizationRequest.getScopes());

            var registeredClient = registeredClientRepository.findByClientId(clientId);
            if (registeredClient == null) {
                log.warn("Refresh QR: registered client not found for clientId={}", clientId);
                return ResponseEntity.notFound().build();
            }

            AuthorizationRequestBuildWorkflow.Result result =
                    authorizationRequestBuildWorkflow.buildAuthorizationRequest(registeredClient, scope, state);

            log.info("QR refreshed for state={}", state.substring(0, Math.min(8, state.length())));
            return ResponseEntity.ok(Map.of("authRequest", result.openid4vpUrl()));
        } catch (NoSuchElementException e) {
            log.warn("Refresh QR: session not found or expired for state={}", state.substring(0, Math.min(8, state.length())));
            return ResponseEntity.notFound().build();
        }
    }
}
