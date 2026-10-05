package es.in2.vcverifier.verifier.infrastructure.controller;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.oauth2.infrastructure.adapter.SseEmitterStore;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.shared.config.TenantDomainFilter;
import es.in2.vcverifier.shared.domain.exception.ResourceNotFoundException;
import es.in2.vcverifier.oauth2.domain.model.AuthorizationRequestJWT;
import es.in2.vcverifier.sso.application.workflow.SsoLoginCompletionWorkflow;
import es.in2.vcverifier.sso.domain.exception.LoginCompletionUnavailableException;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.verifier.domain.model.AuthResponseResult;
import es.in2.vcverifier.verifier.domain.service.AuthorizationResponseProcessorService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.validation.annotation.Validated;
import org.springframework.web.bind.annotation.*;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;

@Slf4j
@RestController
@RequestMapping("/oid4vp")
@RequiredArgsConstructor
@Validated
@Tag(name = "OID4VP", description = "OpenID for Verifiable Presentations endpoints")
public class Oid4vpController {

    private final CacheStore<AuthorizationRequestJWT> cacheStoreForAuthorizationRequestJWT;
    private final AuthorizationResponseProcessorService authorizationResponseProcessorService;
    private final SsoLoginCompletionWorkflow ssoLoginCompletionWorkflow;
    private final SseEmitterStore sseEmitterStore;
    private final SsoAuditPort ssoAuditPort;
    private final ObjectMapper objectMapper;

    @Operation(
            summary = "Retrieve authorization request JWT by nonce",
            description = "Returns the signed authorization request JWT for the given nonce (QR code scan)")
    @ApiResponse(responseCode = "200", description = "Authorization request JWT",
            content = @Content(mediaType = "application/oauth-authz-req+jwt"))
    @ApiResponse(responseCode = "404", description = "Authorization request not found or expired")
    @GetMapping("/auth-request/{id}")
    @ResponseStatus(HttpStatus.OK)
    // SEC-F1: Input validation on path/request parameters. Next step: ensure proper error handling for invalid inputs.
    public String getAuthorizationRequest(
            @Parameter(description = "Authorization request nonce (from QR code)", required = true)
            @PathVariable @NotBlank @Size(max = 256) String id) {
        AuthorizationRequestJWT authorizationRequestJWT = cacheStoreForAuthorizationRequestJWT.get(id);
        cacheStoreForAuthorizationRequestJWT.delete(id);
        String jwt = authorizationRequestJWT.authRequest();

        if (jwt != null) {
            return jwt;
        } else {
            throw new ResourceNotFoundException("JWT not found for id: " + id);
        }
    }

    @Operation(
            summary = "Process authorization response from wallet",
            description = "Receives the VP token and state from the wallet after credential presentation")
    @ApiResponse(responseCode = "200", description = "Redirect URL for the wallet")
    @ApiResponse(responseCode = "400", description = "Invalid authorization response")
    @ApiResponse(responseCode = "401", description = "VP verification failed")
    @PostMapping("/auth-response")
    @ResponseStatus(HttpStatus.OK)
    public void handleAuthResponse(
            @Parameter(description = "OAuth2 state parameter", required = true)
            @RequestParam("state") @NotBlank @Size(max = 128) String state,
            @Parameter(description = "Verifiable Presentation token", required = true)
            @RequestParam("vp_token") @NotBlank @Size(max = 65536) String vpToken,
            HttpServletRequest request) {

        log.info("Processing auth response");
        log.debug("Oid4vpController -- handleAuthResponse -- Request params: state = {}, vpToken=[{} chars]",
                state, vpToken != null ? vpToken.length() : 0);

        String tenant = TenantDomainFilter.getCurrentTenant(request);
        String correlationId = UUID.randomUUID().toString();

        AuthResponseResult result;
        try {
            result = authorizationResponseProcessorService.handleAuthResponse(state, vpToken, tenant);
        } catch (Exception ex) {
            // ES-01: VP invalid or any processing failure → emit sso_establish_failed audit, then re-throw
            // The existing OID4VP error handling produces the access_denied response.
            ssoAuditPort.publish(new SsoAuditEvent(
                    SsoAuditEvent.EventType.SSO_ESTABLISH_FAILED,
                    tenant != null ? tenant : "",
                    tenant != null ? tenant : "",
                    null,
                    "FAILURE",
                    correlationId,
                    Instant.now()
            ));
            throw ex;
        }

        // EUD-252: this request comes from the WALLET (possibly another device) — it never gets the
        // SSO cookie. The browser that started the login is sent, over SSE, straight to the RP
        // (unbound login) or to the one-time close URL (browser-bound login, always).
        String browserRedirect;
        try {
            browserRedirect = ssoLoginCompletionWorkflow.resolveBrowserRedirect(
                    tenant, result, () -> extractSubFromVpToken(vpToken), correlationId);
        } catch (LoginCompletionUnavailableException e) {
            // Fail closed (code already revoked and audited): tell the browser, never send the code.
            sseEmitterStore.sendValidationFailed(state, "LOGIN_COMPLETION_UNAVAILABLE",
                    "The login could not be completed, please try again");
            throw e;
        }
        sseEmitterStore.send(state, browserRedirect);
    }

    private String extractSubFromVpToken(String vpToken) {
        try {
            // vpToken arrives Base64-encoded from the HTTP request — decode first (mirrors service layer)
            String decoded = new String(Base64.getDecoder().decode(vpToken), StandardCharsets.UTF_8).trim();

            // Resolve DCQL wrapper: JSON object keyed by credential query IDs → extract first VP token
            String resolved = decoded;
            if (decoded.startsWith("{")) {
                JsonNode dcql = objectMapper.readTree(decoded);
                var fields = dcql.fields();
                while (fields.hasNext()) {
                    var entry = fields.next();
                    JsonNode val = entry.getValue();
                    if (val.isArray() && !val.isEmpty()) {
                        resolved = val.get(0).asText();
                        break;
                    } else if (val.isTextual()) {
                        resolved = val.asText();
                        break;
                    }
                }
            }

            // SD-JWT format: header.payload.sig~disclosure~...~KB-JWT → issuer-signed part is first
            String jwt = resolved.contains("~") ? resolved.split("~")[0] : resolved;
            String[] parts = jwt.split("\\.");
            if (parts.length >= 2) {
                // Base64url may omit padding — add it before decoding
                String padded = parts[1];
                int mod = padded.length() % 4;
                if (mod != 0) padded = padded + "=".repeat(4 - mod);
                byte[] payloadBytes = Base64.getUrlDecoder().decode(padded);
                JsonNode payload = objectMapper.readTree(payloadBytes);
                // AD-3: prefer 'sub' (credential subject) as holder identity per technical-design
                if (payload.has("sub") && !payload.get("sub").isNull()) {
                    String sub = payload.get("sub").asText();
                    if (!sub.isBlank()) return sub;
                }
                // Fallback: in a VP JWT, iss = the presenter (holder DID)
                if (payload.has("iss") && !payload.get("iss").isNull()) {
                    String iss = payload.get("iss").asText();
                    if (!iss.isBlank()) return iss;
                }
            }

            // SD-JWT only: KB-JWT iss = the holder (last non-empty segment after ~)
            if (resolved.contains("~")) {
                String[] sdParts = resolved.split("~");
                String kbJwt = sdParts[sdParts.length - 1];
                if (!kbJwt.isBlank()) {
                    String[] kbParts = kbJwt.split("\\.");
                    if (kbParts.length >= 2) {
                        String padded = kbParts[1];
                        int mod = padded.length() % 4;
                        if (mod != 0) padded = padded + "=".repeat(4 - mod);
                        JsonNode kbPayload = objectMapper.readTree(Base64.getUrlDecoder().decode(padded));
                        if (kbPayload.has("iss") && !kbPayload.get("iss").isNull()) {
                            String kbIss = kbPayload.get("iss").asText();
                            if (!kbIss.isBlank()) return kbIss;
                        }
                    }
                }
            }
        } catch (Exception e) {
            log.warn("Could not extract subject from vpToken: {}", e.getMessage());
        }
        // B5: reject — prevents SHA-256("") session collision from empty/missing subject
        throw new IllegalStateException("VP token contains no usable subject for SSO session establishment");
    }

}
