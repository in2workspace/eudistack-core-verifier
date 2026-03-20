package es.in2.vcverifier.verifier.infrastructure.controller;

import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.shared.domain.exception.ResourceNotFoundException;
import es.in2.vcverifier.oauth2.domain.model.AuthorizationRequestJWT;
import es.in2.vcverifier.verifier.domain.service.AuthorizationResponseProcessorService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/oid4vp")
@RequiredArgsConstructor
@Tag(name = "OID4VP", description = "OpenID for Verifiable Presentations endpoints")
public class Oid4vpController {

    private final CacheStore<AuthorizationRequestJWT> cacheStoreForAuthorizationRequestJWT;
    private final AuthorizationResponseProcessorService authorizationResponseProcessorService;

    @Operation(
            summary = "Retrieve authorization request JWT by nonce",
            description = "Returns the signed authorization request JWT for the given nonce (QR code scan)")
    @ApiResponse(responseCode = "200", description = "Authorization request JWT",
            content = @Content(mediaType = "application/oauth-authz-req+jwt"))
    @ApiResponse(responseCode = "404", description = "Authorization request not found or expired")
    @GetMapping("/auth-request/{id}")
    @ResponseStatus(HttpStatus.OK)
    public String getAuthorizationRequest(
            @Parameter(description = "Authorization request nonce (from QR code)", required = true)
            @PathVariable String id) {
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
            @RequestParam("state") String state,
            @Parameter(description = "Verifiable Presentation token", required = true)
            @RequestParam("vp_token") String vpToken) {
        log.info("Processing auth response");
        log.debug("Oid4vpController -- handleAuthResponse -- Request params: state = {}, vpToken = {}", state, vpToken);
        authorizationResponseProcessorService.handleAuthResponse(state, vpToken);
    }

}
