package es.in2.vcverifier.verifier.infrastructure.controller;

import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.shared.domain.exception.ResourceNotFoundException;
import es.in2.vcverifier.oauth2.domain.model.AuthorizationRequestJWT;
import es.in2.vcverifier.verifier.domain.service.AuthorizationResponseProcessorService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

@Slf4j
@RestController
@RequestMapping("/oid4vp")
@RequiredArgsConstructor
public class Oid4vpController {

    private final CacheStore<AuthorizationRequestJWT> cacheStoreForAuthorizationRequestJWT;
    private final AuthorizationResponseProcessorService authorizationResponseProcessorService;

    // Este método manejará las solicitudes GET al endpoint
    @GetMapping("/auth-request/{id}")
    @ResponseStatus(HttpStatus.OK)
    public String getAuthorizationRequest(@PathVariable String id) {
        AuthorizationRequestJWT authorizationRequestJWT = cacheStoreForAuthorizationRequestJWT.get(id);
        cacheStoreForAuthorizationRequestJWT.delete(id);
        String jwt = authorizationRequestJWT.authRequest();

        if (jwt != null) {
            return jwt;
        } else {
            throw new ResourceNotFoundException("JWT not found for id: " + id);
        }
    }

    @PostMapping("/auth-response")
    @ResponseStatus(HttpStatus.OK)
    public void handleAuthResponse(
            @RequestParam("state") String state,
            @RequestParam("vp_token") String vpToken) {
        log.info("Processing auth response");
        log.debug("Oid4vpController -- handleAuthResponse -- Request params: state = {}, vpToken = {}", state, vpToken);
        authorizationResponseProcessorService.handleAuthResponse(state, vpToken);
    }

}
