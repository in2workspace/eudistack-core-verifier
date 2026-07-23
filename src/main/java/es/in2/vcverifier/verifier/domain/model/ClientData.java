package es.in2.vcverifier.verifier.domain.model;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import es.in2.vcverifier.verifier.domain.model.oid4vp.ClientMetadata;

import java.util.List;

@JsonIgnoreProperties(ignoreUnknown = true)
public record ClientData(
        String id,
        String url,
        String clientId,
        String clientSecret,
        List<String> redirectUris,
        List<String> scopes,
        List<String> clientAuthenticationMethods,
        List<String> authorizationGrantTypes,
        Boolean requireAuthorizationConsent,
        List<String> postLogoutRedirectUris,
        Boolean requireProofKey,
        String jwkSetUrl,
        String tokenEndpointAuthenticationSigningAlgorithm,
        String tenant,
        String loginPageUri,
        ClientMetadata clientMetadata,
        // US-06 Single Logout (AD-4/DELTA-01): backchannel_logout_uri declarado por el RP.
        // Opcional; ausente = el callee se trata como sin canal (backchannel_skipped, AC-04).
        String backchannelLogoutUri
) {}
