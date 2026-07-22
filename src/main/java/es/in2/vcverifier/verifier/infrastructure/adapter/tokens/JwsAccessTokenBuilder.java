package es.in2.vcverifier.verifier.infrastructure.adapter.tokens;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.crypto.JWTService;
import es.in2.vcverifier.verifier.domain.model.tokens.BuildContext;
import es.in2.vcverifier.verifier.domain.model.validation.ExtractedClaims;
import es.in2.vcverifier.verifier.domain.service.AccessTokenBuilder;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.stereotype.Component;

import java.util.Date;
import java.util.UUID;

@Slf4j
@Component
@RequiredArgsConstructor
public class JwsAccessTokenBuilder implements AccessTokenBuilder {

    private final JWTService jwtService;
    private final BackendConfig backendConfig;
    private final ObjectMapper objectMapper;

    @Override
    public String build(BuildContext buildContext) {
        ExtractedClaims extractedClaims = buildContext.extractedClaims();
        String configId = buildContext.credentialConfigurationId();

        JWTClaimsSet.Builder payloadBuilder = new JWTClaimsSet.Builder()
                .issuer(backendConfig.getUrl())
                .audience(buildContext.audience())
                .subject(extractedClaims.subject())
                .jwtID(UUID.randomUUID().toString())
                .issueTime(Date.from(buildContext.issueTime()))
                .expirationTime(Date.from(buildContext.expirationTime()))
                .claim(OAuth2ParameterNames.SCOPE, extractedClaims.scope())
                .claim("credential_type", configId);

        if (extractedClaims.accessTokenClaims() != null) {
            extractedClaims.accessTokenClaims().forEach(payloadBuilder::claim);
        }

        if (extractedClaims.accessTokenEmbeds() != null) {
            extractedClaims.accessTokenEmbeds().forEach(payloadBuilder::claim);
        }

        if (buildContext.tenant() != null && !buildContext.tenant().isBlank()) {
            payloadBuilder.claim("tenant", buildContext.tenant());
        } else {
            payloadBuilder.claim("tenant", null);
            log.warn("Client has no tenant configured. Excluding tenant claim from access token.");
        }

        payloadBuilder.claim("vc", objectMapper.convertValue(buildContext.credential(), Object.class));

        JWTClaimsSet payload = payloadBuilder.build();
        return jwtService.issueJWT(payload.toString());
    }
}
