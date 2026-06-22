package es.in2.vcverifier.verifier.infrastructure.adapter.tokens;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import com.nimbusds.jwt.JWTClaimsSet;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.crypto.JWTService;
import es.in2.vcverifier.verifier.domain.model.dispatch.CredentialFormat;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchDecision;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchReason;
import es.in2.vcverifier.verifier.domain.model.tokens.BuildContext;
import es.in2.vcverifier.verifier.domain.model.validation.ExtractedClaims;
import es.in2.vcverifier.verifier.domain.model.validation.SchemaProfile;
import es.in2.vcverifier.verifier.domain.service.SchemaProfileRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.text.ParseException;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class JwsAccessTokenBuilderTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Mock
    private JWTService jwtService;

    @Mock
    private BackendConfig backendConfig;

    @Mock
    private SchemaProfileRegistry schemaProfileRegistry;

    private JwsAccessTokenBuilder jwsAccessTokenBuilder;

    @BeforeEach
    void setUp() {
        when(jwtService.issueJWT(anyString())).thenAnswer(invocation -> invocation.getArgument(0));
        when(backendConfig.getUrl()).thenReturn("https://verifier.example");
        jwsAccessTokenBuilder = new JwsAccessTokenBuilder(jwtService, backendConfig, schemaProfileRegistry, MAPPER);
    }

    @Test
    void build_wrapEnabled_putsVcAsObject() throws ParseException {
        String configId = "LEARCredentialEmployee.4";
        when(schemaProfileRegistry.findByConfigId(configId)).thenReturn(Optional.of(schemaProfile(configId, true)));

        String tokenPayload = jwsAccessTokenBuilder.build(buildContext(configId, credential(configId), CredentialFormat.BUMPED_V2_0));
        JWTClaimsSet claims = JWTClaimsSet.parse(tokenPayload);

        assertEquals(configId, claims.getStringClaim("credential_type"));
        assertInstanceOf(Map.class, claims.getClaim("vc"));
    }

    @Test
    void build_wrapDisabled_putsVcAsString() throws ParseException {
        String configId = "LEARCredentialEmployee.3";
        when(schemaProfileRegistry.findByConfigId(configId)).thenReturn(Optional.of(schemaProfile(configId, false)));

        JsonNode legacyCredential = credential(configId);
        String tokenPayload = jwsAccessTokenBuilder.build(buildContext(configId, legacyCredential, CredentialFormat.LEGACY_V1_1));
        JWTClaimsSet claims = JWTClaimsSet.parse(tokenPayload);

        assertEquals(configId, claims.getStringClaim("credential_type"));
        assertInstanceOf(String.class, claims.getClaim("vc"));
        assertEquals(legacyCredential.toString(), claims.getClaim("vc"));
    }

    @Test
    void build_legacyAndBumpedHaveSameRootClaimShape() throws ParseException {
        String legacyConfigId = "LEARCredentialEmployee.3";
        String bumpedConfigId = "LEARCredentialEmployee.4";

        when(schemaProfileRegistry.findByConfigId(legacyConfigId)).thenReturn(Optional.of(schemaProfile(legacyConfigId, false)));
        when(schemaProfileRegistry.findByConfigId(bumpedConfigId)).thenReturn(Optional.of(schemaProfile(bumpedConfigId, true)));

        JWTClaimsSet legacyClaims = JWTClaimsSet.parse(
                jwsAccessTokenBuilder.build(buildContext(legacyConfigId, credential(legacyConfigId), CredentialFormat.LEGACY_V1_1))
        );

        JWTClaimsSet bumpedClaims = JWTClaimsSet.parse(
                jwsAccessTokenBuilder.build(buildContext(bumpedConfigId, credential(bumpedConfigId), CredentialFormat.BUMPED_V2_0))
        );

        Map<String, Object> legacyRoot = new HashMap<>(legacyClaims.getClaims());
        Map<String, Object> bumpedRoot = new HashMap<>(bumpedClaims.getClaims());

        assertEquals(legacyRoot.keySet(), bumpedRoot.keySet());
        assertTrue(legacyRoot.keySet().contains("vc"));
        assertTrue(legacyRoot.keySet().contains("credential_type"));
        assertTrue(legacyRoot.keySet().contains("tenant"));
    }

    private BuildContext buildContext(String configId, JsonNode credential, CredentialFormat format) {
        Instant issue = Instant.parse("2026-05-26T10:00:00Z");
        return new BuildContext(
                credential,
                DispatchDecision.permitted(configId, format, DispatchReason.BY_TYPE),
                ExtractedClaims.builder()
                        .subject("did:key:z6Mktestsubject")
                        .scope("openid")
                        .accessTokenClaims(Map.of("role", "employee"))
                        .accessTokenEmbeds(Map.of("cnf", Map.of("jwk", "dummy")))
                        .build(),
                issue,
                issue.plusSeconds(900),
                "audience-client",
                "dome",
                Map.of(),
                true
        );
    }

    private ObjectNode credential(String configId) {
        ObjectNode credential = MAPPER.createObjectNode();
        credential.putArray("type").add("VerifiableCredential").add(configId);
        credential.put("credential_configuration_id", configId);
        credential.putObject("credentialSubject").put("id", "did:key:z6Mktestsubject");
        return credential;
    }

    private SchemaProfile schemaProfile(String configId, boolean wrapVc) {
        return new SchemaProfile(configId, "openid", null, null, Set.of("authorization_code"), false, null, null, wrapVc);
    }
}
