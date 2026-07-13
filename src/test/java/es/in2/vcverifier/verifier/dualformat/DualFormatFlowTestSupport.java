package es.in2.vcverifier.verifier.dualformat;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jwt.JWTClaimsSet;
import io.micrometer.core.instrument.simple.SimpleMeterRegistry;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.crypto.JWTService;
import es.in2.vcverifier.verifier.domain.model.config.TenantDomeConfig;
import es.in2.vcverifier.verifier.domain.model.dispatch.CredentialFormat;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchDecision;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchReason;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchRule;
import es.in2.vcverifier.verifier.domain.model.tokens.BuildContext;
import es.in2.vcverifier.verifier.domain.model.validation.ExtractedClaims;
import es.in2.vcverifier.verifier.domain.service.TenantConfigPort;
import es.in2.vcverifier.verifier.infrastructure.adapter.dispatch.ContextAndTypeCredentialSchemaDispatcher;
import es.in2.vcverifier.verifier.infrastructure.adapter.tokens.JwsAccessTokenBuilder;

import java.io.IOException;
import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

final class DualFormatFlowTestSupport {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final ContextAndTypeCredentialSchemaDispatcher dispatcher;
    private final JwsAccessTokenBuilder accessTokenBuilder;

    DualFormatFlowTestSupport() {
        TenantConfigPort tenantConfigPort = mock(TenantConfigPort.class);
        when(tenantConfigPort.getDomeConfig(anyString())).thenReturn(new TenantDomeConfig(true, true));

        JWTService jwtService = mock(JWTService.class);
        when(jwtService.issueJWT(anyString())).thenAnswer(invocation -> invocation.getArgument(0));

        BackendConfig backendConfig = mock(BackendConfig.class);
        when(backendConfig.getUrl()).thenReturn("https://verifier.example");

        this.dispatcher = new ContextAndTypeCredentialSchemaDispatcher(
                List.of(
                        new DispatchRule("LEARCredentialEmployee.3", CredentialFormat.LEGACY_V1_1),
                        new DispatchRule("LEARCredentialMachine.2", CredentialFormat.LEGACY_V1_1),
                        new DispatchRule("gx:LabelCredential.1", CredentialFormat.LEGACY_V1_1),
                        new DispatchRule("LEARCredentialEmployee.4", CredentialFormat.BUMPED_V2_0),
                        new DispatchRule("LEARCredentialMachine.3", CredentialFormat.BUMPED_V2_0),
                        new DispatchRule("gx:LabelCredential.2", CredentialFormat.BUMPED_V2_0)
                ),
                tenantConfigPort,
                new SimpleMeterRegistry()
        );

        this.accessTokenBuilder = new JwsAccessTokenBuilder(jwtService, backendConfig, MAPPER);
    }

    JsonNode readFixture(String resourcePath) throws IOException {
        return MAPPER.readTree(this.getClass().getClassLoader().getResourceAsStream(resourcePath));
    }

    FlowResult runFlow(JsonNode credential) throws ParseException {
        DispatchDecision decision = dispatcher.dispatch(credential);

        BuildContext tokenContext = buildContext(credential, decision.credentialConfigurationId());
        String jwtPayload = accessTokenBuilder.build(tokenContext);
        JWTClaimsSet claimsSet = JWTClaimsSet.parse(jwtPayload);
        return new FlowResult(decision, claimsSet);
    }

    void assertHappyPath(FlowResult result, String expectedCredentialType, CredentialFormat expectedFormat) {
        assertEquals(expectedCredentialType, result.dispatchDecision().credentialConfigurationId());
        assertEquals(expectedFormat, result.dispatchDecision().format());
        assertTrue(result.dispatchDecision().permitted());
        assertTrue(result.dispatchDecision().reason() == DispatchReason.BY_TYPE ||
                result.dispatchDecision().reason() == DispatchReason.BY_TYPE_CONTEXT_MISMATCH);

        assertEquals(expectedCredentialType, String.valueOf(result.claimsSet().getClaim("credential_type")));
        assertNotNull(result.claimsSet().getClaim("vc"));

        assertTrue(result.claimsSet().getClaim("vc") instanceof Map);
    }

    private BuildContext buildContext(JsonNode credential, String credentialConfigurationId) {
        Instant issue = Instant.parse("2026-05-26T10:00:00Z");
        return new BuildContext(
                credential,
                credentialConfigurationId,
                ExtractedClaims.builder()
                        .subject("did:key:z6Mktestsubject")
                        .scope("openid")
                        .accessTokenClaims(Map.of("role", "holder"))
                        .build(),
                issue,
                issue.plusSeconds(900),
                "audience-client",
                "dome",
                Map.of(),
                true
        );
    }

    record FlowResult(
            DispatchDecision dispatchDecision,
            JWTClaimsSet claimsSet
    ) {
    }
}
