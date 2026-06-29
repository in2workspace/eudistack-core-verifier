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
import es.in2.vcverifier.verifier.domain.model.validation.SchemaProfile;
import es.in2.vcverifier.verifier.domain.service.CredentialReader;
import es.in2.vcverifier.verifier.domain.service.SchemaProfileRegistry;
import es.in2.vcverifier.verifier.domain.service.TenantConfigPort;
import es.in2.vcverifier.verifier.infrastructure.adapter.dispatch.BumpedCredentialReader;
import es.in2.vcverifier.verifier.infrastructure.adapter.dispatch.ContextAndTypeCredentialSchemaDispatcher;
import es.in2.vcverifier.verifier.infrastructure.adapter.dispatch.LegacyCredentialReader;
import es.in2.vcverifier.verifier.infrastructure.adapter.tokens.JwsAccessTokenBuilder;

import java.io.IOException;
import java.text.ParseException;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

final class DualFormatFlowTestSupport {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private final ContextAndTypeCredentialSchemaDispatcher dispatcher;
    private final List<CredentialReader> readers;
    private final JwsAccessTokenBuilder accessTokenBuilder;
    private final SchemaProfileRegistry schemaProfileRegistry;

    DualFormatFlowTestSupport() {
        TenantConfigPort tenantConfigPort = mock(TenantConfigPort.class);
        when(tenantConfigPort.getDomeConfig(anyString())).thenReturn(new TenantDomeConfig(true, true));

        this.schemaProfileRegistry = mock(SchemaProfileRegistry.class);
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

        this.readers = List.of(
                new LegacyCredentialReader(schemaProfileRegistry),
                new BumpedCredentialReader(schemaProfileRegistry)
        );

        this.accessTokenBuilder = new JwsAccessTokenBuilder(jwtService, backendConfig, schemaProfileRegistry, MAPPER);
    }

    JsonNode readFixture(String resourcePath) throws IOException {
        return MAPPER.readTree(this.getClass().getClassLoader().getResourceAsStream(resourcePath));
    }

    FlowResult runFlow(JsonNode credential) throws ParseException {
        DispatchDecision decision = dispatcher.dispatch(credential);
        SchemaProfile profile = schemaProfile(decision.credentialConfigurationId(), decision.format() == CredentialFormat.BUMPED_V2_0);
        when(schemaProfileRegistry.findByConfigId(decision.credentialConfigurationId())).thenReturn(Optional.of(profile));

        CredentialReader selectedReader = readers.stream()
                .filter(reader -> reader.supports(decision.format()))
                .findFirst()
                .orElseThrow();

        BuildContext readerContext = buildContext(credential, decision);
        var readerResult = selectedReader.read(readerContext);

        BuildContext tokenContext = new BuildContext(
                readerResult.credential(),
                decision,
                readerContext.extractedClaims(),
                readerContext.issueTime(),
                readerContext.expirationTime(),
                readerContext.audience(),
                readerContext.tenant(),
                readerContext.additionalParameters(),
                readerContext.generateIdToken()
        );

        String jwtPayload = accessTokenBuilder.build(tokenContext);
        JWTClaimsSet claimsSet = JWTClaimsSet.parse(jwtPayload);
        return new FlowResult(decision, selectedReader, claimsSet);
    }

    void assertHappyPath(FlowResult result, String expectedCredentialType, CredentialFormat expectedFormat, boolean expectedVcObject) {
        assertEquals(expectedCredentialType, result.dispatchDecision().credentialConfigurationId());
        assertEquals(expectedFormat, result.dispatchDecision().format());
        assertTrue(result.dispatchDecision().permitted());
        assertTrue(result.dispatchDecision().reason() == DispatchReason.BY_TYPE ||
                result.dispatchDecision().reason() == DispatchReason.BY_TYPE_CONTEXT_MISMATCH);

        assertEquals(expectedCredentialType, String.valueOf(result.claimsSet().getClaim("credential_type")));
        assertNotNull(result.claimsSet().getClaim("vc"));

        if (expectedVcObject) {
            assertTrue(result.claimsSet().getClaim("vc") instanceof Map);
        } else {
            assertTrue(result.claimsSet().getClaim("vc") instanceof String);
        }
    }

    static void assertReaderClass(FlowResult result, Class<?> expectedReaderType) {
        assertSame(expectedReaderType, result.reader().getClass());
    }

    private BuildContext buildContext(JsonNode credential, DispatchDecision decision) {
        Instant issue = Instant.parse("2026-05-26T10:00:00Z");
        return new BuildContext(
                credential,
                decision,
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

    private SchemaProfile schemaProfile(String configId, boolean wrap) {
        return new SchemaProfile(configId, "openid", null, null, Set.of("authorization_code", "client_credentials"), false, null, null, wrap);
    }

    record FlowResult(
            DispatchDecision dispatchDecision,
            CredentialReader reader,
            JWTClaimsSet claimsSet
    ) {
    }
}
