package es.in2.vcverifier.verifier.infrastructure.adapter.dispatch;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.vcverifier.verifier.domain.model.dispatch.CredentialFormat;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchDecision;
import es.in2.vcverifier.verifier.domain.model.dispatch.DispatchReason;
import es.in2.vcverifier.verifier.domain.model.tokens.BuildContext;
import es.in2.vcverifier.verifier.domain.model.tokens.ReaderResult;
import es.in2.vcverifier.verifier.domain.model.validation.SchemaProfile;
import es.in2.vcverifier.verifier.domain.service.SchemaProfileRegistry;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Instant;
import java.util.Map;
import java.util.Optional;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class LegacyCredentialReaderTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Mock
    private SchemaProfileRegistry schemaProfileRegistry;

    private LegacyCredentialReader legacyCredentialReader;

    @BeforeEach
    void setUp() {
        legacyCredentialReader = new LegacyCredentialReader(schemaProfileRegistry);
    }

    @Test
    void supports_returnsTrueOnlyForLegacy() {
        assertTrue(legacyCredentialReader.supports(CredentialFormat.LEGACY_V1_1));
        assertFalse(legacyCredentialReader.supports(CredentialFormat.BUMPED_V2_0));
    }

    @Test
    void read_withVcWrappedPayload_usesWrappedNodeAndDoesNotWrapAgain() {
        String configId = "LEARCredentialEmployee.3";
        SchemaProfile profile = schemaProfile(configId, false);
        when(schemaProfileRegistry.findByConfigId(configId)).thenReturn(Optional.of(profile));

        ObjectNode wrappedVc = MAPPER.createObjectNode().put("employeeId", "EMP-001");
        ObjectNode credential = MAPPER.createObjectNode();
        credential.set("vc", wrappedVc);

        ReaderResult result = legacyCredentialReader.read(buildContext(credential, configId));

        assertSame(wrappedVc, result.credential());
        assertEquals(configId, result.credentialConfigurationId());
        assertSame(profile, result.schemaProfile());
        assertFalse(result.wrapVcInAccessToken());
    }

    @Test
    void read_withoutProfile_returnsNullProfile() {
        String configId = "LEARCredentialEmployee.3";
        when(schemaProfileRegistry.findByConfigId(configId)).thenReturn(Optional.empty());

        ObjectNode credential = MAPPER.createObjectNode().put("id", "urn:uuid:test");
        ReaderResult result = legacyCredentialReader.read(buildContext(credential, configId));

        assertSame(credential, result.credential());
        assertNull(result.schemaProfile());
        assertFalse(result.wrapVcInAccessToken());
    }

    private BuildContext buildContext(ObjectNode credential, String configId) {
        return new BuildContext(
                credential,
                DispatchDecision.permitted(configId, CredentialFormat.LEGACY_V1_1, DispatchReason.BY_TYPE),
                null,
                Instant.now(),
                Instant.now().plusSeconds(60),
                "audience",
                "dome",
                Map.of(),
                true
        );
    }

    private SchemaProfile schemaProfile(String configId, boolean wrap) {
        return new SchemaProfile(configId, "scope", null, null, Set.of("authorization_code"), false, null, null, wrap);
    }
}
