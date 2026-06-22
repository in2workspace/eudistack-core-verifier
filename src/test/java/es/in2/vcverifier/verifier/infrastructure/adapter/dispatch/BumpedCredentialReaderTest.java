package es.in2.vcverifier.verifier.infrastructure.adapter.dispatch;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.vcverifier.verifier.domain.exception.InvalidCredentialTypeException;
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
import static org.junit.jupiter.api.Assertions.assertSame;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class BumpedCredentialReaderTest {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    @Mock
    private SchemaProfileRegistry schemaProfileRegistry;

    private BumpedCredentialReader bumpedCredentialReader;

    @BeforeEach
    void setUp() {
        bumpedCredentialReader = new BumpedCredentialReader(schemaProfileRegistry);
    }

    @Test
    void supports_returnsTrueOnlyForBumped() {
        assertTrue(bumpedCredentialReader.supports(CredentialFormat.BUMPED_V2_0));
        assertFalse(bumpedCredentialReader.supports(CredentialFormat.LEGACY_V1_1));
    }

    @Test
    void read_withProfile_returnsRootPayloadAndWrapEnabled() {
        String configId = "LEARCredentialEmployee.4";
        SchemaProfile profile = schemaProfile(configId, true);
        when(schemaProfileRegistry.findByConfigId(configId)).thenReturn(Optional.of(profile));

        ObjectNode credential = MAPPER.createObjectNode().put("id", "urn:uuid:bumped");
        ReaderResult result = bumpedCredentialReader.read(buildContext(credential, configId));

        assertSame(credential, result.credential());
        assertEquals(configId, result.credentialConfigurationId());
        assertSame(profile, result.schemaProfile());
        assertTrue(result.wrapVcInAccessToken());
    }

    @Test
    void read_withoutProfile_throwsInvalidCredentialTypeException() {
        String configId = "LEARCredentialEmployee.4";
        when(schemaProfileRegistry.findByConfigId(configId)).thenReturn(Optional.empty());

        ObjectNode credential = MAPPER.createObjectNode().put("id", "urn:uuid:bumped");

        assertThrows(InvalidCredentialTypeException.class, () -> bumpedCredentialReader.read(buildContext(credential, configId)));
    }

    private BuildContext buildContext(ObjectNode credential, String configId) {
        return new BuildContext(
                credential,
                DispatchDecision.permitted(configId, CredentialFormat.BUMPED_V2_0, DispatchReason.BY_TYPE),
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
