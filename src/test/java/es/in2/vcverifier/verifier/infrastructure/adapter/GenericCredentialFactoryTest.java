package es.in2.vcverifier.verifier.infrastructure.adapter;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.Payload;
import es.in2.vcverifier.shared.crypto.JWTService;
import es.in2.vcverifier.shared.domain.exception.JsonConversionException;
import es.in2.vcverifier.verifier.domain.exception.InvalidCredentialTypeException;
import es.in2.vcverifier.verifier.domain.model.GenericCredential;
import es.in2.vcverifier.verifier.domain.model.validation.SchemaProfile;
import es.in2.vcverifier.verifier.domain.service.SchemaProfileRegistry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GenericCredentialFactoryTest {

    @Mock
    private JWTService jwtService;

    @Spy
    private ObjectMapper objectMapper = new ObjectMapper();

    @Mock
    private SchemaProfileRegistry schemaProfileRegistry;

    @InjectMocks
    private GenericCredentialFactory factory;

    @Test
    void create_withW3cTypeArray_resolvesConfigIdAndReturnsGenericCredential() {
        // Given
        Payload payload = mock(Payload.class);
        SchemaProfile profile = mock(SchemaProfile.class);

        Map<String, Object> vcMap = new LinkedHashMap<>();
        vcMap.put("type", List.of("VerifiableCredential", "VerifiableAttestation", "LEARCredentialEmployee"));
        vcMap.put("@context", List.of("https://www.w3.org/2018/credentials/v1", "https://dome-marketplace.eu/2022/credentials/learcredentialemployee/v1"));
        vcMap.put("credentialSubject", Map.of("id", "did:example:123"));

        when(jwtService.extractVCFromPayload(payload)).thenReturn(vcMap);
        when(schemaProfileRegistry.findByConfigId("LEARCredentialEmployee")).thenReturn(Optional.of(profile));

        // When
        GenericCredential result = factory.create(payload);

        // Then
        assertEquals("LEARCredentialEmployee", result.credentialConfigurationId());
        assertEquals(List.of("VerifiableCredential", "VerifiableAttestation", "LEARCredentialEmployee"), result.types());
        assertEquals(List.of("https://www.w3.org/2018/credentials/v1", "https://dome-marketplace.eu/2022/credentials/learcredentialemployee/v1"), result.context());
        assertSame(profile, result.profile());
        assertNotNull(result.root());
    }

    @Test
    void create_withSdJwtVctClaim_resolvesConfigIdFromVct() {
        // Given
        Payload payload = mock(Payload.class);
        SchemaProfile profile = mock(SchemaProfile.class);

        Map<String, Object> vcMap = new LinkedHashMap<>();
        vcMap.put("vct", "learcredential.employee.sd.1");
        vcMap.put("credentialSubject", Map.of("email", "test@example.com"));

        when(jwtService.extractVCFromPayload(payload)).thenReturn(vcMap);
        when(schemaProfileRegistry.findByConfigId("learcredential.employee.sd.1")).thenReturn(Optional.of(profile));

        // When
        GenericCredential result = factory.create(payload);

        // Then
        assertEquals("learcredential.employee.sd.1", result.credentialConfigurationId());
        assertEquals(List.of(), result.types());
        assertEquals(List.of(), result.context());
        assertSame(profile, result.profile());
    }

    @Test
    void create_withUnknownType_throwsInvalidCredentialTypeException() {
        // Given
        Payload payload = mock(Payload.class);

        Map<String, Object> vcMap = new LinkedHashMap<>();
        vcMap.put("type", List.of("VerifiableCredential", "UnknownType"));

        when(jwtService.extractVCFromPayload(payload)).thenReturn(vcMap);
        when(schemaProfileRegistry.findByConfigId("UnknownType")).thenReturn(Optional.empty());

        // When & Then
        InvalidCredentialTypeException exception = assertThrows(
                InvalidCredentialTypeException.class,
                () -> factory.create(payload)
        );
        assertTrue(exception.getMessage().contains("UnknownType"));
    }

    @Test
    void create_withoutTypeOrVct_throwsInvalidCredentialTypeException() {
        // Given
        Payload payload = mock(Payload.class);

        Map<String, Object> vcMap = new LinkedHashMap<>();
        vcMap.put("credentialSubject", Map.of("id", "did:example:123"));

        when(jwtService.extractVCFromPayload(payload)).thenReturn(vcMap);

        // When & Then
        InvalidCredentialTypeException exception = assertThrows(
                InvalidCredentialTypeException.class,
                () -> factory.create(payload)
        );
        assertTrue(exception.getMessage().contains("Cannot resolve credential type"));
    }

    @Test
    void create_withOnlyGenericTypes_fallsToVct() {
        // Given
        Payload payload = mock(Payload.class);
        SchemaProfile profile = mock(SchemaProfile.class);

        Map<String, Object> vcMap = new LinkedHashMap<>();
        vcMap.put("type", List.of("VerifiableCredential", "VerifiableAttestation"));
        vcMap.put("vct", "learcredential.employee.sd.1");

        when(jwtService.extractVCFromPayload(payload)).thenReturn(vcMap);
        when(schemaProfileRegistry.findByConfigId("learcredential.employee.sd.1")).thenReturn(Optional.of(profile));

        // When
        GenericCredential result = factory.create(payload);

        // Then
        assertEquals("learcredential.employee.sd.1", result.credentialConfigurationId());
    }

    @Test
    void create_withV20PayloadNoVcWrapper_resolvesConfigIdCorrectly() {
        // Given — v2.0 payload: type array at root, no vc wrapper
        Payload payload = mock(Payload.class);
        SchemaProfile profile = mock(SchemaProfile.class);

        Map<String, Object> v20Payload = new LinkedHashMap<>();
        v20Payload.put("@context", List.of(
                "https://www.w3.org/ns/credentials/v2",
                "https://credentials.eudistack.eu/2025/credentials/learcredentialemployee/v4"));
        v20Payload.put("type", List.of("VerifiableCredential", "learcredential.employee.w3c.4"));
        v20Payload.put("issuer", "did:example:issuer");
        v20Payload.put("validFrom", "2026-01-01T00:00:00Z");
        v20Payload.put("credentialSubject", Map.of("id", "did:example:subject"));

        when(jwtService.extractVCFromPayload(payload)).thenReturn(v20Payload);
        when(schemaProfileRegistry.findByConfigId("learcredential.employee.w3c.4")).thenReturn(Optional.of(profile));

        // When
        GenericCredential result = factory.create(payload);

        // Then
        assertEquals("learcredential.employee.w3c.4", result.credentialConfigurationId());
        assertEquals(List.of("VerifiableCredential", "learcredential.employee.w3c.4"), result.types());
        assertEquals(List.of(
                "https://www.w3.org/ns/credentials/v2",
                "https://credentials.eudistack.eu/2025/credentials/learcredentialemployee/v4"), result.context());
        assertSame(profile, result.profile());
        assertNotNull(result.root());
    }

    @Test
    void create_withUnsupportedVcObjectType_throwsJsonConversionException() {
        // Given
        Payload payload = mock(Payload.class);
        when(jwtService.extractVCFromPayload(payload)).thenReturn("not-a-map");

        // When & Then
        assertThrows(
                JsonConversionException.class,
                () -> factory.create(payload)
        );
    }
}
