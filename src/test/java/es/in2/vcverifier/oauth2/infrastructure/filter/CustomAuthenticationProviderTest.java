package es.in2.vcverifier.oauth2.infrastructure.filter;

import es.in2.vcverifier.oauth2.infrastructure.filter.CustomAuthenticationProvider;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.oauth2.application.workflow.TokenGenerationWorkflow;
import es.in2.vcverifier.oauth2.domain.model.RefreshTokenDataCache;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.oauth2.core.AuthorizationGrantType;
import org.springframework.security.oauth2.core.ClientAuthenticationMethod;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.InMemoryOAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.OAuth2Authorization;
import org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationService;
import org.springframework.security.oauth2.server.authorization.authentication.*;
import org.springframework.security.oauth2.server.authorization.client.InMemoryRegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClient;
import org.springframework.security.oauth2.server.authorization.client.RegisteredClientRepository;
import org.springframework.security.oauth2.server.authorization.settings.ClientSettings;

import java.security.Principal;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;
import java.util.UUID;

import static es.in2.vcverifier.shared.domain.util.Constants.CLIENT_SETTING_TENANT;
import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyMap;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.ArgumentMatchers.isNull;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CustomAuthenticationProviderTest {

    private CustomAuthenticationProvider provider;

    @Mock
    private BackendConfig backendConfig;

    @Mock
    private CacheStore<RefreshTokenDataCache> cacheStoreForRefreshTokenData;

    @Mock
    private TokenGenerationWorkflow tokenGenerationWorkflow;

    private final ObjectMapper objectMapper = new ObjectMapper();
    private RegisteredClientRepository registeredClientRepository;
    private OAuth2AuthorizationService oAuth2AuthorizationService;

    @BeforeEach
    void setUp() {
        RegisteredClient registeredClient = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("test-client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .authorizationGrantType(AuthorizationGrantType.REFRESH_TOKEN)
                .redirectUri("https://example.com/callback")
                .scope("openid")
                .clientSettings(ClientSettings.builder().requireProofKey(false).build())
                .build();

        registeredClientRepository = new InMemoryRegisteredClientRepository(registeredClient);
        oAuth2AuthorizationService = new InMemoryOAuth2AuthorizationService();

        provider = new CustomAuthenticationProvider(
                registeredClientRepository,
                backendConfig,
                objectMapper,
                cacheStoreForRefreshTokenData,
                oAuth2AuthorizationService,
                tokenGenerationWorkflow
        );
    }

    @Test
    void authenticate_validAuthorizationCodeGrant_withEmployeeCredential_success() {
        JsonNode vcJson = buildEmployeeCredentialV1();

        TokenGenerationWorkflow.Result tokenResult = new TokenGenerationWorkflow.Result(
                "signed-access-jwt", Instant.now(), Instant.now().plusSeconds(3600),
                "signed-id-jwt", "openid learcredential", "did:key:zDnaeTest123");
        when(tokenGenerationWorkflow.issueAccessToken(any(JsonNode.class), anyString(), anyMap(), eq(true), any()))
                .thenReturn(tokenResult);
        when(backendConfig.getRefreshTokenExpirationSeconds()).thenReturn(43200L);

        Map<String, Object> additionalParams = new HashMap<>();
        additionalParams.put(OAuth2ParameterNames.CLIENT_ID, "test-client");
        additionalParams.put("vc", objectMapper.convertValue(vcJson, Map.class));
        additionalParams.put(OAuth2ParameterNames.AUDIENCE, "https://rp.example.com");
        additionalParams.put(OAuth2ParameterNames.SCOPE, "openid");

        storeAuthorizationCode("test-code");

        OAuth2AuthorizationCodeAuthenticationToken authToken = new OAuth2AuthorizationCodeAuthenticationToken(
                "test-code", mock(Authentication.class), "https://example.com/callback", additionalParams);

        Authentication result = provider.authenticate(authToken);

        assertNotNull(result);
        assertInstanceOf(OAuth2AccessTokenAuthenticationToken.class, result);
        verify(tokenGenerationWorkflow).issueAccessToken(any(JsonNode.class), eq("https://rp.example.com"), anyMap(), eq(true), any());
    }

    @Test
    void authenticate_validClientCredentialsGrant_withMachineCredential_success() {
        JsonNode vcJson = buildMachineCredentialV1();

        when(backendConfig.getUrl()).thenReturn("https://verifier.example.com");

        TokenGenerationWorkflow.Result tokenResult = new TokenGenerationWorkflow.Result(
                "signed-access-jwt", Instant.now(), Instant.now().plusSeconds(3600),
                null, "machine learcredential", "did:key:zDnaeMachine123");
        when(tokenGenerationWorkflow.issueAccessToken(any(JsonNode.class), anyString(), anyMap(), eq(false), any()))
                .thenReturn(tokenResult);

        Map<String, Object> additionalParams = new HashMap<>();
        additionalParams.put(OAuth2ParameterNames.CLIENT_ID, "test-client");
        additionalParams.put("vc", objectMapper.convertValue(vcJson, Map.class));

        OAuth2ClientCredentialsAuthenticationToken authToken = new OAuth2ClientCredentialsAuthenticationToken(
                mock(Authentication.class), null, additionalParams);

        Authentication result = provider.authenticate(authToken);

        assertNotNull(result);
        assertInstanceOf(OAuth2AccessTokenAuthenticationToken.class, result);
        verify(tokenGenerationWorkflow).issueAccessToken(any(JsonNode.class), eq("https://verifier.example.com"), anyMap(), eq(false), any());
    }

    @Test
    void authenticate_missingVcParameter_throwsException() {
        Map<String, Object> additionalParams = new HashMap<>();
        additionalParams.put(OAuth2ParameterNames.CLIENT_ID, "test-client");

        OAuth2ClientCredentialsAuthenticationToken authToken = new OAuth2ClientCredentialsAuthenticationToken(
                mock(Authentication.class), null, additionalParams);

        assertThrows(OAuth2AuthenticationException.class, () -> provider.authenticate(authToken));
    }

    @Test
    void authenticate_missingAudienceForEmployee_throwsException() {
        JsonNode vcJson = buildEmployeeCredentialV1();

        when(tokenGenerationWorkflow.extractCredentialType(any(JsonNode.class))).thenReturn("learcredential.employee.w3c.4");

        Map<String, Object> additionalParams = new HashMap<>();
        additionalParams.put(OAuth2ParameterNames.CLIENT_ID, "test-client");
        additionalParams.put("vc", objectMapper.convertValue(vcJson, Map.class));

        storeAuthorizationCode("test-code-no-aud");

        OAuth2AuthorizationCodeAuthenticationToken authToken = new OAuth2AuthorizationCodeAuthenticationToken(
                "test-code-no-aud", mock(Authentication.class), "https://example.com/callback", additionalParams);

        assertThrows(OAuth2AuthenticationException.class, () -> provider.authenticate(authToken));
    }

    @Test
    void authenticate_unsupportedGrantType_throwsException() {
        Authentication unsupported = mock(Authentication.class);
        assertThrows(OAuth2AuthenticationException.class, () -> provider.authenticate(unsupported));
    }

    @Test
    void supports_correctAuthenticationTypes() {
        assertTrue(provider.supports(OAuth2AuthorizationCodeAuthenticationToken.class));
        assertTrue(provider.supports(OAuth2ClientCredentialsAuthenticationToken.class));
        assertTrue(provider.supports(OAuth2RefreshTokenAuthenticationToken.class));
        assertFalse(provider.supports(Authentication.class));
    }

    @Test
    void authenticate_clientCredentialsGrant_passesTenantFromClientSettings() {
        // Register a client WITH tenant setting
        RegisteredClient clientWithTenant = RegisteredClient.withId(UUID.randomUUID().toString())
                .clientId("tenant-client")
                .clientAuthenticationMethod(ClientAuthenticationMethod.NONE)
                .authorizationGrantType(AuthorizationGrantType.CLIENT_CREDENTIALS)
                .redirectUri("https://example.com/callback")
                .scope("openid")
                .clientSettings(ClientSettings.builder()
                        .requireProofKey(false)
                        .setting(CLIENT_SETTING_TENANT, "dome")
                        .build())
                .build();

        registeredClientRepository = new InMemoryRegisteredClientRepository(clientWithTenant);
        provider = new CustomAuthenticationProvider(
                registeredClientRepository, backendConfig, objectMapper,
                cacheStoreForRefreshTokenData, oAuth2AuthorizationService, tokenGenerationWorkflow);

        JsonNode vcJson = buildMachineCredentialV1();
        when(backendConfig.getUrl()).thenReturn("https://verifier.example.com");

        TokenGenerationWorkflow.Result tokenResult = new TokenGenerationWorkflow.Result(
                "signed-access-jwt", Instant.now(), Instant.now().plusSeconds(3600),
                null, "machine learcredential", "did:key:zDnaeMachine123");
        when(tokenGenerationWorkflow.issueAccessToken(any(JsonNode.class), anyString(), anyMap(), eq(false), eq("dome")))
                .thenReturn(tokenResult);

        Map<String, Object> additionalParams = new HashMap<>();
        additionalParams.put(OAuth2ParameterNames.CLIENT_ID, "tenant-client");
        additionalParams.put("vc", objectMapper.convertValue(vcJson, Map.class));

        OAuth2ClientCredentialsAuthenticationToken authToken = new OAuth2ClientCredentialsAuthenticationToken(
                mock(Authentication.class), null, additionalParams);

        Authentication result = provider.authenticate(authToken);

        assertNotNull(result);
        verify(tokenGenerationWorkflow).issueAccessToken(any(JsonNode.class), anyString(), anyMap(), eq(false), eq("dome"));
    }

    @Test
    void authenticate_clientCredentialsGrant_passesNullTenantWhenNotConfigured() {
        // The default setUp() client has no tenant setting
        JsonNode vcJson = buildMachineCredentialV1();
        when(backendConfig.getUrl()).thenReturn("https://verifier.example.com");

        TokenGenerationWorkflow.Result tokenResult = new TokenGenerationWorkflow.Result(
                "signed-access-jwt", Instant.now(), Instant.now().plusSeconds(3600),
                null, "machine learcredential", "did:key:zDnaeMachine123");
        when(tokenGenerationWorkflow.issueAccessToken(any(JsonNode.class), anyString(), anyMap(), eq(false), isNull()))
                .thenReturn(tokenResult);

        Map<String, Object> additionalParams = new HashMap<>();
        additionalParams.put(OAuth2ParameterNames.CLIENT_ID, "test-client");
        additionalParams.put("vc", objectMapper.convertValue(vcJson, Map.class));

        OAuth2ClientCredentialsAuthenticationToken authToken = new OAuth2ClientCredentialsAuthenticationToken(
                mock(Authentication.class), null, additionalParams);

        Authentication result = provider.authenticate(authToken);

        assertNotNull(result);
        verify(tokenGenerationWorkflow).issueAccessToken(any(JsonNode.class), anyString(), anyMap(), eq(false), isNull());
    }

    // --- Helper methods ---

    private void storeAuthorizationCode(String code) {
        RegisteredClient rc = registeredClientRepository.findByClientId("test-client");
        OAuth2Authorization auth = OAuth2Authorization.withRegisteredClient(rc)
                .id(UUID.randomUUID().toString())
                .principalName("test-client")
                .authorizationGrantType(AuthorizationGrantType.AUTHORIZATION_CODE)
                .token(new org.springframework.security.oauth2.server.authorization.OAuth2AuthorizationCode(
                        code, Instant.now(), Instant.now().plusSeconds(300)))
                .attribute(OAuth2ParameterNames.CLIENT_ID, "test-client")
                .attribute(Principal.class.getName(), mock(Authentication.class))
                .build();
        oAuth2AuthorizationService.save(auth);
    }

    private JsonNode buildEmployeeCredentialV1() {
        ObjectNode vc = JsonNodeFactory.instance.objectNode();
        ArrayNode type = vc.putArray("type");
        type.add("VerifiableCredential");
        type.add("learcredential.employee.w3c.4");
        ObjectNode cs = vc.putObject("credentialSubject");
        cs.put("id", "did:key:zDnaeTest123");
        return vc;
    }

    private JsonNode buildMachineCredentialV1() {
        ObjectNode vc = JsonNodeFactory.instance.objectNode();
        ArrayNode type = vc.putArray("type");
        type.add("VerifiableCredential");
        type.add("learcredential.machine.w3c.3");
        ObjectNode cs = vc.putObject("credentialSubject");
        cs.put("id", "did:key:zDnaeMachine123");
        return vc;
    }
}
