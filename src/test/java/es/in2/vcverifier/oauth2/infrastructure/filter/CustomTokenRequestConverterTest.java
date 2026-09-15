package es.in2.vcverifier.oauth2.infrastructure.filter;

import es.in2.vcverifier.oauth2.infrastructure.filter.CustomTokenRequestConverter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.JsonNodeFactory;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.shared.domain.exception.FailedCommunicationException;
import es.in2.vcverifier.oauth2.application.workflow.ClientCredentialsValidationWorkflow;
import es.in2.vcverifier.oauth2.domain.model.OAuth2M2MAuditEvent;
import es.in2.vcverifier.oauth2.domain.port.OAuth2M2MAuditPort;
import es.in2.vcverifier.verifier.domain.exception.CredentialExpiredException;
import es.in2.vcverifier.verifier.domain.exception.CredentialNotActiveException;
import es.in2.vcverifier.verifier.domain.exception.CredentialRevokedException;
import es.in2.vcverifier.verifier.domain.exception.InvalidCredentialTypeException;
import es.in2.vcverifier.verifier.domain.exception.IssuerNotAuthorizedException;
import es.in2.vcverifier.verifier.domain.exception.StatusListCredentialException;
import es.in2.vcverifier.oauth2.domain.exception.InvalidProofOfPossessionException;
import es.in2.vcverifier.oauth2.domain.exception.UnsupportedGrantTypeException;
import es.in2.vcverifier.oauth2.domain.model.AuthorizationCodeData;
import es.in2.vcverifier.oauth2.domain.model.RefreshTokenDataCache;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2AuthorizationCodeAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2ClientCredentialsAuthenticationToken;
import org.springframework.security.oauth2.server.authorization.authentication.OAuth2RefreshTokenAuthenticationToken;
import org.springframework.util.LinkedMultiValueMap;
import org.springframework.util.MultiValueMap;

import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class CustomTokenRequestConverterTest {

    @Mock
    private ClientCredentialsValidationWorkflow clientCredentialsValidationWorkflow;

    @Mock
    private CacheStore<AuthorizationCodeData> cacheStoreForAuthorizationCodeData;

    @Mock
    private CacheStore<RefreshTokenDataCache> refreshTokenDataCacheCacheStore;

    @Mock
    private OAuth2M2MAuditPort oAuth2M2MAuditPort;

    private CustomTokenRequestConverter customTokenRequestConverter;

    @BeforeEach
    void setUp() {
        customTokenRequestConverter = new CustomTokenRequestConverter(
                clientCredentialsValidationWorkflow,
                cacheStoreForAuthorizationCodeData,
                refreshTokenDataCacheCacheStore,
                oAuth2M2MAuditPort
        );
    }

    @Test
    void convert_authorizationCodeGrant_shouldReturnOAuth2AuthorizationCodeAuthenticationToken() {
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        Authentication clientPrincipal = mock(Authentication.class);
        SecurityContextHolder.getContext().setAuthentication(clientPrincipal);

        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add(OAuth2ParameterNames.GRANT_TYPE, "authorization_code");
        parameters.add(OAuth2ParameterNames.CODE, "code");
        parameters.add(OAuth2ParameterNames.CLIENT_ID, "client-id");
        parameters.add(OAuth2ParameterNames.STATE, "state");

        when(mockRequest.getParameterMap()).thenReturn(convertToMap(parameters));
        AuthorizationCodeData authorizationCodeData = mock(AuthorizationCodeData.class);
        when(cacheStoreForAuthorizationCodeData.get("code")).thenReturn(authorizationCodeData);
        when(authorizationCodeData.state()).thenReturn("state");

        JsonNode jsonNodeMock = mock(JsonNode.class);
        when(authorizationCodeData.verifiableCredential()).thenReturn(jsonNodeMock);

        Authentication result = customTokenRequestConverter.convert(mockRequest);

        assertNotNull(result);
        assertInstanceOf(OAuth2AuthorizationCodeAuthenticationToken.class, result);
    }

    @Test
    void convert_clientCredentialsGrant_success() {
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);
        Authentication clientPrincipal = mock(Authentication.class);
        SecurityContextHolder.getContext().setAuthentication(clientPrincipal);

        String clientId = "client-id";
        String clientAssertion = "client-assertion";

        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add(OAuth2ParameterNames.GRANT_TYPE, "client_credentials");
        parameters.add(OAuth2ParameterNames.CLIENT_ID, clientId);
        parameters.add(OAuth2ParameterNames.CLIENT_ASSERTION, clientAssertion);

        when(mockRequest.getParameterMap()).thenReturn(convertToMap(parameters));

        JsonNode mockVC = buildMachineCredentialJsonNode();
        when(clientCredentialsValidationWorkflow.validateClientCredentialsGrant(clientId, clientAssertion)).thenReturn(mockVC);

        Authentication result = customTokenRequestConverter.convert(mockRequest);

        assertNotNull(result);
        assertInstanceOf(OAuth2ClientCredentialsAuthenticationToken.class, result);

        OAuth2ClientCredentialsAuthenticationToken token = (OAuth2ClientCredentialsAuthenticationToken) result;
        assertEquals(clientPrincipal, token.getPrincipal());

        Map<String, Object> additionalParameters = token.getAdditionalParameters();
        assertEquals(clientId, additionalParameters.get(OAuth2ParameterNames.CLIENT_ID));

        verify(oAuth2M2MAuditPort, never()).publish(any());
    }

    @Nested
    @DisplayName("refresh_token grant")
    class RefreshTokenGrantTests {

        private static final String REFRESH_TOKEN_VALUE = "opaque-refresh-token";
        private static final String CLIENT_ID = "vc-auth-client-sandbox";

        @Test
        @DisplayName("carries the cached auth_time forward when present")
        void convert_refreshTokenGrant_withCachedAuthTime_includesAuthTimeParam() {
            HttpServletRequest mockRequest = mock(HttpServletRequest.class);
            Authentication clientPrincipal = mock(Authentication.class);
            SecurityContextHolder.getContext().setAuthentication(clientPrincipal);

            MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
            parameters.add(OAuth2ParameterNames.GRANT_TYPE, "refresh_token");
            parameters.add(OAuth2ParameterNames.REFRESH_TOKEN, REFRESH_TOKEN_VALUE);
            parameters.add(OAuth2ParameterNames.CLIENT_ID, CLIENT_ID);
            when(mockRequest.getParameterMap()).thenReturn(convertToMap(parameters));

            JsonNode vc = buildMachineCredentialJsonNode();
            RefreshTokenDataCache cached = RefreshTokenDataCache.builder()
                    .clientId(CLIENT_ID)
                    .verifiableCredential(vc)
                    .authTimeEpochSeconds(1_700_000_000L)
                    .build();
            when(refreshTokenDataCacheCacheStore.get(REFRESH_TOKEN_VALUE)).thenReturn(cached);

            Authentication result = customTokenRequestConverter.convert(mockRequest);

            assertInstanceOf(OAuth2RefreshTokenAuthenticationToken.class, result);
            OAuth2RefreshTokenAuthenticationToken token = (OAuth2RefreshTokenAuthenticationToken) result;
            assertEquals(REFRESH_TOKEN_VALUE, token.getRefreshToken());
            assertEquals(vc, token.getAdditionalParameters().get("vc"));
            assertEquals(CLIENT_ID, token.getAdditionalParameters().get(OAuth2ParameterNames.CLIENT_ID));
            assertEquals(1_700_000_000L, token.getAdditionalParameters().get("auth_time"));
            verify(refreshTokenDataCacheCacheStore).delete(REFRESH_TOKEN_VALUE);
        }

        @Test
        @DisplayName("omits auth_time when the cached entry predates it")
        void convert_refreshTokenGrant_withoutCachedAuthTime_omitsAuthTimeParam() {
            HttpServletRequest mockRequest = mock(HttpServletRequest.class);
            Authentication clientPrincipal = mock(Authentication.class);
            SecurityContextHolder.getContext().setAuthentication(clientPrincipal);

            MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
            parameters.add(OAuth2ParameterNames.GRANT_TYPE, "refresh_token");
            parameters.add(OAuth2ParameterNames.REFRESH_TOKEN, REFRESH_TOKEN_VALUE);
            parameters.add(OAuth2ParameterNames.CLIENT_ID, CLIENT_ID);
            when(mockRequest.getParameterMap()).thenReturn(convertToMap(parameters));

            RefreshTokenDataCache cached = RefreshTokenDataCache.builder()
                    .clientId(CLIENT_ID)
                    .verifiableCredential(buildMachineCredentialJsonNode())
                    .authTimeEpochSeconds(null)
                    .build();
            when(refreshTokenDataCacheCacheStore.get(REFRESH_TOKEN_VALUE)).thenReturn(cached);

            Authentication result = customTokenRequestConverter.convert(mockRequest);

            OAuth2RefreshTokenAuthenticationToken token = (OAuth2RefreshTokenAuthenticationToken) result;
            assertFalse(token.getAdditionalParameters().containsKey("auth_time"));
        }

        @Test
        @DisplayName("refresh token redeemed by a different client_id than it was issued to throws invalid_grant")
        void convert_refreshTokenGrant_clientIdMismatch_throwsInvalidGrant() {
            HttpServletRequest mockRequest = mock(HttpServletRequest.class);

            MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
            parameters.add(OAuth2ParameterNames.GRANT_TYPE, "refresh_token");
            parameters.add(OAuth2ParameterNames.REFRESH_TOKEN, REFRESH_TOKEN_VALUE);
            parameters.add(OAuth2ParameterNames.CLIENT_ID, "a-different-client");
            when(mockRequest.getParameterMap()).thenReturn(convertToMap(parameters));

            RefreshTokenDataCache cached = RefreshTokenDataCache.builder()
                    .clientId(CLIENT_ID)
                    .verifiableCredential(buildMachineCredentialJsonNode())
                    .build();
            when(refreshTokenDataCacheCacheStore.get(REFRESH_TOKEN_VALUE)).thenReturn(cached);

            OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class,
                    () -> customTokenRequestConverter.convert(mockRequest));

            assertEquals(OAuth2ErrorCodes.INVALID_GRANT, exception.getError().getErrorCode());
            verify(refreshTokenDataCacheCacheStore, never()).delete(anyString());
        }

        @Test
        @DisplayName("unknown refresh token throws invalid_token")
        void convert_refreshTokenGrant_unknownToken_throwsInvalidToken() {
            HttpServletRequest mockRequest = mock(HttpServletRequest.class);

            MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
            parameters.add(OAuth2ParameterNames.GRANT_TYPE, "refresh_token");
            parameters.add(OAuth2ParameterNames.REFRESH_TOKEN, "unknown-token");
            parameters.add(OAuth2ParameterNames.CLIENT_ID, CLIENT_ID);
            when(mockRequest.getParameterMap()).thenReturn(convertToMap(parameters));
            when(refreshTokenDataCacheCacheStore.get("unknown-token")).thenReturn(null);

            OAuth2AuthenticationException exception = assertThrows(OAuth2AuthenticationException.class,
                    () -> customTokenRequestConverter.convert(mockRequest));

            assertEquals(OAuth2ErrorCodes.INVALID_TOKEN, exception.getError().getErrorCode());
            verify(refreshTokenDataCacheCacheStore, never()).delete(anyString());
        }
    }

    @Test
    void convert_unsupportedGrantType_shouldThrowUnsupportedGrantTypeException() {
        HttpServletRequest mockRequest = mock(HttpServletRequest.class);

        MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
        parameters.add(OAuth2ParameterNames.GRANT_TYPE, "invalid_grant_type");

        when(mockRequest.getParameterMap()).thenReturn(convertToMap(parameters));

        assertThrows(UnsupportedGrantTypeException.class, () ->
                customTokenRequestConverter.convert(mockRequest));
    }

    /**
     * ES-02: validateClientCredentialsGrant's domain exceptions must never propagate raw past the
     * token endpoint. Every scenario here asserts three things: (1) the OAuth2 error code returned
     * to the client, (2) that the error description is null — i.e. the internal exception message
     * never reaches the HTTP response (see Part A finding: OAuth2AuthenticationException(String) ->
     * OAuth2Error(errorCode, null, null), confirmed against OAuth2ErrorAuthenticationFailureHandler),
     * and (3) the audit event published for that rejection.
     */
    @Nested
    @DisplayName("client_credentials grant: exception translation and audit")
    class ClientCredentialsGrantExceptionHandling {

        private static final String CLIENT_ID = "client-id";
        private static final String CLIENT_ASSERTION = "client-assertion";

        private HttpServletRequest mockRequest;

        @BeforeEach
        void setUpRequestAndPrincipal() {
            mockRequest = mock(HttpServletRequest.class);
            Authentication clientPrincipal = mock(Authentication.class);
            SecurityContextHolder.getContext().setAuthentication(clientPrincipal);
        }

        @Test
        @DisplayName("convert_invalidCredentialType_throwsInvalidClientAndPublishesCredentialTypeNotEligibleAudit")
        void convert_invalidCredentialType_throwsInvalidClientAndPublishesCredentialTypeNotEligibleAudit() {
            givenClientCredentialsRequest(CLIENT_ID, CLIENT_ASSERTION);
            when(clientCredentialsValidationWorkflow.validateClientCredentialsGrant(CLIENT_ID, CLIENT_ASSERTION))
                    .thenThrow(new InvalidCredentialTypeException("Invalid LEARCredentialType. Expected LEARCredentialMachine"));

            OAuth2AuthenticationException exception = whenConvertThrows();

            thenErrorCodeIs(exception, OAuth2ErrorCodes.INVALID_CLIENT);
            thenAuditPublishedWithReason(CLIENT_ID, "credential_type_not_eligible");
        }

        @Test
        @DisplayName("convert_invalidProofOfPossession_throwsInvalidClientAndPublishesInvalidProofOfPossessionAudit")
        void convert_invalidProofOfPossession_throwsInvalidClientAndPublishesInvalidProofOfPossessionAudit() {
            givenClientCredentialsRequest(CLIENT_ID, CLIENT_ASSERTION);
            when(clientCredentialsValidationWorkflow.validateClientCredentialsGrant(CLIENT_ID, CLIENT_ASSERTION))
                    .thenThrow(new InvalidProofOfPossessionException("Invalid JWT claims from assertion"));

            OAuth2AuthenticationException exception = whenConvertThrows();

            thenErrorCodeIs(exception, OAuth2ErrorCodes.INVALID_CLIENT);
            thenAuditPublishedWithReason(CLIENT_ID, "invalid_proof_of_possession");
        }

        @Test
        @DisplayName("convert_untrustedIssuer_throwsInvalidClientAndPublishesIssuerNotTrustedAudit")
        void convert_untrustedIssuer_throwsInvalidClientAndPublishesIssuerNotTrustedAudit() {
            givenClientCredentialsRequest(CLIENT_ID, CLIENT_ASSERTION);
            when(clientCredentialsValidationWorkflow.validateClientCredentialsGrant(CLIENT_ID, CLIENT_ASSERTION))
                    .thenThrow(new IssuerNotAuthorizedException("Issuer is not trusted"));

            OAuth2AuthenticationException exception = whenConvertThrows();

            thenErrorCodeIs(exception, OAuth2ErrorCodes.INVALID_CLIENT);
            thenAuditPublishedWithReason(CLIENT_ID, "issuer_not_trusted");
        }

        @Test
        @DisplayName("convert_expiredCredential_throwsInvalidGrantAndPublishesCredentialExpiredAudit")
        void convert_expiredCredential_throwsInvalidGrantAndPublishesCredentialExpiredAudit() {
            givenClientCredentialsRequest(CLIENT_ID, CLIENT_ASSERTION);
            when(clientCredentialsValidationWorkflow.validateClientCredentialsGrant(CLIENT_ID, CLIENT_ASSERTION))
                    .thenThrow(new CredentialExpiredException("Credential has expired"));

            OAuth2AuthenticationException exception = whenConvertThrows();

            thenErrorCodeIs(exception, OAuth2ErrorCodes.INVALID_GRANT);
            thenAuditPublishedWithReason(CLIENT_ID, "credential_expired");
        }

        @Test
        @DisplayName("convert_notYetActiveCredential_throwsInvalidGrantAndPublishesCredentialNotActiveAudit")
        void convert_notYetActiveCredential_throwsInvalidGrantAndPublishesCredentialNotActiveAudit() {
            givenClientCredentialsRequest(CLIENT_ID, CLIENT_ASSERTION);
            when(clientCredentialsValidationWorkflow.validateClientCredentialsGrant(CLIENT_ID, CLIENT_ASSERTION))
                    .thenThrow(new CredentialNotActiveException("Credential is not yet valid"));

            OAuth2AuthenticationException exception = whenConvertThrows();

            thenErrorCodeIs(exception, OAuth2ErrorCodes.INVALID_GRANT);
            thenAuditPublishedWithReason(CLIENT_ID, "credential_not_active");
        }

        @Test
        @DisplayName("convert_revokedCredential_throwsInvalidGrantAndPublishesCredentialRevokedAudit")
        void convert_revokedCredential_throwsInvalidGrantAndPublishesCredentialRevokedAudit() {
            givenClientCredentialsRequest(CLIENT_ID, CLIENT_ASSERTION);
            when(clientCredentialsValidationWorkflow.validateClientCredentialsGrant(CLIENT_ID, CLIENT_ASSERTION))
                    .thenThrow(new CredentialRevokedException("Credential is revoked"));

            OAuth2AuthenticationException exception = whenConvertThrows();

            thenErrorCodeIs(exception, OAuth2ErrorCodes.INVALID_GRANT);
            thenAuditPublishedWithReason(CLIENT_ID, "credential_revoked");
        }

        @Test
        @DisplayName("convert_trustedIssuersRegistryUnreachable_throwsServerErrorAndPublishesExternalDependencyFailureAudit")
        void convert_trustedIssuersRegistryUnreachable_throwsServerErrorAndPublishesExternalDependencyFailureAudit() {
            givenClientCredentialsRequest(CLIENT_ID, CLIENT_ASSERTION);
            when(clientCredentialsValidationWorkflow.validateClientCredentialsGrant(CLIENT_ID, CLIENT_ASSERTION))
                    .thenThrow(new FailedCommunicationException("Error fetching issuer data"));

            OAuth2AuthenticationException exception = whenConvertThrows();

            thenErrorCodeIs(exception, OAuth2ErrorCodes.SERVER_ERROR);
            thenAuditPublishedWithReason(CLIENT_ID, "external_dependency_failure");
        }

        @Test
        @DisplayName("convert_statusListFetchFails_throwsServerErrorAndPublishesExternalDependencyFailureAudit")
        void convert_statusListFetchFails_throwsServerErrorAndPublishesExternalDependencyFailureAudit() {
            givenClientCredentialsRequest(CLIENT_ID, CLIENT_ASSERTION);
            when(clientCredentialsValidationWorkflow.validateClientCredentialsGrant(CLIENT_ID, CLIENT_ASSERTION))
                    .thenThrow(new StatusListCredentialException("Failed to gunzip content"));

            OAuth2AuthenticationException exception = whenConvertThrows();

            thenErrorCodeIs(exception, OAuth2ErrorCodes.SERVER_ERROR);
            thenAuditPublishedWithReason(CLIENT_ID, "external_dependency_failure");
        }

        @Test
        @DisplayName("convert_unenumeratedIllegalArgument_throwsInvalidClientAndPublishesCredentialValidationFailedAudit")
        void convert_unenumeratedIllegalArgument_throwsInvalidClientAndPublishesCredentialValidationFailedAudit() {
            // ES-01, fail-closed default: an IllegalArgumentException not enumerated above (e.g. a
            // malformed / non-decodable vp_token) falls through to the generic catch, distinct from
            // InvalidProofOfPossessionException (which now owns "invalid claims from assertion").
            givenClientCredentialsRequest(CLIENT_ID, CLIENT_ASSERTION);
            when(clientCredentialsValidationWorkflow.validateClientCredentialsGrant(CLIENT_ID, CLIENT_ASSERTION))
                    .thenThrow(new IllegalArgumentException("vp_token is not valid Base64"));

            OAuth2AuthenticationException exception = whenConvertThrows();

            thenErrorCodeIs(exception, OAuth2ErrorCodes.INVALID_CLIENT);
            thenAuditPublishedWithReason(CLIENT_ID, "credential_validation_failed");
        }

        @Test
        @DisplayName("convert_unenumeratedRuntimeException_throwsInvalidClientAsFailClosedDefaultAndPublishesCredentialValidationFailedAudit")
        void convert_unenumeratedRuntimeException_throwsInvalidClientAsFailClosedDefaultAndPublishesCredentialValidationFailedAudit() {
            givenClientCredentialsRequest(CLIENT_ID, CLIENT_ASSERTION);
            when(clientCredentialsValidationWorkflow.validateClientCredentialsGrant(CLIENT_ID, CLIENT_ASSERTION))
                    .thenThrow(new RuntimeException("Something failed"));

            OAuth2AuthenticationException exception = whenConvertThrows();

            thenErrorCodeIs(exception, OAuth2ErrorCodes.INVALID_CLIENT);
            thenAuditPublishedWithReason(CLIENT_ID, "credential_validation_failed");
        }

        @Test
        @DisplayName("convert_exceptionWithNullMessage_stillTranslatesAndAuditsWithoutThrowingNpe")
        void convert_exceptionWithNullMessage_stillTranslatesAndAuditsWithoutThrowingNpe() {
            givenClientCredentialsRequest(CLIENT_ID, CLIENT_ASSERTION);
            when(clientCredentialsValidationWorkflow.validateClientCredentialsGrant(CLIENT_ID, CLIENT_ASSERTION))
                    .thenThrow(new InvalidCredentialTypeException(null));

            OAuth2AuthenticationException exception = whenConvertThrows();

            thenErrorCodeIs(exception, OAuth2ErrorCodes.INVALID_CLIENT);
            thenAuditPublishedWithReason(CLIENT_ID, "credential_type_not_eligible");
        }

        @Test
        @DisplayName("convert_missingClientIdParameter_publishesAuditWithNullClientIdWithoutThrowingNpe")
        void convert_missingClientIdParameter_publishesAuditWithNullClientIdWithoutThrowingNpe() {
            // client_id absent from the request parameters entirely
            MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
            parameters.add(OAuth2ParameterNames.GRANT_TYPE, "client_credentials");
            parameters.add(OAuth2ParameterNames.CLIENT_ASSERTION, CLIENT_ASSERTION);
            when(mockRequest.getParameterMap()).thenReturn(convertToMap(parameters));

            when(clientCredentialsValidationWorkflow.validateClientCredentialsGrant(isNull(), eq(CLIENT_ASSERTION)))
                    .thenThrow(new InvalidCredentialTypeException("Invalid LEARCredentialType"));

            OAuth2AuthenticationException exception = whenConvertThrows();

            thenErrorCodeIs(exception, OAuth2ErrorCodes.INVALID_CLIENT);
            thenAuditPublishedWithReason(null, "credential_type_not_eligible");
        }

        private void givenClientCredentialsRequest(String clientId, String clientAssertion) {
            MultiValueMap<String, String> parameters = new LinkedMultiValueMap<>();
            parameters.add(OAuth2ParameterNames.GRANT_TYPE, "client_credentials");
            parameters.add(OAuth2ParameterNames.CLIENT_ID, clientId);
            parameters.add(OAuth2ParameterNames.CLIENT_ASSERTION, clientAssertion);
            when(mockRequest.getParameterMap()).thenReturn(convertToMap(parameters));
        }

        private OAuth2AuthenticationException whenConvertThrows() {
            return assertThrows(OAuth2AuthenticationException.class, () ->
                    customTokenRequestConverter.convert(mockRequest));
        }

        private void thenErrorCodeIs(OAuth2AuthenticationException exception, String expectedErrorCode) {
            OAuth2Error error = exception.getError();
            assertEquals(expectedErrorCode, error.getErrorCode());
            // Part A: the internal exception message/type must never reach the client-facing error.
            assertNull(error.getDescription(), "OAuth2Error description must stay null — no internal message may leak to the client");
        }

        private void thenAuditPublishedWithReason(String expectedClientId, String expectedReason) {
            ArgumentCaptor<OAuth2M2MAuditEvent> auditCaptor = ArgumentCaptor.forClass(OAuth2M2MAuditEvent.class);
            verify(oAuth2M2MAuditPort).publish(auditCaptor.capture());
            OAuth2M2MAuditEvent auditEvent = auditCaptor.getValue();
            assertEquals(expectedClientId, auditEvent.getClientId());
            assertEquals("REJECT", auditEvent.getOutcome());
            assertEquals(expectedReason, auditEvent.getReason());
            // Confirmed (not assumed): the credential is never successfully parsed on any of these
            // rejection paths, so there is nothing to derive a tenant from at this point.
            assertNull(auditEvent.getTenant());
        }
    }

    private JsonNode buildMachineCredentialJsonNode() {
        JsonNodeFactory factory = JsonNodeFactory.instance;
        ArrayNode typeArray = factory.arrayNode();
        typeArray.add("VerifiableCredential");
        typeArray.add("LEARCredentialMachine");
        return factory.objectNode().set("type", typeArray);
    }

    private Map<String, String[]> convertToMap(MultiValueMap<String, String> multiValueMap) {
        Map<String, String[]> map = new HashMap<>();
        multiValueMap.forEach((key, valueList) -> map.put(key, valueList.toArray(new String[0])));
        return map;
    }
}
