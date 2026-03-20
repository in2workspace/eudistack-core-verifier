package es.in2.vcverifier.shared.domain.exception.handler;

import es.in2.vcverifier.oauth2.domain.exception.LoginTimeoutException;
import es.in2.vcverifier.shared.domain.exception.FailedCommunicationException;
import es.in2.vcverifier.shared.domain.exception.JWTClaimMissingException;
import es.in2.vcverifier.shared.domain.exception.JWTParsingException;
import es.in2.vcverifier.shared.domain.exception.JWTVerificationException;
import es.in2.vcverifier.shared.domain.exception.MismatchOrganizationIdentifierException;
import es.in2.vcverifier.shared.domain.exception.ResourceNotFoundException;
import es.in2.vcverifier.shared.domain.exception.SsrfProtectionException;
import es.in2.vcverifier.shared.domain.model.GlobalErrorMessage;
import es.in2.vcverifier.shared.domain.util.VerifierErrorTypes;
import es.in2.vcverifier.verifier.domain.exception.CredentialMappingException;
import es.in2.vcverifier.verifier.domain.exception.CredentialNotActiveException;
import es.in2.vcverifier.verifier.domain.exception.CredentialRevokedException;
import es.in2.vcverifier.verifier.domain.exception.InvalidCredentialTypeException;
import es.in2.vcverifier.verifier.domain.exception.InvalidScopeException;
import es.in2.vcverifier.verifier.domain.exception.InvalidVPtokenException;
import es.in2.vcverifier.verifier.domain.exception.IssuerNotAuthorizedException;
import es.in2.vcverifier.verifier.domain.exception.StatusListCredentialException;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.junit.jupiter.MockitoExtension;

import java.util.NoSuchElementException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GlobalExceptionHandlerTest {

    @Spy
    private ErrorResponseFactory errors =
            new ErrorResponseFactory(new io.micrometer.core.instrument.simple.SimpleMeterRegistry());

    @InjectMocks
    private GlobalExceptionHandler globalExceptionHandler;

    @Mock
    private HttpServletRequest mockRequest;

    @Test
    void testHandleResourceNotFoundException() {
        when(mockRequest.getRequestURI()).thenReturn("/test");
        ResourceNotFoundException exception = new ResourceNotFoundException("Resource not found");

        GlobalErrorMessage response = globalExceptionHandler.handleResourceNotFoundException(exception, mockRequest);

        assertThat(response.type()).isEqualTo(VerifierErrorTypes.RESOURCE_NOT_FOUND.getCode());
        assertThat(response.title()).isEqualTo("Resource not found");
        assertThat(response.status()).isEqualTo(404);
        assertThat(response.detail()).isEqualTo("Resource not found");
        assertThat(response.instance()).isNotBlank();
    }

    @Test
    void testHandleNoSuchElementException() {
        when(mockRequest.getRequestURI()).thenReturn("/test");
        NoSuchElementException exception = new NoSuchElementException("Element not found");

        GlobalErrorMessage response = globalExceptionHandler.handleNoSuchElementException(exception, mockRequest);

        assertThat(response.type()).isEqualTo(VerifierErrorTypes.RESOURCE_NOT_FOUND.getCode());
        assertThat(response.title()).isEqualTo("Element not found");
        assertThat(response.status()).isEqualTo(404);
    }

    @Test
    void testHandleCredentialRevokedException() {
        when(mockRequest.getRequestURI()).thenReturn("/test");
        CredentialRevokedException exception = new CredentialRevokedException("Credential revoked");

        GlobalErrorMessage response = globalExceptionHandler.handleCredentialRevokedException(exception, mockRequest);

        assertThat(response.type()).isEqualTo(VerifierErrorTypes.CREDENTIAL_REVOKED.getCode());
        assertThat(response.title()).isEqualTo("Verifiable presentation failed");
        assertThat(response.status()).isEqualTo(403);
        assertThat(response.detail()).isEqualTo("The credential has been revoked");
    }

    @Test
    void testHandleMismatchOrganizationIdentifierException() {
        when(mockRequest.getRequestURI()).thenReturn("/test");
        MismatchOrganizationIdentifierException exception = new MismatchOrganizationIdentifierException("Mismatch org identifier");

        GlobalErrorMessage response = globalExceptionHandler.handleMismatchOrgException(exception, mockRequest);

        assertThat(response.type()).isEqualTo(VerifierErrorTypes.ORGANIZATION_MISMATCH.getCode());
        assertThat(response.status()).isEqualTo(401);
        assertThat(response.detail()).isEqualTo("Mismatch org identifier");
    }

    @Test
    void testHandleCredentialExpiredException() {
        when(mockRequest.getRequestURI()).thenReturn("/test");
        es.in2.vcverifier.verifier.domain.exception.CredentialExpiredException exception =
                new es.in2.vcverifier.verifier.domain.exception.CredentialExpiredException("Credential expired");

        GlobalErrorMessage response = globalExceptionHandler.handleCredentialExpiredException(exception, mockRequest);

        assertThat(response.type()).isEqualTo(VerifierErrorTypes.CREDENTIAL_EXPIRED.getCode());
        assertThat(response.title()).isEqualTo("Credential expired");
        assertThat(response.status()).isEqualTo(401);
    }

    @Test
    void testHandleCredentialNotActiveException() {
        when(mockRequest.getRequestURI()).thenReturn("/test");
        CredentialNotActiveException exception = new CredentialNotActiveException("Credential not active");

        GlobalErrorMessage response = globalExceptionHandler.handleCredentialNotActiveException(exception, mockRequest);

        assertThat(response.type()).isEqualTo(VerifierErrorTypes.CREDENTIAL_NOT_ACTIVE.getCode());
        assertThat(response.status()).isEqualTo(401);
    }

    @Test
    void testHandleUnexpectedException_neverLeaksDetails() {
        when(mockRequest.getRequestURI()).thenReturn("/test");
        Exception exception = new Exception("Sensitive internal detail");

        GlobalErrorMessage response = globalExceptionHandler.handleUnexpectedException(exception, mockRequest);

        assertThat(response.type()).isEqualTo("internal_server_error");
        assertThat(response.title()).isEqualTo("Internal server error");
        assertThat(response.status()).isEqualTo(500);
        assertThat(response.detail()).isEqualTo("An unexpected error occurred");
        assertThat(response.detail()).doesNotContain("Sensitive");
        assertThat(response.instance()).isNotBlank();
    }

    @Test
    void testHandleInvalidVPtokenException() {
        when(mockRequest.getRequestURI()).thenReturn("/oid4vp/auth-response");
        InvalidVPtokenException exception = new InvalidVPtokenException("Invalid VP token");

        GlobalErrorMessage response = globalExceptionHandler.handleInvalidVPtokenException(exception, mockRequest);

        assertThat(response.type()).isEqualTo(VerifierErrorTypes.INVALID_VP_TOKEN.getCode());
        assertThat(response.title()).isEqualTo("Invalid VP Token");
        assertThat(response.status()).isEqualTo(401);
        assertThat(response.detail()).isEqualTo("Invalid VP token");
    }

    @Test
    void testHandleStatusListCredentialException() {
        when(mockRequest.getRequestURI()).thenReturn("/test");
        StatusListCredentialException exception = new StatusListCredentialException("Status list error");

        GlobalErrorMessage response = globalExceptionHandler.handleStatusListCredentialException(exception, mockRequest);

        assertThat(response.type()).isEqualTo(VerifierErrorTypes.STATUS_LIST_ERROR.getCode());
        assertThat(response.status()).isEqualTo(500);
        assertThat(response.detail()).isEqualTo("Status list error");
    }

    @Test
    void testHandleIssuerNotAuthorizedException() {
        when(mockRequest.getRequestURI()).thenReturn("/test");
        IssuerNotAuthorizedException exception = new IssuerNotAuthorizedException("unauthorized issuer");

        GlobalErrorMessage response = globalExceptionHandler.handleIssuerNotAuthorizedException(exception, mockRequest);

        assertThat(response.type()).isEqualTo(VerifierErrorTypes.ISSUER_NOT_AUTHORIZED.getCode());
        assertThat(response.title()).isEqualTo("Issuer not authorized");
        assertThat(response.detail()).isEqualTo("unauthorized issuer");
    }

    @Test
    void testHandleInvalidCredentialTypeException() {
        when(mockRequest.getRequestURI()).thenReturn("/test");
        InvalidCredentialTypeException exception = new InvalidCredentialTypeException("bad type");

        GlobalErrorMessage response = globalExceptionHandler.handleInvalidCredentialTypeException(exception, mockRequest);

        assertThat(response.type()).isEqualTo(VerifierErrorTypes.INVALID_CREDENTIAL_TYPE.getCode());
        assertThat(response.title()).isEqualTo("Invalid credential type");
        assertThat(response.detail()).isEqualTo("bad type");
    }

    @Test
    void testHandleJWTClaimMissingException() {
        when(mockRequest.getRequestURI()).thenReturn("/test");
        JWTClaimMissingException exception = new JWTClaimMissingException("missing nonce");

        GlobalErrorMessage response = globalExceptionHandler.handleJWTClaimMissingException(exception, mockRequest);

        assertThat(response.type()).isEqualTo(VerifierErrorTypes.JWT_CLAIM_MISSING.getCode());
        assertThat(response.detail()).isEqualTo("missing nonce");
    }

    @Test
    void testHandleJWTVerificationException() {
        when(mockRequest.getRequestURI()).thenReturn("/test");
        JWTVerificationException exception = new JWTVerificationException("bad signature");

        GlobalErrorMessage response = globalExceptionHandler.handleJWTVerificationException(exception, mockRequest);

        assertThat(response.type()).isEqualTo(VerifierErrorTypes.JWT_VERIFICATION_FAILED.getCode());
        assertThat(response.detail()).isEqualTo("bad signature");
    }

    @Test
    void testHandleJWTParsingException() {
        when(mockRequest.getRequestURI()).thenReturn("/test");
        JWTParsingException exception = new JWTParsingException("parse error");

        GlobalErrorMessage response = globalExceptionHandler.handleJWTParsingException(exception, mockRequest);

        assertThat(response.type()).isEqualTo(VerifierErrorTypes.JWT_PARSING_FAILED.getCode());
        assertThat(response.detail()).isEqualTo("parse error");
    }

    @Test
    void testHandleInvalidScopeException() {
        when(mockRequest.getRequestURI()).thenReturn("/test");
        InvalidScopeException exception = new InvalidScopeException("bad scope");

        GlobalErrorMessage response = globalExceptionHandler.handleInvalidScopeException(exception, mockRequest);

        assertThat(response.type()).isEqualTo(VerifierErrorTypes.INVALID_SCOPE.getCode());
        assertThat(response.detail()).isEqualTo("bad scope");
    }

    @Test
    void testHandleCredentialMappingException() {
        when(mockRequest.getRequestURI()).thenReturn("/test");
        CredentialMappingException exception = new CredentialMappingException("mapping error");

        GlobalErrorMessage response = globalExceptionHandler.handleCredentialMappingException(exception, mockRequest);

        assertThat(response.type()).isEqualTo(VerifierErrorTypes.CREDENTIAL_MAPPING_ERROR.getCode());
        assertThat(response.detail()).isEqualTo("mapping error");
    }

    @Test
    void testHandleLoginTimeoutException() {
        when(mockRequest.getRequestURI()).thenReturn("/test");
        LoginTimeoutException exception = new LoginTimeoutException("timeout");

        GlobalErrorMessage response = globalExceptionHandler.handleLoginTimeoutException(exception, mockRequest);

        assertThat(response.type()).isEqualTo(VerifierErrorTypes.LOGIN_TIMEOUT.getCode());
        assertThat(response.title()).isEqualTo("Login time has expired");
    }

    @Test
    void testHandleSsrfProtectionException() {
        when(mockRequest.getRequestURI()).thenReturn("/test");
        SsrfProtectionException exception = new SsrfProtectionException("Loopback addresses are not allowed");

        GlobalErrorMessage response = globalExceptionHandler.handleSsrfProtectionException(exception, mockRequest);

        assertThat(response.type()).isEqualTo(VerifierErrorTypes.SSRF_PROTECTION.getCode());
        assertThat(response.detail()).isEqualTo("The provided URL is not allowed");
        assertThat(response.detail()).doesNotContain("Loopback");
    }

    @Test
    void testHandleFailedCommunicationException() {
        when(mockRequest.getRequestURI()).thenReturn("/test");
        FailedCommunicationException exception = new FailedCommunicationException("Connection refused");

        GlobalErrorMessage response = globalExceptionHandler.handleFailedCommunicationException(exception, mockRequest);

        assertThat(response.type()).isEqualTo(VerifierErrorTypes.FAILED_COMMUNICATION.getCode());
        assertThat(response.status()).isEqualTo(502);
        assertThat(response.detail()).isEqualTo("Connection refused");
    }
}
