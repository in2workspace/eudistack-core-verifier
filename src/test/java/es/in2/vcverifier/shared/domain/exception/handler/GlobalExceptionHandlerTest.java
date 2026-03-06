package es.in2.vcverifier.shared.domain.exception.handler;

import es.in2.vcverifier.verifier.domain.exception.*;
import es.in2.vcverifier.oauth2.domain.exception.*;
import es.in2.vcverifier.shared.domain.exception.*;
import es.in2.vcverifier.shared.domain.model.GlobalErrorMessage;
import jakarta.servlet.http.HttpServletRequest;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.security.auth.login.CredentialExpiredException;
import java.util.NoSuchElementException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class GlobalExceptionHandlerTest {

    @InjectMocks
    private GlobalExceptionHandler globalExceptionHandler;

    @Mock
    private HttpServletRequest mockRequest;

    @Test
    void testHandleResourceNotFoundException() {
        ResourceNotFoundException exception = new ResourceNotFoundException("Resource not found");

        GlobalErrorMessage response = globalExceptionHandler.handleResourceNotFoundException(exception);

        assertThat(response.title()).isEmpty();
        assertThat(response.message()).isEmpty();
        assertThat(response.path()).isEmpty();
    }

    @Test
    void testHandleNoSuchElementException() {
        NoSuchElementException exception = new NoSuchElementException("Element not found");

        GlobalErrorMessage response = globalExceptionHandler.handleNoSuchElementException(exception);

        assertThat(response.title()).isEmpty();
        assertThat(response.message()).isEmpty();
        assertThat(response.path()).isEmpty();
    }

    @Test
    void testHandleCredentialRevokedException() {
        CredentialRevokedException exception = new CredentialRevokedException("Credential revoked");

        GlobalErrorMessage response = globalExceptionHandler.handleException(exception);

        assertThat(response.title()).isEqualTo("Verifiable presentation failed");
        assertThat(response.message()).isEmpty();
        assertThat(response.path()).isEmpty();
    }

    @Test
    void testHandleMismatchOrganizationIdentifierException() {
        MismatchOrganizationIdentifierException exception = new MismatchOrganizationIdentifierException("Mismatch org identifier");

        GlobalErrorMessage response = globalExceptionHandler.handleException(exception);

        assertThat(response.title()).isEmpty();
        assertThat(response.message()).isEmpty();
        assertThat(response.path()).isEmpty();
    }

    @Test
    void testHandleGenericException() {
        Exception exception = new Exception("Generic error");

        GlobalErrorMessage response = globalExceptionHandler.handleException(exception);

        assertThat(response.title()).isEqualTo("Unexpected error");
        assertThat(response.message()).isEqualTo("Exception: Generic error");
        assertThat(response.path()).isEmpty();
    }

    @Test
    void testHandleInvalidVPtokenException() {
        InvalidVPtokenException exception = new InvalidVPtokenException("Invalid VP token");

        // Stub the contextPath value
        when(mockRequest.getContextPath()).thenReturn("/test-path");

        GlobalErrorMessage response = globalExceptionHandler.handleException(exception, mockRequest);

        assertThat(response.title()).isEqualTo("Invalid VP Token");
        assertThat(response.message()).isEqualTo("Invalid VP token");
        assertThat(response.path()).isEqualTo("/test-path");
    }

    @Test
    void testHandleCredentialExpiredException() {
        CredentialExpiredException exception = new CredentialExpiredException("Credential expired");

        GlobalErrorMessage response = globalExceptionHandler.handleException(exception);

        assertThat(response.title()).isEqualTo("Unexpected error");
        assertThat(response.message()).isEqualTo("CredentialExpiredException: Credential expired");
        assertThat(response.path()).isEmpty();
    }

    @Test
    void testHandleCredentialNotActiveException() {
        CredentialNotActiveException exception = new CredentialNotActiveException("Credential not active");

        GlobalErrorMessage response = globalExceptionHandler.handleException(exception);

        assertThat(response.title()).isEmpty();
        assertThat(response.message()).isEmpty();
        assertThat(response.path()).isEmpty();
    }

    @Test
    void testHandleStatusListCredentialException() {
        StatusListCredentialException exception = new StatusListCredentialException("Status list error");

        GlobalErrorMessage response = globalExceptionHandler.handleStatusListCredentialException(exception);

        assertThat(response.title()).isEqualTo("Error while handling Status List Credential ");
        assertThat(response.message()).isEqualTo("Status list error");
        assertThat(response.path()).isEmpty();
    }

    @Test
    void testHandleIssuerNotAuthorizedException() {
        IssuerNotAuthorizedException exception = new IssuerNotAuthorizedException("unauthorized issuer");

        GlobalErrorMessage response = globalExceptionHandler.handleIssuerNotAuthorizedException(exception);

        assertThat(response.title()).isEqualTo("Issuer not authorized");
        assertThat(response.message()).isEqualTo("unauthorized issuer");
    }

    @Test
    void testHandleInvalidCredentialTypeException() {
        InvalidCredentialTypeException exception = new InvalidCredentialTypeException("bad type");

        GlobalErrorMessage response = globalExceptionHandler.handleInvalidCredentialTypeException(exception);

        assertThat(response.title()).isEqualTo("Invalid credential type");
        assertThat(response.message()).isEqualTo("bad type");
    }

    @Test
    void testHandleJWTClaimMissingException() {
        JWTClaimMissingException exception = new JWTClaimMissingException("missing nonce");

        GlobalErrorMessage response = globalExceptionHandler.handleJWTClaimMissingException(exception);

        assertThat(response.title()).isEqualTo("JWT claim error");
        assertThat(response.message()).isEqualTo("missing nonce");
    }

    @Test
    void testHandleJWTVerificationException() {
        JWTVerificationException exception = new JWTVerificationException("bad signature");

        GlobalErrorMessage response = globalExceptionHandler.handleJWTVerificationException(exception);

        assertThat(response.title()).isEqualTo("JWT verification failed");
        assertThat(response.message()).isEqualTo("bad signature");
    }

    @Test
    void testHandleJWTParsingException() {
        JWTParsingException exception = new JWTParsingException("parse error");

        GlobalErrorMessage response = globalExceptionHandler.handleJWTParsingException(exception);

        assertThat(response.title()).isEqualTo("JWT parsing failed");
        assertThat(response.message()).isEqualTo("parse error");
    }

    @Test
    void testHandleInvalidScopeException() {
        InvalidScopeException exception = new InvalidScopeException("bad scope");

        GlobalErrorMessage response = globalExceptionHandler.handleInvalidScopeException(exception);

        assertThat(response.title()).isEqualTo("Scope/binding error");
        assertThat(response.message()).isEqualTo("bad scope");
    }

    @Test
    void testHandleCredentialMappingException() {
        CredentialMappingException exception = new CredentialMappingException("mapping error");

        GlobalErrorMessage response = globalExceptionHandler.handleCredentialMappingException(exception);

        assertThat(response.title()).isEqualTo("Credential mapping error");
        assertThat(response.message()).isEqualTo("mapping error");
    }

    @Test
    void testHandleLoginTimeoutException() {
        LoginTimeoutException exception = new LoginTimeoutException("timeout");

        GlobalErrorMessage response = globalExceptionHandler.handleException(exception);

        assertThat(response.title()).contains("Login time has expired");
    }
}
