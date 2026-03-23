package es.in2.vcverifier.shared.domain.exception.handler;

import es.in2.vcverifier.oauth2.domain.exception.LoginTimeoutException;
import es.in2.vcverifier.verifier.domain.exception.InvalidScopeException;
import es.in2.vcverifier.verifier.domain.exception.InvalidVPtokenException;
import es.in2.vcverifier.shared.domain.exception.*;
import es.in2.vcverifier.shared.domain.model.GlobalErrorMessage;
import es.in2.vcverifier.shared.domain.util.VerifierErrorTypes;
import es.in2.vcverifier.verifier.domain.exception.*;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.validation.ConstraintViolationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.ExceptionHandler;
import org.springframework.web.bind.annotation.ResponseStatus;
import org.springframework.web.bind.annotation.RestControllerAdvice;
import org.springframework.web.method.annotation.HandlerMethodValidationException;

import java.util.NoSuchElementException;

@Slf4j
@RestControllerAdvice
@RequiredArgsConstructor
public class GlobalExceptionHandler {

    private final ErrorResponseFactory errors;

    @ExceptionHandler(ResourceNotFoundException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public GlobalErrorMessage handleResourceNotFoundException(ResourceNotFoundException ex, HttpServletRequest request) {
        return errors.handleSafe(ex, request,
                VerifierErrorTypes.RESOURCE_NOT_FOUND.getCode(),
                "Resource not found",
                HttpStatus.NOT_FOUND,
                "The requested resource was not found");
    }

    @ExceptionHandler(NoSuchElementException.class)
    @ResponseStatus(HttpStatus.NOT_FOUND)
    public GlobalErrorMessage handleNoSuchElementException(NoSuchElementException ex, HttpServletRequest request) {
        return errors.handleSafe(ex, request,
                VerifierErrorTypes.RESOURCE_NOT_FOUND.getCode(),
                "Element not found",
                HttpStatus.NOT_FOUND,
                "The requested element was not found");
    }

    @ExceptionHandler(CredentialRevokedException.class)
    @ResponseStatus(HttpStatus.FORBIDDEN)
    public GlobalErrorMessage handleCredentialRevokedException(CredentialRevokedException ex, HttpServletRequest request) {
        return errors.handleSafe(ex, request,
                VerifierErrorTypes.CREDENTIAL_REVOKED.getCode(),
                "Verifiable presentation failed",
                HttpStatus.FORBIDDEN,
                "The credential has been revoked");
    }

    @ExceptionHandler(MismatchOrganizationIdentifierException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public GlobalErrorMessage handleMismatchOrgException(MismatchOrganizationIdentifierException ex, HttpServletRequest request) {
        return errors.handleSafe(ex, request,
                VerifierErrorTypes.ORGANIZATION_MISMATCH.getCode(),
                "Organization identifier mismatch",
                HttpStatus.UNAUTHORIZED,
                "The organization identifier does not match");
    }

    @ExceptionHandler(CredentialExpiredException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public GlobalErrorMessage handleCredentialExpiredException(CredentialExpiredException ex, HttpServletRequest request) {
        return errors.handleSafe(ex, request,
                VerifierErrorTypes.CREDENTIAL_EXPIRED.getCode(),
                "Credential expired",
                HttpStatus.UNAUTHORIZED,
                "The credential has expired");
    }

    @ExceptionHandler(CredentialNotActiveException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public GlobalErrorMessage handleCredentialNotActiveException(CredentialNotActiveException ex, HttpServletRequest request) {
        return errors.handleSafe(ex, request,
                VerifierErrorTypes.CREDENTIAL_NOT_ACTIVE.getCode(),
                "Credential not active",
                HttpStatus.UNAUTHORIZED,
                "The credential is not active yet");
    }

    @ExceptionHandler(IssuerNotAuthorizedException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public GlobalErrorMessage handleIssuerNotAuthorizedException(IssuerNotAuthorizedException ex, HttpServletRequest request) {
        return errors.handleSafe(ex, request,
                VerifierErrorTypes.ISSUER_NOT_AUTHORIZED.getCode(),
                "Issuer not authorized",
                HttpStatus.UNAUTHORIZED,
                "The issuer is not authorized");
    }

    @ExceptionHandler(InvalidCredentialTypeException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public GlobalErrorMessage handleInvalidCredentialTypeException(InvalidCredentialTypeException ex, HttpServletRequest request) {
        return errors.handleSafe(ex, request,
                VerifierErrorTypes.INVALID_CREDENTIAL_TYPE.getCode(),
                "Invalid credential type",
                HttpStatus.UNAUTHORIZED,
                "The credential type is not valid");
    }

    @ExceptionHandler(JWTClaimMissingException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public GlobalErrorMessage handleJWTClaimMissingException(JWTClaimMissingException ex, HttpServletRequest request) {
        return errors.handleSafe(ex, request,
                VerifierErrorTypes.JWT_CLAIM_MISSING.getCode(),
                "JWT claim error",
                HttpStatus.UNAUTHORIZED,
                "A required JWT claim is missing or invalid");
    }

    @ExceptionHandler(JWTVerificationException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public GlobalErrorMessage handleJWTVerificationException(JWTVerificationException ex, HttpServletRequest request) {
        return errors.handleSafe(ex, request,
                VerifierErrorTypes.JWT_VERIFICATION_FAILED.getCode(),
                "JWT verification failed",
                HttpStatus.UNAUTHORIZED,
                "JWT signature verification failed");
    }

    @ExceptionHandler(JWTParsingException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public GlobalErrorMessage handleJWTParsingException(JWTParsingException ex, HttpServletRequest request) {
        return errors.handleSafe(ex, request,
                VerifierErrorTypes.JWT_PARSING_FAILED.getCode(),
                "JWT parsing failed",
                HttpStatus.UNAUTHORIZED,
                "The provided JWT could not be parsed");
    }

    @ExceptionHandler(InvalidScopeException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public GlobalErrorMessage handleInvalidScopeException(InvalidScopeException ex, HttpServletRequest request) {
        return errors.handleSafe(ex, request,
                VerifierErrorTypes.INVALID_SCOPE.getCode(),
                "Scope/binding error",
                HttpStatus.UNAUTHORIZED,
                "The requested scope is invalid");
    }

    @ExceptionHandler(CredentialMappingException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public GlobalErrorMessage handleCredentialMappingException(CredentialMappingException ex, HttpServletRequest request) {
        return errors.handleSafe(ex, request,
                VerifierErrorTypes.CREDENTIAL_MAPPING_ERROR.getCode(),
                "Credential mapping error",
                HttpStatus.BAD_REQUEST,
                "The credential could not be mapped");
    }

    @ExceptionHandler(SsrfProtectionException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public GlobalErrorMessage handleSsrfProtectionException(SsrfProtectionException ex, HttpServletRequest request) {
        return errors.handleSafe(ex, request,
                VerifierErrorTypes.SSRF_PROTECTION.getCode(),
                "Invalid URL",
                HttpStatus.BAD_REQUEST,
                "The provided URL is not allowed");
    }

    @ExceptionHandler(InvalidVPtokenException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public GlobalErrorMessage handleInvalidVPtokenException(InvalidVPtokenException ex, HttpServletRequest request) {
        return errors.handleSafe(ex, request,
                VerifierErrorTypes.INVALID_VP_TOKEN.getCode(),
                "Invalid VP Token",
                HttpStatus.UNAUTHORIZED,
                "The VP token is not valid");
    }

    @ExceptionHandler(LoginTimeoutException.class)
    @ResponseStatus(HttpStatus.UNAUTHORIZED)
    public GlobalErrorMessage handleLoginTimeoutException(LoginTimeoutException ex, HttpServletRequest request) {
        return errors.handleSafe(ex, request,
                VerifierErrorTypes.LOGIN_TIMEOUT.getCode(),
                "Login time has expired",
                HttpStatus.UNAUTHORIZED,
                "The login session has timed out");
    }

    @ExceptionHandler(StatusListCredentialException.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public GlobalErrorMessage handleStatusListCredentialException(StatusListCredentialException ex, HttpServletRequest request) {
        return errors.handleSafe(ex, request,
                VerifierErrorTypes.STATUS_LIST_ERROR.getCode(),
                "Status list credential error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An error occurred while processing the status list credential");
    }

    @ExceptionHandler(FailedCommunicationException.class)
    @ResponseStatus(HttpStatus.BAD_GATEWAY)
    public GlobalErrorMessage handleFailedCommunicationException(FailedCommunicationException ex, HttpServletRequest request) {
        return errors.handleSafe(ex, request,
                VerifierErrorTypes.FAILED_COMMUNICATION.getCode(),
                "Communication error",
                HttpStatus.BAD_GATEWAY,
                "An error occurred while communicating with an external service");
    }

    // SEC-W6: Bean Validation constraint violations return 400, not 500.
    @ExceptionHandler(ConstraintViolationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public GlobalErrorMessage handleConstraintViolationException(ConstraintViolationException ex, HttpServletRequest request) {
        return errors.handleSafe(ex, request,
                "validation_error",
                "Validation error",
                HttpStatus.BAD_REQUEST,
                "Request validation failed");
    }

    @ExceptionHandler(HandlerMethodValidationException.class)
    @ResponseStatus(HttpStatus.BAD_REQUEST)
    public GlobalErrorMessage handleHandlerMethodValidationException(HandlerMethodValidationException ex, HttpServletRequest request) {
        return errors.handleSafe(ex, request,
                "validation_error",
                "Validation error",
                HttpStatus.BAD_REQUEST,
                "Request validation failed");
    }

    // SEC-13: Catch-all handler — never leaks internal details
    @ExceptionHandler(Exception.class)
    @ResponseStatus(HttpStatus.INTERNAL_SERVER_ERROR)
    public GlobalErrorMessage handleUnexpectedException(Exception ex, HttpServletRequest request) {
        return errors.handleSafe(ex, request,
                "internal_server_error",
                "Internal server error",
                HttpStatus.INTERNAL_SERVER_ERROR,
                "An unexpected error occurred");
    }
}
