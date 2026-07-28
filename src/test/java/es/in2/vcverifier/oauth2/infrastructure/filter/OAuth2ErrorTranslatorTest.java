package es.in2.vcverifier.oauth2.infrastructure.filter;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.security.oauth2.core.OAuth2AuthenticationException;
import org.springframework.security.oauth2.core.OAuth2Error;
import org.springframework.security.oauth2.core.OAuth2ErrorCodes;

import static org.assertj.core.api.Assertions.assertThat;

/**
 * AC-04: every OAuth2AuthenticationException built by this translator must carry only the error
 * code — description and uri must stay null so no internal detail ever leaks to the client.
 */
class OAuth2ErrorTranslatorTest {

    @Test
    @DisplayName("invalidClient() returns invalid_client with no description or uri")
    void invalidClient_hasNoDescriptionOrUri() {
        OAuth2AuthenticationException exception = OAuth2ErrorTranslator.invalidClient();

        OAuth2Error error = exception.getError();
        assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_CLIENT);
        assertThat(error.getDescription()).isNull();
        assertThat(error.getUri()).isNull();
    }

    @Test
    @DisplayName("invalidGrant() returns invalid_grant with no description or uri")
    void invalidGrant_hasNoDescriptionOrUri() {
        OAuth2AuthenticationException exception = OAuth2ErrorTranslator.invalidGrant();

        OAuth2Error error = exception.getError();
        assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.INVALID_GRANT);
        assertThat(error.getDescription()).isNull();
        assertThat(error.getUri()).isNull();
    }

    @Test
    @DisplayName("serverError() returns server_error with no description or uri")
    void serverError_hasNoDescriptionOrUri() {
        OAuth2AuthenticationException exception = OAuth2ErrorTranslator.serverError();

        OAuth2Error error = exception.getError();
        assertThat(error.getErrorCode()).isEqualTo(OAuth2ErrorCodes.SERVER_ERROR);
        assertThat(error.getDescription()).isNull();
        assertThat(error.getUri()).isNull();
    }
}
