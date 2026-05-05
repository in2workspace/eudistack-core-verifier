package es.in2.vcverifier.shared.config;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.LoggerContext;
import ch.qos.logback.classic.spi.LoggingEvent;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;

class MaskingPatternLayoutTest {
    private static final String MASK = "***REDACTED***";

    private static final String SAMPLE_JWT =
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9"
                    + ".eyJzdWIiOiJ1c2VyMTIzIiwiZXhwIjoxNzAwMDAwMDAwfQ"
                    + ".SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";

    private MaskingPatternLayout layout;
    private LoggerContext loggerContext;

    @BeforeEach
    void setUp() {
        loggerContext = new LoggerContext();
        loggerContext.start();

        layout = new MaskingPatternLayout();
        layout.setContext(loggerContext);
        layout.setPattern("%msg");   // output = exactly the formatted message
        layout.start();
    }

    // ─── Helper ───────────────────────────────────────────────────────────────

    private String applyLayout(String message) {
        ch.qos.logback.classic.Logger logger = loggerContext.getLogger("test-logger");
        LoggingEvent event = new LoggingEvent(
                MaskingPatternLayoutTest.class.getName(),
                logger, Level.INFO, message, null, null
        );
        return layout.doLayout(event);
    }

    // ─── JWT masking ──────────────────────────────────────────────────────────

    @Test
    void doLayout_MessageContainsJwt_MasksEntireJwtToken() {
        // Arrange
        String message = "Token received: " + SAMPLE_JWT;

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result)
                .contains(MASK)
                .doesNotContain("eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9");
    }

    @Test
    void doLayout_MessageIsOnlyJwt_ReplacesWholeStringWithMask() {
        // Arrange – message is the JWT itself, no surrounding text

        // Act
        String result = applyLayout(SAMPLE_JWT);

        // Assert
        assertThat(result).isEqualTo(MASK);
    }

    @Test
    void doLayout_JsonBodyWithJwtValue_MasksJwtPreservingJsonStructure() {
        // Arrange
        String message = "{\"id_token\":\"" + SAMPLE_JWT + "\",\"expires_in\":3600}";

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result)
                .contains(MASK)
                .doesNotContain(SAMPLE_JWT)
                .contains("\"expires_in\":3600");
    }

    @Test
    void doLayout_MultipleJwtsInMessage_MasksAllOccurrences() {
        // Arrange
        String message = "old=" + SAMPLE_JWT + " new=" + SAMPLE_JWT;

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result)
                .doesNotContain("eyJhbGciOiJSU")
                .contains(MASK);
    }

    // ─── Bearer token masking ─────────────────────────────────────────────────

    @Test
    void doLayout_AuthorizationHeaderWithBearerJwt_MasksTokenKeepingBearerPrefix() {
        // Arrange
        String message = "Authorization: Bearer " + SAMPLE_JWT;

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result)
                .contains("Bearer " + MASK)
                .doesNotContain(SAMPLE_JWT);
    }

    @Test
    void doLayout_AuthorizationHeaderWithBearerOpaqueToken_MasksTokenKeepingBearerPrefix() {
        // Arrange
        String message = "Authorization: Bearer abc123XYZopaqueToken456";

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result)
                .contains("Bearer " + MASK)
                .doesNotContain("abc123XYZopaqueToken456");
    }

    @Test
    void doLayout_BearerKeywordIsLowercase_MasksTokenCaseInsensitively() {
        // Arrange
        String message = "header: bearer xYz-opaque-token";

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result)
                .doesNotContain("xYz-opaque-token")
                .contains(MASK);
    }

    @Test
    void doLayout_BearerKeywordIsMixedCase_MasksTokenCaseInsensitively() {
        // Arrange
        String message = "BEARER some-token-value";

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result)
                .doesNotContain("some-token-value")
                .contains(MASK);
    }

    // ─── Email masking ────────────────────────────────────────────────────────

    @Test
    void doLayout_MessageContainsSimpleEmail_MasksEmailAddress() {
        // Arrange
        String message = "User admin@empresa.com authenticated successfully";

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result)
                .contains(MASK)
                .doesNotContain("admin@empresa.com")
                .contains("User")
                .contains("authenticated successfully");
    }

    @Test
    void doLayout_MessageContainsEmailWithPlusTag_MasksFullEmailAddress() {
        // Arrange
        String message = "Login attempt from user.name+tag@mail.subdomain.org failed";

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result)
                .contains(MASK)
                .doesNotContain("user.name+tag@mail.subdomain.org");
    }

    @Test
    void doLayout_MessageContainsTwoEmails_MasksBothAddresses() {
        // Arrange
        String message = "From: sender@example.com To: recipient@domain.net";

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result)
                .doesNotContain("sender@example.com")
                .doesNotContain("recipient@domain.net")
                .containsPattern("\\*\\*\\*REDACTED\\*\\*\\*.*\\*\\*\\*REDACTED\\*\\*\\*");
    }

    // ─── access_token masking ─────────────────────────────────────────────────

    @Test
    void doLayout_JsonBodyWithAccessToken_MasksTokenValueKeepingKey() {
        // Arrange
        String message = "{\"access_token\":\"super-secret-value\",\"token_type\":\"Bearer\"}";

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result)
                .contains("\"access_token\"")
                .contains(MASK)
                .doesNotContain("super-secret-value")
                .contains("\"token_type\":\"Bearer\"");
    }

    @Test
    void doLayout_QueryStringWithAccessToken_MasksTokenValueKeepingKey() {
        // Arrange
        String message = "POST /token access_token=abc123secret&grant_type=authorization_code";

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result)
                .contains("access_token=")
                .contains(MASK)
                .doesNotContain("abc123secret");
    }

    // ─── refresh_token masking ────────────────────────────────────────────────

    @Test
    void doLayout_JsonBodyWithRefreshToken_MasksTokenValueKeepingKey() {
        // Arrange
        String message = "{\"refresh_token\":\"rt-secret-xyz789\",\"expires_in\":86400}";

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result)
                .contains("\"refresh_token\"")
                .contains(MASK)
                .doesNotContain("rt-secret-xyz789")
                .contains("\"expires_in\":86400");
    }

    @Test
    void doLayout_QueryStringWithRefreshToken_MasksTokenValueKeepingKey() {
        // Arrange
        String message = "refresh_token=myRefreshTokenValue&client_id=my-app";

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result)
                .contains("refresh_token=")
                .contains(MASK)
                .doesNotContain("myRefreshTokenValue");
    }

    // ─── tx_code masking ──────────────────────────────────────────────────────

    @Test
    void doLayout_QueryStringWithTxCode_MasksCodeValueKeepingKey() {
        // Arrange
        String message = "Received tx_code=USER-PIN-1234 from client";

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result)
                .contains("tx_code=")
                .contains(MASK)
                .doesNotContain("USER-PIN-1234");
    }

    @Test
    void doLayout_JsonBodyWithTxCode_MasksCodeValueKeepingKey() {
        // Arrange
        String message = "{\"tx_code\":\"9876\","
                + "\"grant_type\":\"urn:ietf:params:oauth:grant-type:pre-authorized_code\"}";

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result)
                .contains("\"tx_code\"")
                .contains(MASK)
                .doesNotContain("\"9876\"");
    }

    // ─── password masking ─────────────────────────────────────────────────────

    @Test
    void doLayout_QueryStringWithPassword_MasksPasswordValueKeepingKey() {
        // Arrange
        String message = "Binding LDAP with password=MyS3cr3tP@ssw0rd";

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result)
                .contains("password=")
                .contains(MASK)
                .doesNotContain("MyS3cr3tP");
    }

    @Test
    void doLayout_JsonBodyWithPassword_MasksPasswordValueKeepingKey() {
        // Arrange
        String message = "{\"username\":\"admin\",\"password\":\"hunter2\"}";

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result)
                .contains("\"password\"")
                .contains(MASK)
                .doesNotContain("hunter2")
                .contains("\"username\":\"admin\"");
    }

    // ─── secret masking ───────────────────────────────────────────────────────

    @Test
    void doLayout_QueryStringWithSecret_MasksSecretValueKeepingKey() {
        // Arrange
        String message = "OAuth client secret=s3cr3t-c1ient-v4lue registered";

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result)
                .contains("secret=")
                .contains(MASK)
                .doesNotContain("s3cr3t-c1ient-v4lue");
    }

    @Test
    void doLayout_JsonBodyWithSecret_MasksSecretValueKeepingKey() {
        // Arrange
        String message = "{\"client_id\":\"my-app\",\"secret\":\"top-secret-value\"}";

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result)
                .contains("\"secret\"")
                .contains(MASK)
                .doesNotContain("top-secret-value")
                .contains("\"client_id\":\"my-app\"");
    }

    @Test
    void doLayout_YamlStyleWithSecret_MasksSecretValueKeepingKey() {
        // Arrange
        String message = "secret: my-yaml-secret-value";

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result)
                .contains("secret")
                .contains(MASK)
                .doesNotContain("my-yaml-secret-value");
    }

    // ─── Escenarios de log realistas ─────────────────────────────────────────

    @Test
    void doLayout_RealisticAuthLogWithEmailAndBearerJwt_MasksBothSensitiveParts() {
        // Arrange
        String message = "User admin@empresa.com authenticated with token Bearer " + SAMPLE_JWT;

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result)
                .doesNotContain("admin@empresa.com")
                .doesNotContain(SAMPLE_JWT)
                .contains("Bearer " + MASK)
                .contains("User")
                .contains("authenticated with token");
    }

    @Test
    void doLayout_TokenEndpointResponseWithMultipleSecretFields_MasksAllSensitiveFields() {
        // Arrange
        String message = "{\"access_token\":\"access-val\","
                + "\"refresh_token\":\"refresh-val\","
                + "\"id_token\":\"" + SAMPLE_JWT + "\","
                + "\"token_type\":\"Bearer\","
                + "\"expires_in\":3600}";

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result)
                .doesNotContain("access-val")
                .doesNotContain("refresh-val")
                .doesNotContain(SAMPLE_JWT)
                .contains("\"token_type\":\"Bearer\"")
                .contains("\"expires_in\":3600");
    }

    @Test
    void doLayout_LongMessageWithAllSensitiveTypes_MasksEverythingWithoutTruncation() {
        // Arrange
        String message = String.format(
                "User %s logged in, password=%s, received access_token=%s, Bearer %s",
                "user@test.com", "pass123", "tok123", SAMPLE_JWT
        );

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result)
                .doesNotContain("user@test.com")
                .doesNotContain("pass123")
                .doesNotContain("tok123")
                .doesNotContain(SAMPLE_JWT)
                .contains("Bearer " + MASK);
    }

    // ─── Prevención de falsos positivos ──────────────────────────────────────

    @Test
    void doLayout_PlainInfoMessageWithoutSensitiveData_LeavesMessageUnchanged() {
        // Arrange
        String message = "Application started successfully on port 8080";

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result).isEqualTo(message);
    }

    @Test
    void doLayout_MessageContainsStandardUuid_DoesNotMaskUuid() {
        // Arrange
        String message = "Processing request id=550e8400-e29b-41d4-a716-446655440000";

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result)
                .contains("550e8400-e29b-41d4-a716-446655440000")
                .doesNotContain(MASK);
    }

    @Test
    void doLayout_MessageContainsHttpsUrl_DoesNotMaskUrl() {
        // Arrange
        String message = "Calling endpoint https://example.com/api/v1/token?grant_type=client_credentials";

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result)
                .contains("https://example.com/api/v1/token")
                .contains("grant_type=client_credentials")
                .doesNotContain(MASK);
    }

    @Test
    void doLayout_MessageWithNonSensitiveQueryParams_DoesNotMaskAnyParam() {
        // Arrange
        String message = "grant_type=authorization_code&code=AUTH-CODE-123&redirect_uri=https://example.com/cb";

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result)
                .contains("grant_type=authorization_code")
                .contains("code=AUTH-CODE-123")
                .contains("redirect_uri=https://example.com/cb")
                .doesNotContain(MASK);
    }

    @Test
    void doLayout_MessageWithPasswordInUrlPathNotKeyValue_DoesNotMaskPathSegment() {
        // Arrange
        // "password-reset" es un segmento de ruta, no un par clave=valor; no debe enmascararse.
        String message = "Redirecting to /api/password-reset?code=resetCode123";

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result)
                .contains("password-reset");
    }

    @Test
    void doLayout_MessageWithSingleBase64SegmentWithoutJwtStructure_DoesNotMask() {
        // Arrange
        // Un único segmento Base64 sin la estructura eyJ...eyJ...sig no es un JWT
        String message = "Encoded value: dGhpcyBpcyBub3QgYSBqd3Q=";

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result)
                .contains("dGhpcyBpcyBub3QgYSBqd3Q=")
                .doesNotContain(MASK);
    }

    @Test
    void doLayout_MessageWithAtSymbolNotFollowedByValidDomain_DoesNotMaskAnnotation() {
        // Arrange
        // "@NotNull" no es un email válido: no tiene dominio con TLD tras el @
        String message = "Annotation @NotNull applied to field username";

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result)
                .contains("@NotNull")
                .doesNotContain(MASK);
    }

    @Test
    void doLayout_MessageWithVersionNumberContainingDots_DoesNotMask() {
        // Arrange
        String message = "Spring Boot version 3.5.11 started in 2.345 seconds";

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result)
                .isEqualTo(message)
                .doesNotContain(MASK);
    }

    @Test
    void doLayout_MessageContainsClientIdNotInSensitiveKeysList_DoesNotMaskClientId() {
        // Arrange
        String message = "client_id=my-application-id registered";

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result)
                .contains("my-application-id")
                .doesNotContain(MASK);
    }

    // ─── Edge cases ───────────────────────────────────────────────────────────

    @Test
    void doLayout_EmptyMessage_ReturnsEmptyStringWithoutException() {
        // Arrange
        String message = "";

        // Act & Assert
        assertThatCode(() -> {
            String result = applyLayout(message);
            assertThat(result).isEmpty();
        }).doesNotThrowAnyException();
    }

    @Test
    void doLayout_MessageWithOnlyWhitespace_ReturnsWhitespaceUnchanged() {
        // Arrange
        String message = "   ";

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result).isEqualTo(message);
    }

    @Test
    void doLayout_MessageWithNoSensitiveData_ReturnsOriginalContent() {
        // Arrange
        String message = "INFO - Server listening on 0.0.0.0:8443 with TLS enabled";

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result).isEqualTo(message);
    }

    @Test
    void doLayout_MessageWithSpecialRegexCharacters_DoesNotThrowException() {
        // Arrange
        // Caracteres que podrían romper un regex mal construido
        String message = "Unexpected chars: []{}.^$|*+?()\\";

        // Act & Assert
        assertThatCode(() -> applyLayout(message)).doesNotThrowAnyException();
    }

    @Test
    void doLayout_VeryLongMessageWithSingleEmailEmbedded_MasksEmailWithoutTruncation() {
        // Arrange
        String prefix = "x".repeat(500);
        String suffix = "y".repeat(500);
        String message = prefix + " contact@company.io " + suffix;

        // Act
        String result = applyLayout(message);

        // Assert
        assertThat(result)
                .doesNotContain("contact@company.io")
                .contains(MASK)
                .hasSize(message.length() - "contact@company.io".length() + MASK.length());
    }
}


