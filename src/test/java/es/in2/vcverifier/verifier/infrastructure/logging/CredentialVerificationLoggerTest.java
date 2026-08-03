package es.in2.vcverifier.verifier.infrastructure.logging;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import es.in2.vcverifier.shared.config.TenantDomainFilter;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import static org.assertj.core.api.Assertions.assertThat;

class CredentialVerificationLoggerTest {

    private ListAppender<ILoggingEvent> appender;
    private CredentialVerificationLogger credentialVerificationLogger;

    @BeforeEach
    void setUp() {
        Logger logger = (Logger) LoggerFactory.getLogger(CredentialVerificationLogger.class);
        appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);

        credentialVerificationLogger = new CredentialVerificationLogger();
    }

    @AfterEach
    void tearDown() {
        RequestContextHolder.resetRequestAttributes();
        Logger logger = (Logger) LoggerFactory.getLogger(CredentialVerificationLogger.class);
        logger.detachAppender(appender);
    }

    @Test
    void logVerifiedOk_emitsInfoWithEventTenantAndOk() {
        bindRequestWithTenant("kpmg");

        credentialVerificationLogger.logVerifiedOk("learcredential.employee.w3c.4");

        assertThat(appender.list).hasSize(1);
        ILoggingEvent event = appender.list.getFirst();
        assertThat(event.getLevel()).isEqualTo(Level.INFO);
        assertThat(event.getFormattedMessage())
                .contains("event=business.credential.verified")
                .contains("tenant=kpmg")
                .contains("configurationId=learcredential.employee.w3c.4")
                .contains("outcome=ok");
    }

    @Test
    void logVerifiedError_emitsWarnWithEventTenantErrorAndErrorType() {
        bindRequestWithTenant("kpmg");

        credentialVerificationLogger.logVerifiedError("learcredential.employee.w3c.4",
                new IllegalStateException("boom"));

        assertThat(appender.list).hasSize(1);
        ILoggingEvent event = appender.list.getFirst();
        assertThat(event.getLevel()).isEqualTo(Level.WARN);
        assertThat(event.getFormattedMessage())
                .contains("event=business.credential.verified")
                .contains("tenant=kpmg")
                .contains("configurationId=learcredential.employee.w3c.4")
                .contains("outcome=error")
                .contains("errorType=IllegalStateException");
    }

    @Test
    void logVerifiedOk_noRequestBound_tenantFallsBackToUnknown() {
        credentialVerificationLogger.logVerifiedOk("learcredential.employee.w3c.4");

        assertThat(appender.list.getFirst().getFormattedMessage()).contains("tenant=unknown");
    }

    @Test
    void logVerifiedOk_nullOrBlankConfigurationId_fallsBackToUnknown() {
        credentialVerificationLogger.logVerifiedOk(null);
        credentialVerificationLogger.logVerifiedOk("  ");

        assertThat(appender.list).hasSize(2);
        assertThat(appender.list.get(0).getFormattedMessage()).contains("configurationId=unknown");
        assertThat(appender.list.get(1).getFormattedMessage()).contains("configurationId=unknown");
    }

    @Test
    void logVerifiedError_nullError_fallsBackToUnknownErrorType() {
        credentialVerificationLogger.logVerifiedError("learcredential.employee.w3c.4", null);

        assertThat(appender.list.getFirst().getFormattedMessage()).contains("errorType=unknown");
    }

    @Test
    void logVerifiedOk_resolvesTenantFromRequest() {
        bindRequestWithTenant("kpmg");

        credentialVerificationLogger.logVerifiedOk("learcredential.employee.w3c.4");

        assertThat(appender.list.getFirst().getFormattedMessage()).contains("tenant=kpmg");
    }

    private void bindRequestWithTenant(String tenant) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(TenantDomainFilter.TENANT_ATTRIBUTE, tenant);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }
}
