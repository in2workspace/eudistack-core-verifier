package es.in2.vcverifier.verifier.infrastructure.logging;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import es.in2.vcverifier.shared.domain.model.AssuranceLevel;
import es.in2.vcverifier.shared.domain.model.CertificateIdentity;
import es.in2.vcverifier.shared.domain.model.ClientCertificate;
import es.in2.vcverifier.shared.domain.model.SessionOrigin;
import es.in2.vcverifier.shared.domain.model.audit.AuditResult;
import es.in2.vcverifier.verifier.domain.model.CertificateLoginReason;
import es.in2.vcverifier.verifier.domain.model.audit.AuditedPerson;
import es.in2.vcverifier.verifier.domain.model.audit.CertificateAuthenticationAudit;
import es.in2.vcverifier.verifier.domain.model.audit.IamSessionAudit;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;

import java.time.Instant;
import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class AuthenticationAuditLoggerTest {

    private static final CertificateIdentity IDENTITY = new CertificateIdentity(
            "JOSE ANTONIO", "GARCIA FERNANDEZ", "GARCIA FERNANDEZ JOSE ANTONIO", "jose@example.com", "ES", "12345678Z");
    private static final ClientCertificate CERTIFICATE = new ClientCertificate(
            IDENTITY, "CN=AC FNMT Usuarios", "sha256:ab12cd", Instant.parse("2027-01-01T00:00:00Z"));

    private final AuthenticationAuditLogger adapter = new AuthenticationAuditLogger();
    private final Logger logger = (Logger) LoggerFactory.getLogger(AuthenticationAuditLogger.class);
    private final ListAppender<ILoggingEvent> appender = new ListAppender<>();

    @BeforeEach
    void attach() {
        appender.start();
        logger.addAppender(appender);
    }

    @AfterEach
    void detach() {
        logger.detachAppender(appender);
    }

    @Test
    void certificateAuthentication_success_logsTypeCorrelationAndResultWithoutReason() {
        adapter.certificateAuthentication(CertificateAuthenticationAudit.success("cgcom", "corr-1", "portal",
                CERTIFICATE, AssuranceLevel.HIGH, "hwk", AuditedPerson.of(IDENTITY)));

        assertThat(onlyLine()).isEqualTo(
                "event=audit event_type=CertificateAuthentication correlation_id=corr-1 result=Success reason=-");
    }

    @Test
    void certificateAuthentication_rejection_logsTheCatalogueReason() {
        adapter.certificateAuthentication(CertificateAuthenticationAudit.rejected("cgcom", "corr-1", "portal",
                CertificateLoginReason.CERTIFICATE_REVOKED, CERTIFICATE));

        assertThat(onlyLine()).isEqualTo(
                "event=audit event_type=CertificateAuthentication correlation_id=corr-1 result=Denied reason=CertificateRevoked");
    }

    @Test
    void certificateAuthentication_validationUnavailable_logsAFailure() {
        adapter.certificateAuthentication(CertificateAuthenticationAudit.rejected("cgcom", "corr-1", "portal",
                CertificateLoginReason.VALIDATION_UNAVAILABLE, CERTIFICATE));

        assertThat(onlyLine()).contains("result=Failure reason=ValidationUnavailable");
    }

    @Test
    void iamSessionEstablished_failure_logsTokenIssuanceFailed() {
        adapter.iamSessionEstablished(new IamSessionAudit("cgcom", "corr-2", "portal", SessionOrigin.CERTIFICATE,
                AuditResult.FAILURE, AuditedPerson.of(IDENTITY), null));

        assertThat(onlyLine()).isEqualTo(
                "event=audit event_type=IamSessionEstablished correlation_id=corr-2 result=Failure reason=TokenIssuanceFailed");
    }

    @Test
    void auditLines_neverContainPersonalOrCertificateData() {
        adapter.certificateAuthentication(CertificateAuthenticationAudit.success("cgcom", "corr-1", "portal",
                CERTIFICATE, AssuranceLevel.HIGH, "hwk", AuditedPerson.of(IDENTITY)));
        adapter.iamSessionEstablished(new IamSessionAudit("cgcom", "corr-1", "portal", SessionOrigin.CERTIFICATE,
                AuditResult.SUCCESS, AuditedPerson.of(IDENTITY),
                Map.of("personal_administrative_number", "12345678Z", "email", "jose@example.com")));

        assertThat(appender.list).hasSize(2).allSatisfy(event -> assertThat(event.getFormattedMessage())
                .doesNotContain("12345678Z", "JOSE", "GARCIA", "jose@example.com", "ab12cd", "AC FNMT", "portal"));
    }

    private String onlyLine() {
        assertThat(appender.list).hasSize(1);
        return appender.list.getFirst().getFormattedMessage();
    }
}
