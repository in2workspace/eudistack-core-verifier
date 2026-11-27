package es.in2.vcverifier.verifier.infrastructure.audit;

import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
import es.in2.vcverifier.shared.config.TenantDomainFilter;
import es.in2.vcverifier.shared.domain.model.AssuranceLevel;
import es.in2.vcverifier.shared.domain.model.CertificateIdentity;
import es.in2.vcverifier.shared.domain.model.ClientCertificate;
import es.in2.vcverifier.shared.domain.model.SessionOrigin;
import es.in2.vcverifier.shared.domain.model.audit.AuditEntry;
import es.in2.vcverifier.shared.domain.model.audit.AuditEventType;
import es.in2.vcverifier.shared.domain.model.audit.AuditResult;
import es.in2.vcverifier.shared.domain.port.AuditTrailPort;
import es.in2.vcverifier.shared.domain.port.RecordingAuditTrail;
import es.in2.vcverifier.shared.infrastructure.audit.RejectionThrottle;
import es.in2.vcverifier.verifier.domain.model.CertificateLoginReason;
import es.in2.vcverifier.verifier.domain.model.audit.AuditedPerson;
import es.in2.vcverifier.verifier.domain.model.audit.CertificateAuthenticationAudit;
import es.in2.vcverifier.verifier.domain.model.audit.IamSessionAudit;
import es.in2.vcverifier.verifier.infrastructure.logging.AuthenticationAuditLogger;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.slf4j.LoggerFactory;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import java.time.Instant;
import java.util.Map;
import java.util.stream.IntStream;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatCode;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;

class AuthenticationAuditTrailAdapterTest {

    private static final CertificateIdentity IDENTITY = new CertificateIdentity(
            "JOSE ANTONIO", "GARCIA FERNANDEZ", "GARCIA FERNANDEZ JOSE ANTONIO", "jose@example.com", "ES", "12345678Z");
    private static final ClientCertificate CERTIFICATE = new ClientCertificate(
            IDENTITY, "CN=AC FNMT Usuarios", "ab12cd", Instant.parse("2027-01-01T00:00:00Z"));

    private final AuthenticationAuditLogger logger = mock(AuthenticationAuditLogger.class);
    private final RecordingAuditTrail auditTrail = new RecordingAuditTrail();
    private final AuthenticationAuditTrailAdapter adapter = new AuthenticationAuditTrailAdapter(logger, auditTrail);

    @Test
    void certificateAuthentication_success_logsAndStagesItInATransactionOfItsOwn() {
        CertificateAuthenticationAudit event = success("corr-1");

        adapter.certificateAuthentication(event);

        verify(logger).certificateAuthentication(event);
        assertThat(auditTrail.staged()).isEmpty();
        AuditEntry entry = auditTrail.stagedInNewTransaction().getFirst();
        assertThat(entry.type()).isEqualTo(AuditEventType.CERTIFICATE_AUTHENTICATION);
        assertThat(entry.result()).isEqualTo(AuditResult.SUCCESS);
    }

    @Test
    void certificateAuthentication_rejection_stagesTheDenial() {
        adapter.certificateAuthentication(rejected(CertificateLoginReason.CERTIFICATE_REVOKED));

        AuditEntry entry = auditTrail.stagedInNewTransaction().getFirst();
        assertThat(entry.result()).isEqualTo(AuditResult.DENIED);
        assertThat(entry.reason()).isEqualTo("CertificateRevoked");
    }

    @Test
    void certificateAuthentication_repeatedRejection_isBoundedPerTenantClientAndReason() {
        IntStream.range(0, RejectionThrottle.MAX_PER_KEY + 2)
                .forEach(_ -> adapter.certificateAuthentication(rejected(CertificateLoginReason.CERTIFICATE_MISSING)));
        adapter.certificateAuthentication(rejected(CertificateLoginReason.LEVEL_NOT_MET));

        assertThat(auditTrail.stagedInNewTransaction()).extracting(AuditEntry::reason)
                .containsExactly("CertificateMissing", "CertificateMissing", "CertificateMissing", "LevelNotMet");
    }

    @Test
    void certificateAuthentication_throttledRejection_leavesALogLineWithoutPersonalData() {
        Logger adapterLogger = (Logger) LoggerFactory.getLogger(AuthenticationAuditTrailAdapter.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        adapterLogger.addAppender(appender);
        try {
            IntStream.range(0, RejectionThrottle.MAX_PER_KEY + 1)
                    .forEach(_ -> adapter.certificateAuthentication(rejected(CertificateLoginReason.CERTIFICATE_REVOKED)));
        } finally {
            adapterLogger.detachAppender(appender);
        }

        assertThat(appender.list).extracting(ILoggingEvent::getFormattedMessage).containsExactly(
                "event=authentication_audit_throttled event_type=CertificateAuthentication tenant=cgcom "
                        + "clientId=portal reason=CertificateRevoked correlation_id=corr-1");
        assertThat(appender.list.getFirst().getFormattedMessage())
                .doesNotContain("12345678Z", "JOSE", "jose@example.com", "ab12cd", "AC FNMT");
    }

    @Test
    void certificateAuthentication_repeatedSuccess_isNeverThrottled() {
        IntStream.range(0, RejectionThrottle.MAX_PER_KEY + 2)
                .forEach(i -> adapter.certificateAuthentication(success("corr-" + i)));

        assertThat(auditTrail.stagedInNewTransaction()).hasSize(RejectionThrottle.MAX_PER_KEY + 2);
    }

    @Test
    void iamSessionEstablished_logsAndStagesIt() {
        IamSessionAudit event = new IamSessionAudit("cgcom", "corr-1", "portal", SessionOrigin.CERTIFICATE,
                AuditResult.SUCCESS, AuditedPerson.of(IDENTITY), Map.of("given_name", "JOSE ANTONIO"));

        adapter.iamSessionEstablished(event);

        verify(logger).iamSessionEstablished(event);
        AuditEntry entry = auditTrail.stagedInNewTransaction().getFirst();
        assertThat(entry.type()).isEqualTo(AuditEventType.IAM_SESSION_ESTABLISHED);
        assertThat(entry.details()).containsEntry("session_origin", "Certificate");
    }

    @Test
    void iamSessionEstablished_requestOnTheClientTenant_isStaged() {
        onRequestOfTenant("cgcom");

        adapter.iamSessionEstablished(session("cgcom"));

        assertThat(auditTrail.stagedInNewTransaction()).hasSize(1);
    }

    @Test
    void iamSessionEstablished_requestOnAnotherTenant_isNotStagedAndLeavesAWarning() {
        onRequestOfTenant("kpmg");
        IamSessionAudit event = session("cgcom");
        Logger adapterLogger = (Logger) LoggerFactory.getLogger(AuthenticationAuditTrailAdapter.class);
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        adapterLogger.addAppender(appender);
        try {
            adapter.iamSessionEstablished(event);
        } finally {
            adapterLogger.detachAppender(appender);
        }

        verify(logger).iamSessionEstablished(event);
        assertThat(auditTrail.all()).isEmpty();
        assertThat(appender.list).extracting(ILoggingEvent::getFormattedMessage).containsExactly(
                "event=authentication_audit_tenant_mismatch event_type=IamSessionEstablished client_tenant=cgcom "
                        + "request_tenant=kpmg clientId=portal correlation_id=corr-1");
        assertThat(appender.list.getFirst().getFormattedMessage()).doesNotContain("12345678Z", "JOSE", "jose@example.com");
    }

    @Test
    void iamSessionEstablished_clientWithoutTenant_isStaged() {
        onRequestOfTenant("cgcom");

        adapter.iamSessionEstablished(session(null));

        assertThat(auditTrail.stagedInNewTransaction()).hasSize(1);
    }

    @Test
    void iamSessionEstablished_requestWithoutTenant_isStaged() {
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(new MockHttpServletRequest()));

        adapter.iamSessionEstablished(session("cgcom"));

        assertThat(auditTrail.stagedInNewTransaction()).hasSize(1);
    }

    @AfterEach
    void clearRequest() {
        RequestContextHolder.resetRequestAttributes();
    }

    private static void onRequestOfTenant(String tenant) {
        MockHttpServletRequest request = new MockHttpServletRequest();
        request.setAttribute(TenantDomainFilter.TENANT_ATTRIBUTE, tenant);
        RequestContextHolder.setRequestAttributes(new ServletRequestAttributes(request));
    }

    private static IamSessionAudit session(String tenant) {
        return new IamSessionAudit(tenant, "corr-1", "portal", SessionOrigin.CERTIFICATE, AuditResult.SUCCESS,
                AuditedPerson.of(IDENTITY), Map.of("given_name", "JOSE ANTONIO"));
    }

    @Test
    void iamSessionEstablished_failure_stagesTokenIssuanceFailed() {
        adapter.iamSessionEstablished(new IamSessionAudit("cgcom", "corr-1", "portal", SessionOrigin.SSO_REUSE,
                AuditResult.FAILURE, AuditedPerson.UNKNOWN, null));

        assertThat(auditTrail.stagedInNewTransaction().getFirst().reason()).isEqualTo("TokenIssuanceFailed");
    }

    @Test
    void outboxUnavailable_neverFailsTheCaller() {
        AuthenticationAuditTrailAdapter failing = new AuthenticationAuditTrailAdapter(logger,
                new RecordingAuditTrail().failingOnNewTransaction());
        IamSessionAudit session = new IamSessionAudit("cgcom", "corr-1", "portal", SessionOrigin.CERTIFICATE,
                AuditResult.SUCCESS, AuditedPerson.UNKNOWN, null);

        assertThatCode(() -> failing.certificateAuthentication(success("corr-1"))).doesNotThrowAnyException();
        assertThatCode(() -> failing.iamSessionEstablished(session)).doesNotThrowAnyException();
    }

    @Test
    void stagingFails_stillLogsAndNeverFailsTheCaller() {
        AuditTrailPort withoutContext = mock(AuditTrailPort.class);
        doThrow(new IllegalStateException("no audit context")).when(withoutContext).stageBestEffort(any());
        AuthenticationAuditTrailAdapter outOfContext = new AuthenticationAuditTrailAdapter(logger, withoutContext);
        CertificateAuthenticationAudit event = success("corr-1");

        assertThatCode(() -> outOfContext.certificateAuthentication(event)).doesNotThrowAnyException();
        verify(logger).certificateAuthentication(event);
    }

    private static CertificateAuthenticationAudit success(String correlationId) {
        return CertificateAuthenticationAudit.success("cgcom", correlationId, "portal", CERTIFICATE,
                AssuranceLevel.HIGH, "hwk", AuditedPerson.of(IDENTITY));
    }

    private static CertificateAuthenticationAudit rejected(CertificateLoginReason reason) {
        return CertificateAuthenticationAudit.rejected("cgcom", "corr-1", "portal", reason,
                reason == CertificateLoginReason.CERTIFICATE_MISSING ? null : CERTIFICATE);
    }
}
