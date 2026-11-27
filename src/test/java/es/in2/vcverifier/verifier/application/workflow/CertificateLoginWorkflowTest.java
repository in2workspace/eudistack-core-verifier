package es.in2.vcverifier.verifier.application.workflow;

import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.shared.crypto.CertificateSubjectService;
import es.in2.vcverifier.shared.crypto.ClientCertificateReader;
import es.in2.vcverifier.shared.domain.model.AssuranceLevel;
import es.in2.vcverifier.shared.domain.model.CertificateAuthentication;
import es.in2.vcverifier.shared.domain.model.CertificateIdentity;
import es.in2.vcverifier.shared.domain.model.ClientCertificate;
import es.in2.vcverifier.shared.domain.model.audit.AuditResult;
import es.in2.vcverifier.shared.domain.port.RecordingAuditTrail;
import es.in2.vcverifier.sso.application.workflow.SsoLoginCompletionWorkflow;
import es.in2.vcverifier.sso.domain.exception.LoginCompletionUnavailableException;
import es.in2.vcverifier.verifier.application.workflow.CertificateLoginWorkflow.Outcome;
import es.in2.vcverifier.verifier.domain.model.AuthResponseResult;
import es.in2.vcverifier.verifier.domain.model.CertificateLoginReason;
import es.in2.vcverifier.verifier.domain.model.CertificateTrust;
import es.in2.vcverifier.verifier.domain.model.audit.AuditedPerson;
import es.in2.vcverifier.verifier.domain.model.audit.CertificateAuthenticationAudit;
import es.in2.vcverifier.verifier.domain.port.AuthenticationAuditPort;
import es.in2.vcverifier.verifier.domain.port.CertificateTrustValidationPort;
import es.in2.vcverifier.verifier.domain.service.AuthorizationResponseProcessorService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;

import java.security.cert.X509Certificate;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.function.Supplier;

import static es.in2.vcverifier.shared.domain.util.Constants.ACR_ESSENTIAL;
import static es.in2.vcverifier.shared.domain.util.Constants.ACR_REQUESTED;
import static es.in2.vcverifier.shared.domain.util.Constants.AUDIT_CORRELATION_ID;
import static es.in2.vcverifier.shared.domain.util.Constants.AUTHORIZE_TENANT;
import static es.in2.vcverifier.shared.domain.util.Constants.EXPIRATION;
import static es.in2.vcverifier.shared.domain.util.Constants.LOGIN_METHODS;
import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.doThrow;
import static org.mockito.Mockito.lenient;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.verifyNoInteractions;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class CertificateLoginWorkflowTest {

    private final RecordingAuditTrail auditTrail = new RecordingAuditTrail();

    private static final Instant NOW = Instant.parse("2026-11-04T10:00:00Z");
    private static final String STATE = "s-1";
    private static final String TENANT = "cgcom";
    private static final String HEADER = ":MIIB:";
    private static final List<String> CHAIN = List.of(":MIIC:");
    private static final String SUBJECT = "b2f1c3";
    private static final String CORRELATION_ID = "corr-1";
    private static final CertificateIdentity IDENTITY = new CertificateIdentity(
            "JOSE ANTONIO", "GARCIA FERNANDEZ", "GARCIA FERNANDEZ JOSE ANTONIO", null, "ES", "12345678Z");

    @Mock
    private CacheStore<OAuth2AuthorizationRequest> cache;
    @Mock
    private ClientCertificateReader clientCertificateReader;
    @Mock
    private CertificateTrustValidationPort certificateTrustValidationPort;
    @Mock
    private CertificateSubjectService certificateSubjectService;
    @Mock
    private AuthorizationResponseProcessorService authorizationResponseProcessorService;
    @Mock
    private SsoLoginCompletionWorkflow ssoLoginCompletionWorkflow;
    @Mock
    private AuthenticationAuditPort authenticationAuditPort;

    @Mock
    private X509Certificate leaf;
    @Mock
    private X509Certificate issuer;
    private CertificateLoginWorkflow workflow;

    @BeforeEach
    void setUp() {
        workflow = new CertificateLoginWorkflow(cache, clientCertificateReader, certificateTrustValidationPort,
                certificateSubjectService, authorizationResponseProcessorService, ssoLoginCompletionWorkflow,
                authenticationAuditPort, auditTrail, Clock.fixed(NOW, ZoneOffset.UTC));
    }

    @Test
    void login_validCertificate_issuesTheCodeWithACertificateAuthenticationAndReturnsTheRedirect() {
        givenOpenLogin(Map.of());
        givenCertificate(new CertificateTrust.Trusted(AssuranceLevel.HIGH, List.of("hwk")), IDENTITY);
        AuthResponseResult issued = mock(AuthResponseResult.class);
        when(authorizationResponseProcessorService.issueCodeForCertificateLogin(eq(STATE), eq(TENANT), any()))
                .thenReturn(Optional.of(issued));
        when(ssoLoginCompletionWorkflow.resolveBrowserRedirect(eq(TENANT), eq(issued), any(), anyString()))
                .thenReturn("https://portal.example.com/callback?code=c&state=s-1");

        Outcome outcome = workflow.login(STATE, TENANT, HEADER, CHAIN);

        assertThat(outcome).isEqualTo(new Outcome.Completed("https://portal.example.com/callback?code=c&state=s-1"));
        verify(certificateTrustValidationPort).validate(leaf, List.of(issuer));
        ArgumentCaptor<CertificateAuthentication> authentication = ArgumentCaptor.forClass(CertificateAuthentication.class);
        verify(authorizationResponseProcessorService).issueCodeForCertificateLogin(eq(STATE), eq(TENANT), authentication.capture());
        assertThat(authentication.getValue()).isEqualTo(new CertificateAuthentication(SUBJECT, IDENTITY,
                "CN=AC FNMT Usuarios", "ab12", NOW.plusSeconds(86_400), AssuranceLevel.HIGH, List.of("hwk"), NOW));
        @SuppressWarnings("unchecked")
        ArgumentCaptor<Supplier<String>> holderSubject = ArgumentCaptor.forClass(Supplier.class);
        verify(ssoLoginCompletionWorkflow).resolveBrowserRedirect(eq(TENANT), eq(issued), holderSubject.capture(), anyString());
        assertThat(holderSubject.getValue().get()).isEqualTo(SUBJECT);
    }

    @Test
    void login_unknownState_isLoginNotFoundWithoutValidating() {
        assertThat(workflow.login(STATE, TENANT, HEADER, CHAIN)).isEqualTo(rejected(CertificateLoginReason.LOGIN_NOT_FOUND));
        verifyNoInteractions(certificateTrustValidationPort, authorizationResponseProcessorService);
    }

    @Test
    void login_loginOfAnotherTenant_isLoginNotFoundWithoutValidating() {
        givenOpenLogin(Map.of(AUTHORIZE_TENANT, "kpmg"));

        assertThat(workflow.login(STATE, TENANT, HEADER, CHAIN)).isEqualTo(rejected(CertificateLoginReason.LOGIN_NOT_FOUND));
        verifyNoInteractions(certificateTrustValidationPort);
    }

    @Test
    void login_expiredLogin_isLoginNotFound() {
        givenOpenLogin(Map.of(EXPIRATION, NOW.getEpochSecond()));

        assertThat(workflow.login(STATE, TENANT, HEADER, CHAIN)).isEqualTo(rejected(CertificateLoginReason.LOGIN_NOT_FOUND));
        verifyNoInteractions(certificateTrustValidationPort);
    }

    @Test
    void login_loginThatDoesNotOfferTheCertificate_isLoginNotFound() {
        givenOpenLogin(Map.of(LOGIN_METHODS, List.of("wallet")));

        assertThat(workflow.login(STATE, TENANT, HEADER, CHAIN)).isEqualTo(rejected(CertificateLoginReason.LOGIN_NOT_FOUND));
        verifyNoInteractions(certificateTrustValidationPort);
    }

    @Test
    void login_requestWithoutTenant_isLoginNotFound() {
        assertThat(workflow.login(STATE, null, HEADER, CHAIN)).isEqualTo(rejected(CertificateLoginReason.LOGIN_NOT_FOUND));
        verifyNoInteractions(cache, certificateTrustValidationPort);
    }

    @Test
    void login_withoutCertificateHeader_isCertificateMissing() {
        givenOpenLogin(Map.of());
        when(clientCertificateReader.readChain(null, List.of())).thenThrow(new IllegalArgumentException("empty"));

        assertThat(workflow.login(STATE, TENANT, null, List.of())).isEqualTo(rejected(CertificateLoginReason.CERTIFICATE_MISSING));
        verifyNoInteractions(certificateTrustValidationPort);
    }

    @Test
    void login_unreadableCertificateHeader_isCertificateMissing() {
        givenOpenLogin(Map.of());
        when(clientCertificateReader.readChain(HEADER, CHAIN)).thenThrow(new IllegalArgumentException("unreadable"));

        assertThat(workflow.login(STATE, TENANT, HEADER, CHAIN)).isEqualTo(rejected(CertificateLoginReason.CERTIFICATE_MISSING));
        verifyNoInteractions(certificateTrustValidationPort);
    }

    @Test
    void login_rejectedByTheTrustValidation_returnsItsReasonWithoutIssuingACode() {
        givenOpenLogin(Map.of());
        when(clientCertificateReader.readChain(HEADER, CHAIN)).thenReturn(List.of(leaf, issuer));
        when(certificateTrustValidationPort.validate(leaf, List.of(issuer)))
                .thenReturn(new CertificateTrust.Rejected(CertificateLoginReason.CERTIFICATE_REVOKED));

        assertThat(workflow.login(STATE, TENANT, HEADER, CHAIN)).isEqualTo(rejected(CertificateLoginReason.CERTIFICATE_REVOKED));
        verifyNoInteractions(authorizationResponseProcessorService);
    }

    @Test
    void login_certificateWithoutRecognisableNumber_isNotQualified() {
        givenOpenLogin(Map.of());
        givenCertificate(new CertificateTrust.Trusted(AssuranceLevel.HIGH, List.of("hwk")),
                new CertificateIdentity("JOSE ANTONIO", "GARCIA FERNANDEZ", "NAME", null, null, null));

        assertThat(workflow.login(STATE, TENANT, HEADER, CHAIN)).isEqualTo(rejected(CertificateLoginReason.CERTIFICATE_NOT_QUALIFIED));
        verifyNoInteractions(authorizationResponseProcessorService);
    }

    @Test
    void login_essentialHighLevelWithASoftwareCertificate_isLevelNotMet() {
        givenOpenLogin(Map.of(ACR_REQUESTED, AssuranceLevel.HIGH.acrValue(), ACR_ESSENTIAL, true));
        givenCertificate(new CertificateTrust.Trusted(AssuranceLevel.SUBSTANTIAL, List.of("swk")), IDENTITY);

        assertThat(workflow.login(STATE, TENANT, HEADER, CHAIN)).isEqualTo(rejected(CertificateLoginReason.LEVEL_NOT_MET));
        verifyNoInteractions(authorizationResponseProcessorService);
    }

    @Test
    void login_nonEssentialHighLevelWithASoftwareCertificate_completes() {
        givenOpenLogin(Map.of(ACR_REQUESTED, AssuranceLevel.HIGH.acrValue(), ACR_ESSENTIAL, false));
        givenCertificate(new CertificateTrust.Trusted(AssuranceLevel.SUBSTANTIAL, List.of("swk")), IDENTITY);
        AuthResponseResult issued = mock(AuthResponseResult.class);
        when(authorizationResponseProcessorService.issueCodeForCertificateLogin(eq(STATE), eq(TENANT), any()))
                .thenReturn(Optional.of(issued));
        when(ssoLoginCompletionWorkflow.resolveBrowserRedirect(eq(TENANT), eq(issued), any(), anyString()))
                .thenReturn("https://portal.example.com/callback");

        assertThat(workflow.login(STATE, TENANT, HEADER, CHAIN)).isInstanceOf(Outcome.Completed.class);
    }

    @Test
    void login_loginGoneWhenIssuingTheCode_isLoginNotFound() {
        givenOpenLogin(Map.of());
        givenCertificate(new CertificateTrust.Trusted(AssuranceLevel.HIGH, List.of("hwk")), IDENTITY);
        when(authorizationResponseProcessorService.issueCodeForCertificateLogin(eq(STATE), eq(TENANT), any()))
                .thenReturn(Optional.empty());

        assertThat(workflow.login(STATE, TENANT, HEADER, CHAIN)).isEqualTo(rejected(CertificateLoginReason.LOGIN_NOT_FOUND));
        verifyNoInteractions(ssoLoginCompletionWorkflow);
    }

    @Test
    void login_loginCompletionUnavailable_isAnInternalError() {
        givenOpenLogin(Map.of());
        givenCertificate(new CertificateTrust.Trusted(AssuranceLevel.HIGH, List.of("hwk")), IDENTITY);
        AuthResponseResult issued = mock(AuthResponseResult.class);
        when(authorizationResponseProcessorService.issueCodeForCertificateLogin(eq(STATE), eq(TENANT), any()))
                .thenReturn(Optional.of(issued));
        when(ssoLoginCompletionWorkflow.resolveBrowserRedirect(eq(TENANT), eq(issued), any(), anyString()))
                .thenThrow(new LoginCompletionUnavailableException("unavailable"));

        assertThat(workflow.login(STATE, TENANT, HEADER, CHAIN)).isEqualTo(rejected(CertificateLoginReason.INTERNAL_ERROR));
    }

    @Test
    void login_validCertificate_auditsASuccessWithTheLoginCorrelationId() {
        givenOpenLogin(Map.of());
        givenCertificate(new CertificateTrust.Trusted(AssuranceLevel.HIGH, List.of("hwk")), IDENTITY);
        AuthResponseResult issued = mock(AuthResponseResult.class);
        when(authorizationResponseProcessorService.issueCodeForCertificateLogin(eq(STATE), eq(TENANT), any()))
                .thenReturn(Optional.of(issued));
        when(ssoLoginCompletionWorkflow.resolveBrowserRedirect(eq(TENANT), eq(issued), any(), anyString()))
                .thenReturn("https://portal.example.com/callback");

        workflow.login(STATE, TENANT, HEADER, CHAIN);

        CertificateAuthenticationAudit audit = auditedCertificateAuthentication();
        assertThat(audit.result()).isEqualTo(AuditResult.SUCCESS);
        assertThat(audit.reason()).isNull();
        assertThat(audit.tenant()).isEqualTo(TENANT);
        assertThat(audit.correlationId()).isEqualTo(CORRELATION_ID);
        assertThat(audit.oidcClientId()).isEqualTo("portal");
        assertThat(audit.certificateIssuer()).isEqualTo("CN=AC FNMT Usuarios");
        assertThat(audit.certificateFingerprint()).isEqualTo("ab12");
        assertThat(audit.assuranceLevel()).isEqualTo(AssuranceLevel.HIGH);
        assertThat(audit.amr()).isEqualTo("hwk");
        assertThat(audit.holder()).isEqualTo(new AuditedPerson("12345678Z", "JOSE ANTONIO GARCIA FERNANDEZ", null));
    }

    @Test
    void login_unknownState_isNotAudited() {
        workflow.login(STATE, TENANT, HEADER, CHAIN);

        verifyNoInteractions(authenticationAuditPort);
        assertThat(auditTrail.correlationIds()).isEmpty();
    }

    @Test
    void login_openLogin_runsUnderTheLoginCorrelationId() {
        givenOpenLogin(Map.of());
        when(clientCertificateReader.readChain(null, List.of())).thenThrow(new IllegalArgumentException("empty"));

        workflow.login(STATE, TENANT, null, List.of());

        assertThat(auditTrail.correlationIds()).containsExactly(CORRELATION_ID);
    }

    @Test
    void login_loginOfAnotherTenant_isNotAudited() {
        givenOpenLogin(Map.of(AUTHORIZE_TENANT, "kpmg"));

        workflow.login(STATE, TENANT, HEADER, CHAIN);

        verifyNoInteractions(authenticationAuditPort);
    }

    @Test
    void login_withoutCertificateHeader_auditsCertificateMissingWithoutCertificateData() {
        givenOpenLogin(Map.of());
        when(clientCertificateReader.readChain(null, List.of())).thenThrow(new IllegalArgumentException("empty"));

        workflow.login(STATE, TENANT, null, List.of());

        CertificateAuthenticationAudit audit = auditedCertificateAuthentication();
        assertThat(audit.result()).isEqualTo(AuditResult.DENIED);
        assertThat(audit.reason()).isEqualTo(CertificateLoginReason.CERTIFICATE_MISSING);
        assertThat(audit.correlationId()).isEqualTo(CORRELATION_ID);
        assertThat(audit.certificateIssuer()).isNull();
        assertThat(audit.certificateFingerprint()).isNull();
        assertThat(audit.holder()).isNull();
    }

    @Test
    void login_rejectedByTheTrustValidation_auditsItsReasonWithTheCertificateButNoHolder() {
        givenOpenLogin(Map.of());
        givenCertificate(new CertificateTrust.Rejected(CertificateLoginReason.CERTIFICATE_REVOKED), IDENTITY);

        workflow.login(STATE, TENANT, HEADER, CHAIN);

        CertificateAuthenticationAudit audit = auditedCertificateAuthentication();
        assertThat(audit.result()).isEqualTo(AuditResult.DENIED);
        assertThat(audit.reason()).isEqualTo(CertificateLoginReason.CERTIFICATE_REVOKED);
        assertThat(audit.certificateIssuer()).isEqualTo("CN=AC FNMT Usuarios");
        assertThat(audit.certificateFingerprint()).isEqualTo("ab12");
        assertThat(audit.holder()).isNull();
        assertThat(audit.assuranceLevel()).isNull();
    }

    @Test
    void login_trustValidationUnavailable_auditsAFailure() {
        givenOpenLogin(Map.of());
        givenCertificate(new CertificateTrust.Rejected(CertificateLoginReason.VALIDATION_UNAVAILABLE), IDENTITY);

        workflow.login(STATE, TENANT, HEADER, CHAIN);

        CertificateAuthenticationAudit audit = auditedCertificateAuthentication();
        assertThat(audit.result()).isEqualTo(AuditResult.FAILURE);
        assertThat(audit.reason()).isEqualTo(CertificateLoginReason.VALIDATION_UNAVAILABLE);
    }

    @Test
    void login_certificateWithoutRecognisableNumber_auditsNotQualified() {
        givenOpenLogin(Map.of());
        givenCertificate(new CertificateTrust.Trusted(AssuranceLevel.HIGH, List.of("hwk")),
                new CertificateIdentity("JOSE ANTONIO", "GARCIA FERNANDEZ", "NAME", null, null, null));

        workflow.login(STATE, TENANT, HEADER, CHAIN);

        assertThat(auditedCertificateAuthentication().reason()).isEqualTo(CertificateLoginReason.CERTIFICATE_NOT_QUALIFIED);
    }

    @Test
    void login_essentialLevelNotMet_auditsLevelNotMet() {
        givenOpenLogin(Map.of(ACR_REQUESTED, AssuranceLevel.HIGH.acrValue(), ACR_ESSENTIAL, true));
        givenCertificate(new CertificateTrust.Trusted(AssuranceLevel.SUBSTANTIAL, List.of("swk")), IDENTITY);

        workflow.login(STATE, TENANT, HEADER, CHAIN);

        CertificateAuthenticationAudit audit = auditedCertificateAuthentication();
        assertThat(audit.result()).isEqualTo(AuditResult.DENIED);
        assertThat(audit.reason()).isEqualTo(CertificateLoginReason.LEVEL_NOT_MET);
    }

    @Test
    void login_loginGoneWhenIssuingTheCode_isNotAudited() {
        givenOpenLogin(Map.of());
        givenCertificate(new CertificateTrust.Trusted(AssuranceLevel.HIGH, List.of("hwk")), IDENTITY);
        when(authorizationResponseProcessorService.issueCodeForCertificateLogin(eq(STATE), eq(TENANT), any()))
                .thenReturn(Optional.empty());

        workflow.login(STATE, TENANT, HEADER, CHAIN);

        verifyNoInteractions(authenticationAuditPort);
    }

    @Test
    void login_auditFails_stillCompletes() {
        givenOpenLogin(Map.of());
        givenCertificate(new CertificateTrust.Trusted(AssuranceLevel.HIGH, List.of("hwk")), IDENTITY);
        AuthResponseResult issued = mock(AuthResponseResult.class);
        when(authorizationResponseProcessorService.issueCodeForCertificateLogin(eq(STATE), eq(TENANT), any()))
                .thenReturn(Optional.of(issued));
        when(ssoLoginCompletionWorkflow.resolveBrowserRedirect(eq(TENANT), eq(issued), any(), anyString()))
                .thenReturn("https://portal.example.com/callback");
        doThrow(new IllegalStateException("audit down")).when(authenticationAuditPort).certificateAuthentication(any());

        assertThat(workflow.login(STATE, TENANT, HEADER, CHAIN))
                .isEqualTo(new Outcome.Completed("https://portal.example.com/callback"));
    }

    @Test
    void login_auditFailsOnARejection_keepsTheReason() {
        givenOpenLogin(Map.of());
        when(clientCertificateReader.readChain(HEADER, CHAIN)).thenThrow(new IllegalArgumentException("unreadable"));
        doThrow(new IllegalStateException("audit down")).when(authenticationAuditPort).certificateAuthentication(any());

        assertThat(workflow.login(STATE, TENANT, HEADER, CHAIN)).isEqualTo(rejected(CertificateLoginReason.CERTIFICATE_MISSING));
    }

    @Test
    void login_loginWithoutCorrelationId_auditsWithAGeneratedOne() {
        givenOpenLogin(Map.of(AUDIT_CORRELATION_ID, 42));
        when(clientCertificateReader.readChain(HEADER, CHAIN)).thenThrow(new IllegalArgumentException("unreadable"));

        workflow.login(STATE, TENANT, HEADER, CHAIN);

        assertThat(auditedCertificateAuthentication().correlationId()).isNotBlank().isNotEqualTo(CORRELATION_ID);
    }

    private CertificateAuthenticationAudit auditedCertificateAuthentication() {
        ArgumentCaptor<CertificateAuthenticationAudit> audit = ArgumentCaptor.forClass(CertificateAuthenticationAudit.class);
        verify(authenticationAuditPort).certificateAuthentication(audit.capture());
        return audit.getValue();
    }

    private void givenOpenLogin(Map<String, Object> overrides) {
        Map<String, Object> parameters = new HashMap<>(Map.of(
                AUTHORIZE_TENANT, TENANT,
                EXPIRATION, NOW.plusSeconds(300).getEpochSecond(),
                LOGIN_METHODS, List.of("x509", "wallet"),
                AUDIT_CORRELATION_ID, CORRELATION_ID));
        parameters.putAll(overrides);
        when(cache.getIfPresent(STATE)).thenReturn(OAuth2AuthorizationRequest.authorizationCode()
                .authorizationUri("https://cgcom.example.com/verifier/oidc/authorize")
                .clientId("portal")
                .state(STATE)
                .additionalParameters(parameters)
                .build());
    }

    private void givenCertificate(CertificateTrust trust, CertificateIdentity identity) {
        when(clientCertificateReader.readChain(HEADER, CHAIN)).thenReturn(List.of(leaf, issuer));
        when(certificateTrustValidationPort.validate(leaf, List.of(issuer))).thenReturn(trust);
        when(clientCertificateReader.read(leaf)).thenReturn(
                new ClientCertificate(identity, "CN=AC FNMT Usuarios", "ab12", NOW.plusSeconds(86_400)));
        if (identity.personalAdministrativeNumber() != null) {
            lenient().when(certificateSubjectService.subject(TENANT, "ES", "12345678Z")).thenReturn(SUBJECT);
        }
    }

    private static Outcome rejected(CertificateLoginReason reason) {
        return new Outcome.Rejected(reason);
    }
}
