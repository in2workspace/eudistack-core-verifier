package es.in2.vcverifier.sso.application.workflow;

import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.service.HashingService;
import es.in2.vcverifier.sso.domain.exception.LoginCompletionUnavailableException;
import es.in2.vcverifier.sso.domain.model.PendingSsoLogin;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.verifier.domain.model.AuthResponseResult;
import es.in2.vcverifier.verifier.domain.service.AuthorizationResponseProcessorService;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.ArgumentCaptor;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import java.time.Duration;
import java.util.List;
import java.util.Optional;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.awaitility.Awaitility.await;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ExtendWith(MockitoExtension.class)
class SsoLoginCompletionWorkflowTest {

    private static final String TENANT = "tenant-a";
    private static final String BINDING_VALUE = "browser-binding-value";
    private static final String CODE = "issued-code";

    @Mock private TenantSsoConfigPort tenantSsoConfigPort;
    @Mock private SsoAuditPort ssoAuditPort;
    @Mock private AuthorizationResponseProcessorService authorizationResponseProcessorService;

    private final HashingService hashingService = new HashingService();
    private CacheStore<PendingSsoLogin> cache;
    private SsoLoginCompletionWorkflow workflow;

    @BeforeEach
    void setUp() {
        cache = new CacheStore<>(60, TimeUnit.SECONDS);
        workflow = new SsoLoginCompletionWorkflow(cache, tenantSsoConfigPort, hashingService, ssoAuditPort,
                authorizationResponseProcessorService);
    }

    // ---- resolveBrowserRedirect (wallet POST → where the browser goes over SSE) ----

    private static final String RP_URL = "https://rp.example.com/cb?code=" + CODE + "&state=st";
    private static final String BASE_URL = "https://tenant-a.example.com/verifier";

    @Test
    void resolveBrowserRedirect_unboundLogin_returnsRpUrlDirectly() {
        // Given: SSO-disabled tenant at /authorize → no binding hash (EC-07)
        // When
        String url = workflow.resolveBrowserRedirect(TENANT, result(null, BASE_URL), () -> "holder-sub", "corr");

        // Then
        assertThat(url).isEqualTo(RP_URL);
        verify(authorizationResponseProcessorService, never()).revokeAuthorizationCode(any());
    }

    @Test
    void resolveBrowserRedirect_boundSsoLogin_parksEligibleLoginAndReturnsCloseUrl() {
        // Given
        when(tenantSsoConfigPort.getByTenant(TENANT)).thenReturn(Optional.of(config(true)));

        // When
        String url = workflow.resolveBrowserRedirect(TENANT, result("bind-hash", BASE_URL), () -> "holder-sub", "corr");

        // Then
        assertThat(url).startsWith(BASE_URL + "/api/login/complete?h=").doesNotContain("code=");
        PendingSsoLogin parked = cache.getIfPresent(hashingService.sha256(handleOf(url)));
        assertThat(parked.ssoEligible()).isTrue();
        assertThat(parked.holderSubject()).isEqualTo("holder-sub");
        verify(ssoAuditPort, never()).publish(any());
    }

    @Test
    void resolveBrowserRedirect_boundLoginNoUsableSubject_parksIneligibleLoginAndAudits() {
        // Given
        when(tenantSsoConfigPort.getByTenant(TENANT)).thenReturn(Optional.of(config(true)));

        // When
        String url = workflow.resolveBrowserRedirect(TENANT, result("bind-hash", BASE_URL),
                () -> { throw new IllegalStateException("no sub"); }, "corr");

        // Then: still the close URL — the code never goes over SSE for a bound login
        assertThat(url).startsWith(BASE_URL + "/api/login/complete?h=");
        assertThat(cache.getIfPresent(hashingService.sha256(handleOf(url))).ssoEligible()).isFalse();
        assertAudited(SsoLoginCompletionWorkflow.REASON_NO_USABLE_SUBJECT);
    }

    @Test
    void resolveBrowserRedirect_boundLoginConfigUnreadable_parksIneligibleLoginAndAudits() {
        // Given
        when(tenantSsoConfigPort.getByTenant(TENANT)).thenThrow(new IllegalStateException("config store down"));

        // When
        String url = workflow.resolveBrowserRedirect(TENANT, result("bind-hash", BASE_URL), () -> "holder-sub", "corr");

        // Then
        assertThat(url).startsWith(BASE_URL + "/api/login/complete?h=");
        assertThat(cache.getIfPresent(hashingService.sha256(handleOf(url))).ssoEligible()).isFalse();
        assertAudited(SsoLoginCompletionWorkflow.REASON_SSO_CONFIG_UNAVAILABLE);
    }

    @Test
    void resolveBrowserRedirect_boundLoginSsoDisabledMeanwhile_parksIneligibleLoginWithoutAudit() {
        // Given: SSO switched off between /authorize and the wallet POST
        when(tenantSsoConfigPort.getByTenant(TENANT)).thenReturn(Optional.of(config(false)));

        // When
        String url = workflow.resolveBrowserRedirect(TENANT, result("bind-hash", BASE_URL), () -> "holder-sub", "corr");

        // Then
        assertThat(cache.getIfPresent(hashingService.sha256(handleOf(url))).ssoEligible()).isFalse();
        verify(ssoAuditPort, never()).publish(any());
    }

    @Test
    void resolveBrowserRedirect_boundLoginWithoutBaseUrl_failsClosed() {
        // When / Then
        assertThatThrownBy(() -> workflow.resolveBrowserRedirect(TENANT, result("bind-hash", null),
                () -> "holder-sub", "corr")).isInstanceOf(LoginCompletionUnavailableException.class);
        verify(authorizationResponseProcessorService).revokeAuthorizationCode(CODE);
        assertAudited(SsoLoginCompletionWorkflow.REASON_LOGIN_COMPLETION_UNAVAILABLE);
    }

    @Test
    void resolveBrowserRedirect_boundLoginRegistrationFails_failsClosed() {
        // Given: a store that can't hold the pending login
        HashingService brokenHashing = org.mockito.Mockito.mock(HashingService.class);
        when(tenantSsoConfigPort.getByTenant(TENANT)).thenReturn(Optional.of(config(true)));
        SsoLoginCompletionWorkflow brokenWorkflow = new SsoLoginCompletionWorkflow(cache, tenantSsoConfigPort,
                brokenHashing, ssoAuditPort, authorizationResponseProcessorService);

        // When / Then (null hash key → CacheStore refuses the entry)
        assertThatThrownBy(() -> brokenWorkflow.resolveBrowserRedirect(TENANT, result("bind-hash", BASE_URL),
                () -> "holder-sub", "corr")).isInstanceOf(LoginCompletionUnavailableException.class);
        verify(authorizationResponseProcessorService).revokeAuthorizationCode(CODE);
    }

    @Test
    void complete_ineligibleLoginWithMatchingBinding_completesWithoutSsoFlag() {
        // Given
        String handle = workflow.registerPendingLogin(new PendingSsoLogin(TENANT, null, "client-a", null, RP_URL,
                "https://rp.example.com/cb", "st", hashingService.sha256(BINDING_VALUE), CODE, false));

        // When
        var outcome = workflow.complete(handle, BINDING_VALUE, TENANT);

        // Then: binding still enforced; caller skips the session
        assertThat(((SsoLoginCompletionWorkflow.Outcome.Completed) outcome).login().ssoEligible()).isFalse();
    }

    @Test
    void complete_ineligibleLoginWithWrongBinding_rejectsWithoutHolderHash() {
        // Given
        String handle = workflow.registerPendingLogin(new PendingSsoLogin(TENANT, null, "client-a", null, RP_URL,
                "https://rp.example.com/cb", "st", hashingService.sha256(BINDING_VALUE), CODE, false));

        // When
        var outcome = workflow.complete(handle, "attacker-browser-value", TENANT);

        // Then
        assertThat(outcome).isInstanceOf(SsoLoginCompletionWorkflow.Outcome.Rejected.class);
        verify(authorizationResponseProcessorService).revokeAuthorizationCode(CODE);
    }

    private void assertAudited(String reason) {
        ArgumentCaptor<SsoAuditEvent> event = ArgumentCaptor.forClass(SsoAuditEvent.class);
        verify(ssoAuditPort).publish(event.capture());
        assertThat(event.getValue().getEventType()).isEqualTo(SsoAuditEvent.EventType.SSO_ESTABLISH_FAILED);
        assertThat(event.getValue().getReason()).isEqualTo(reason);
    }

    private static String handleOf(String closeUrl) {
        return closeUrl.substring(closeUrl.indexOf("?h=") + 3);
    }

    private static AuthResponseResult result(String bindingHash, String baseUrl) {
        return new AuthResponseResult(null, RP_URL, "https://rp.example.com/cb", "st", "client-a", CODE,
                bindingHash, baseUrl);
    }

    @Test
    void registerPendingLogin_storesUnderHashOfHandleOnly() {
        // When
        String handle = workflow.registerPendingLogin(pending());

        // Then: 256-bit base64url handle; the raw handle is not a cache key
        assertThat(handle).matches("^[A-Za-z0-9_-]{43}$");
        assertThat(cache.getIfPresent(handle)).isNull();
        assertThat(cache.getIfPresent(hashingService.sha256(handle))).isNotNull();
    }

    @Test
    void complete_matchingBinding_returnsCompletedAndConsumesHandle() {
        // Given
        String handle = workflow.registerPendingLogin(pending());

        // When
        var outcome = workflow.complete(handle, BINDING_VALUE, TENANT);

        // Then
        assertThat(outcome).isInstanceOf(SsoLoginCompletionWorkflow.Outcome.Completed.class);
        assertThat(((SsoLoginCompletionWorkflow.Outcome.Completed) outcome).login().redirectUrl())
                .isEqualTo("https://rp.example.com/cb?code=" + CODE + "&state=st");
        verify(authorizationResponseProcessorService, never()).revokeAuthorizationCode(any());
        verify(ssoAuditPort, never()).publish(any());
    }

    @Test
    void complete_secondUseOfSameHandle_isUnknown() {
        // Given
        String handle = workflow.registerPendingLogin(pending());
        workflow.complete(handle, BINDING_VALUE, TENANT);

        // When
        var outcome = workflow.complete(handle, BINDING_VALUE, TENANT);

        // Then
        assertThat(outcome).isInstanceOf(SsoLoginCompletionWorkflow.Outcome.Unknown.class);
    }

    @Test
    void complete_unknownOrBlankHandle_isUnknown() {
        assertThat(workflow.complete("never-issued", BINDING_VALUE, TENANT))
                .isInstanceOf(SsoLoginCompletionWorkflow.Outcome.Unknown.class);
        assertThat(workflow.complete(null, BINDING_VALUE, TENANT))
                .isInstanceOf(SsoLoginCompletionWorkflow.Outcome.Unknown.class);
    }

    @Test
    void complete_expiredHandle_isUnknown() {
        // Given: a store whose entries expire almost immediately
        CacheStore<PendingSsoLogin> shortLived = new CacheStore<>(1, TimeUnit.MILLISECONDS);
        SsoLoginCompletionWorkflow shortWorkflow = new SsoLoginCompletionWorkflow(shortLived, tenantSsoConfigPort,
                hashingService, ssoAuditPort, authorizationResponseProcessorService);
        String handle = shortWorkflow.registerPendingLogin(pending());
        await().atMost(Duration.ofSeconds(2))
                .until(() -> shortLived.getIfPresent(hashingService.sha256(handle)) == null);

        // When / Then
        assertThat(shortWorkflow.complete(handle, BINDING_VALUE, TENANT))
                .isInstanceOf(SsoLoginCompletionWorkflow.Outcome.Unknown.class);
    }

    @Test
    void complete_missingBindingCookie_rejectsRevokesCodeAndAudits() {
        // Given
        String handle = workflow.registerPendingLogin(pending());

        // When
        var outcome = workflow.complete(handle, null, TENANT);

        // Then
        assertRejected(outcome, SsoLoginCompletionWorkflow.REASON_BINDING_MISSING);
    }

    @Test
    void complete_wrongBindingCookie_rejectsRevokesCodeAndAudits() {
        // Given
        String handle = workflow.registerPendingLogin(pending());

        // When
        var outcome = workflow.complete(handle, "attacker-browser-value", TENANT);

        // Then
        assertRejected(outcome, SsoLoginCompletionWorkflow.REASON_BINDING_MISMATCH);
    }

    @Test
    void complete_tenantMismatch_rejects() {
        // Given
        String handle = workflow.registerPendingLogin(pending());

        // When
        var outcome = workflow.complete(handle, BINDING_VALUE, "tenant-b");

        // Then
        assertRejected(outcome, SsoLoginCompletionWorkflow.REASON_TENANT_MISMATCH);
    }

    @Test
    void complete_rejected_handleIsConsumed() {
        // Given: a hijack attempt burns the handle — the legitimate browser can't retry it either
        String handle = workflow.registerPendingLogin(pending());
        workflow.complete(handle, "attacker-browser-value", TENANT);

        // When / Then
        assertThat(workflow.complete(handle, BINDING_VALUE, TENANT))
                .isInstanceOf(SsoLoginCompletionWorkflow.Outcome.Unknown.class);
    }

    private void assertRejected(SsoLoginCompletionWorkflow.Outcome outcome, String expectedReason) {
        assertThat(outcome).isInstanceOf(SsoLoginCompletionWorkflow.Outcome.Rejected.class);
        assertThat(((SsoLoginCompletionWorkflow.Outcome.Rejected) outcome).errorRedirectUrl())
                .isEqualTo("https://rp.example.com/cb?error=access_denied&state=st");
        verify(authorizationResponseProcessorService).revokeAuthorizationCode(CODE);
        ArgumentCaptor<SsoAuditEvent> event = ArgumentCaptor.forClass(SsoAuditEvent.class);
        verify(ssoAuditPort).publish(event.capture());
        assertThat(event.getValue().getEventType()).isEqualTo(SsoAuditEvent.EventType.SSO_ESTABLISH_FAILED);
        assertThat(event.getValue().getOutcome()).isEqualTo(SsoLoginCompletionWorkflow.OUTCOME_BINDING_REJECTED);
        assertThat(event.getValue().getReason()).isEqualTo(expectedReason);
        assertThat(event.getValue().getHolderHash()).isEqualTo(hashingService.sha256("holder-sub"));
    }

    private PendingSsoLogin pending() {
        return new PendingSsoLogin(TENANT, "holder-sub", "client-a", null,
                "https://rp.example.com/cb?code=" + CODE + "&state=st", "https://rp.example.com/cb", "st",
                hashingService.sha256(BINDING_VALUE), CODE, true);
    }

    private static TenantSsoConfig config(boolean ssoEnabled) {
        return new TenantSsoConfig(TENANT, "example.com", ssoEnabled,
                new TenantSsoConfig.SsoTtlConfig(Duration.ofHours(1), Duration.ofMinutes(10)), List.of());
    }
}
