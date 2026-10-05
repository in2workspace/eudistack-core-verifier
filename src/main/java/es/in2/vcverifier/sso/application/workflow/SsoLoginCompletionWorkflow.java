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
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.net.URLEncoder;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.Base64;
import java.util.UUID;
import java.util.function.Supplier;

import static es.in2.vcverifier.shared.domain.util.Constants.LOGIN_COMPLETION_PATH;

/**
 * EUD-252: closes a cross-device SSO login in the browser that started it.
 *
 * <p>The wallet's POST (another device) verifies the VP and issues the code, but must not receive
 * the SSO cookie. Instead the login is parked here under a one-time handle and the browser —
 * notified over SSE — calls the close endpoint with that handle plus its {@code __Host-sso-tx}
 * browser-binding cookie. Only a matching browser gets the SSO session and the code; anyone else
 * who learnt the public {@code state} gets {@code access_denied} and the code is invalidated.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class SsoLoginCompletionWorkflow {

    static final String OUTCOME_BINDING_REJECTED = "BINDING_REJECTED";
    static final String REASON_BINDING_MISSING = "browser_binding_missing";
    static final String REASON_BINDING_MISMATCH = "browser_binding_mismatch";
    static final String REASON_TENANT_MISMATCH = "tenant_mismatch";
    static final String REASON_NO_USABLE_SUBJECT = "no_usable_subject";
    static final String REASON_SSO_CONFIG_UNAVAILABLE = "sso_config_unavailable";
    static final String REASON_LOGIN_COMPLETION_UNAVAILABLE = "login_completion_unavailable";

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final CacheStore<PendingSsoLogin> cacheStoreForPendingSsoLogin;
    private final TenantSsoConfigPort tenantSsoConfigPort;
    private final HashingService hashingService;
    private final SsoAuditPort ssoAuditPort;
    private final AuthorizationResponseProcessorService authorizationResponseProcessorService;

    /**
     * Where the browser that started this verified login must go next (sent to it over SSE).
     *
     * <ul>
     *   <li>Unbound login (SSO-disabled tenant at /authorize): straight to the RP, as before EUD-252.</li>
     *   <li>Bound login: ALWAYS the one-time close URL, so the code only ever reaches the browser that
     *       proves the binding. If the SSO session can't be prepared (tenant config unreadable, SSO
     *       turned off meanwhile, no usable subject) the login is still parked, flagged not SSO-eligible:
     *       the close step checks the binding and redirects with the code, without an SSO session.</li>
     *   <li>Bound login whose close step can't be offered (no base URL, parking fails): fail CLOSED —
     *       the code is revoked and {@link LoginCompletionUnavailableException} is thrown. A bound
     *       login never falls back to sending {@code redirect_uri?code=...} over the public SSE channel.</li>
     * </ul>
     *
     * @param holderSubject supplies the RAW credential subject; may throw {@link IllegalStateException}
     *                      when the VP has no usable subject
     */
    public String resolveBrowserRedirect(String tenant, AuthResponseResult result, Supplier<String> holderSubject,
                                         String correlationId) {
        String bindingHash = result.browserBindingHash();
        if (bindingHash == null || bindingHash.isBlank()) {
            return result.redirectUrl();
        }
        String baseUrl = result.authorizationServerBaseUrl();
        if (baseUrl == null || baseUrl.isBlank()) {
            throw failClosed(tenant, result, correlationId);
        }

        String subject = null;
        String ineligibleReason = null;
        Boolean ssoEnabled = readSsoEnabled(tenant);
        if (ssoEnabled == null) {
            ineligibleReason = REASON_SSO_CONFIG_UNAVAILABLE;
        } else if (ssoEnabled) {
            try {
                subject = holderSubject.get();
            } catch (IllegalStateException e) {
                // B5: no usable subject → no SSO session (avoids a SHA-256("") collision)
                ineligibleReason = REASON_NO_USABLE_SUBJECT;
            }
        }
        boolean ssoEligible = subject != null;
        if (ineligibleReason != null) {
            log.warn("event=sso_establish_skipped tenant={} reason={}", tenant, ineligibleReason);
            ssoAuditPort.publish(SsoAuditEvent.builder()
                    .eventType(SsoAuditEvent.EventType.SSO_ESTABLISH_FAILED)
                    .tenant(tenant)
                    .clientId(result.clientId())
                    .outcome("FAILURE")
                    .correlationId(correlationId)
                    .occurredAt(Instant.now())
                    .reason(ineligibleReason)
                    .build());
        }

        String handle;
        try {
            handle = registerPendingLogin(new PendingSsoLogin(
                    tenant, subject, result.clientId(), result.credentialJson(), result.redirectUrl(),
                    result.redirectUri(), result.state(), bindingHash, result.authorizationCode(), ssoEligible));
        } catch (RuntimeException e) {
            log.error("event=login_completion_register_failed tenant={} error={}", tenant, e.getClass().getSimpleName());
            throw failClosed(tenant, result, correlationId);
        }
        return baseUrl + LOGIN_COMPLETION_PATH + "?h=" + handle;
    }

    /**
     * Parks a verified login until its browser closes it.
     *
     * @return the raw one-time handle (256-bit, base64url) — only its hash is stored; the caller
     * puts it in the close URL and must never log it
     * @throws IllegalStateException if the login could not be stored
     */
    String registerPendingLogin(PendingSsoLogin pendingLogin) {
        byte[] randomBytes = new byte[32];
        SECURE_RANDOM.nextBytes(randomBytes);
        String handle = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        if (cacheStoreForPendingSsoLogin.add(hashingService.sha256(handle), pendingLogin) == null) {
            throw new IllegalStateException("Pending login could not be stored");
        }
        return handle;
    }

    /** Whether the tenant has SSO enabled; {@code null} when its configuration can't be read. */
    private Boolean readSsoEnabled(String tenant) {
        if (tenant == null || tenant.isBlank()) {
            return false;
        }
        try {
            return tenantSsoConfigPort.getByTenant(tenant).filter(TenantSsoConfig::ssoEnabled).isPresent();
        } catch (RuntimeException e) {
            return null;
        }
    }

    private LoginCompletionUnavailableException failClosed(String tenant, AuthResponseResult result,
                                                            String correlationId) {
        try {
            authorizationResponseProcessorService.revokeAuthorizationCode(result.authorizationCode());
        } catch (RuntimeException e) {
            log.error("event=login_completion_revoke_failed tenant={} error={}", tenant, e.getClass().getSimpleName());
        }
        log.error("event=login_completion_unavailable tenant={} clientId={}", tenant, result.clientId());
        ssoAuditPort.publish(SsoAuditEvent.builder()
                .eventType(SsoAuditEvent.EventType.SSO_ESTABLISH_FAILED)
                .tenant(tenant)
                .clientId(result.clientId())
                .outcome("FAILURE")
                .correlationId(correlationId)
                .occurredAt(Instant.now())
                .reason(REASON_LOGIN_COMPLETION_UNAVAILABLE)
                .build());
        return new LoginCompletionUnavailableException("Browser-bound login cannot be completed");
    }

    /**
     * Consumes (single use) the pending login behind {@code handle} and checks the browser binding.
     *
     * @param handle               one-time handle from the close URL
     * @param browserBindingValue  value of the request's {@code __Host-sso-tx} cookie, or {@code null}
     * @param requestTenant        tenant resolved on the close request
     */
    public Outcome complete(String handle, String browserBindingValue, String requestTenant) {
        if (handle == null || handle.isBlank()) {
            return new Outcome.Unknown();
        }
        PendingSsoLogin pending = cacheStoreForPendingSsoLogin.remove(hashingService.sha256(handle));
        if (pending == null) {
            return new Outcome.Unknown();
        }

        String rejectionReason = checkBinding(pending, browserBindingValue, requestTenant);
        if (rejectionReason != null) {
            return reject(pending, rejectionReason);
        }
        log.info("event=sso_login_completed tenant={} clientId={}", pending.tenant(), pending.clientId());
        return new Outcome.Completed(pending);
    }

    private String checkBinding(PendingSsoLogin pending, String browserBindingValue, String requestTenant) {
        if (requestTenant == null || !requestTenant.equals(pending.tenant())) {
            return REASON_TENANT_MISMATCH;
        }
        if (browserBindingValue == null || browserBindingValue.isBlank()) {
            return REASON_BINDING_MISSING;
        }
        byte[] presented = hashingService.sha256(browserBindingValue).getBytes(StandardCharsets.UTF_8);
        byte[] expected = pending.browserBindingHash().getBytes(StandardCharsets.UTF_8);
        return MessageDigest.isEqual(presented, expected) ? null : REASON_BINDING_MISMATCH;
    }

    private Outcome reject(PendingSsoLogin pending, String reason) {
        authorizationResponseProcessorService.revokeAuthorizationCode(pending.authorizationCode());
        log.warn("event=sso_login_completion_rejected tenant={} clientId={} reason={}",
                pending.tenant(), pending.clientId(), reason);
        ssoAuditPort.publish(SsoAuditEvent.builder()
                .eventType(SsoAuditEvent.EventType.SSO_ESTABLISH_FAILED)
                .tenant(pending.tenant())
                .clientId(pending.clientId())
                .holderHash(pending.holderSubject() != null ? hashingService.sha256(pending.holderSubject()) : null)
                .outcome(OUTCOME_BINDING_REJECTED)
                .correlationId(UUID.randomUUID().toString())
                .occurredAt(Instant.now())
                .reason(reason)
                .build());
        return new Outcome.Rejected(accessDeniedRedirect(pending));
    }

    /** RFC 6749 §4.1.2.1 error response to the client's registered redirect_uri — no open redirect. */
    private String accessDeniedRedirect(PendingSsoLogin pending) {
        String redirectUri = pending.redirectUri();
        String separator = redirectUri.contains("?") ? "&" : "?";
        String location = redirectUri + separator + "error=access_denied";
        if (pending.state() != null && !pending.state().isBlank()) {
            location += "&state=" + URLEncoder.encode(pending.state(), StandardCharsets.UTF_8);
        }
        return location;
    }

    /** Result of {@link #complete}. */
    public sealed interface Outcome {

        /** Binding verified: establish the SSO session for {@code login} and redirect to its RP URL. */
        record Completed(PendingSsoLogin login) implements Outcome {
        }

        /** Binding failed: the code was invalidated; redirect the browser to this error URL. */
        record Rejected(String errorRedirectUrl) implements Outcome {
        }

        /** Unknown, expired or already used handle. */
        record Unknown() implements Outcome {
        }
    }
}
