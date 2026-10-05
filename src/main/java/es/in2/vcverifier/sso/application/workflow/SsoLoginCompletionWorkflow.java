package es.in2.vcverifier.sso.application.workflow;

import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfig;
import es.in2.vcverifier.shared.domain.port.TenantSsoConfigPort;
import es.in2.vcverifier.sso.application.service.HashingService;
import es.in2.vcverifier.sso.domain.model.PendingSsoLogin;
import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
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

    private static final SecureRandom SECURE_RANDOM = new SecureRandom();

    private final CacheStore<PendingSsoLogin> cacheStoreForPendingSsoLogin;
    private final TenantSsoConfigPort tenantSsoConfigPort;
    private final HashingService hashingService;
    private final SsoAuditPort ssoAuditPort;
    private final AuthorizationResponseProcessorService authorizationResponseProcessorService;

    /**
     * Whether a verified login must be closed through the browser-bound step: the tenant has SSO
     * enabled AND the login was bound to a browser at /authorize. Otherwise the browser goes
     * straight to the RP, exactly as before (SSO-disabled tenants, logins started pre-deploy).
     */
    public boolean requiresBrowserBinding(String tenant, String browserBindingHash) {
        if (tenant == null || tenant.isBlank() || browserBindingHash == null || browserBindingHash.isBlank()) {
            return false;
        }
        return tenantSsoConfigPort.getByTenant(tenant).filter(TenantSsoConfig::ssoEnabled).isPresent();
    }

    /**
     * Parks a verified login until its browser closes it.
     *
     * @return the raw one-time handle (256-bit, base64url) — only its hash is stored; the caller
     * puts it in the close URL and must never log it
     */
    public String registerPendingLogin(PendingSsoLogin pendingLogin) {
        byte[] randomBytes = new byte[32];
        SECURE_RANDOM.nextBytes(randomBytes);
        String handle = Base64.getUrlEncoder().withoutPadding().encodeToString(randomBytes);
        cacheStoreForPendingSsoLogin.add(hashingService.sha256(handle), pendingLogin);
        return handle;
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
                .holderHash(hashingService.sha256(pending.holderSubject()))
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
