package es.in2.vcverifier.sso.infrastructure.controller;

import es.in2.vcverifier.shared.config.TenantDomainFilter;
import es.in2.vcverifier.sso.application.workflow.SsoLoginCompletionWorkflow;
import es.in2.vcverifier.sso.domain.model.PendingSsoLogin;
import es.in2.vcverifier.sso.infrastructure.web.SsoBrowserBindingCookie;
import es.in2.vcverifier.sso.infrastructure.web.SsoSessionAuthenticationSuccessHandler;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpHeaders;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;

import java.io.IOException;
import java.util.HashMap;
import java.util.Map;

/**
 * EUD-252: browser-side close of a cross-device login. The browser that started the login follows
 * the one-time URL it received over SSE; if it carries the matching {@code __Host-sso-tx} cookie,
 * the SSO session is established HERE — so the {@code __Secure-sso-<tenant>} cookie lands in that
 * browser, not in the wallet's — and it is redirected to the RP with the authorization code.
 */
@Slf4j
@RestController
@RequestMapping("/api/login")
@RequiredArgsConstructor
@Tag(name = "Login", description = "SSE-based login events")
public class SsoLoginCompletionController {

    private final SsoLoginCompletionWorkflow ssoLoginCompletionWorkflow;
    private final SsoBrowserBindingCookie ssoBrowserBindingCookie;
    private final SsoSessionAuthenticationSuccessHandler ssoSessionHandler;

    @Operation(
            summary = "Complete a cross-device SSO login in the browser that started it",
            description = "One-time URL delivered over the login SSE stream. Verifies the browser-binding "
                    + "cookie set at /authorize, establishes the SSO session and redirects to the RP.")
    @ApiResponse(responseCode = "302", description = "Redirect to the RP: code on success, error=access_denied otherwise")
    @ApiResponse(responseCode = "400", description = "Unknown, expired or already used handle")
    @GetMapping("/complete")
    public void complete(
            @Parameter(description = "One-time login completion handle", required = true)
            @RequestParam(name = "h", required = false) String handle,
            HttpServletRequest request,
            HttpServletResponse response) throws IOException {

        // Single-use URL carrying (on success) an authorization code in its redirect: never cache.
        response.setHeader(HttpHeaders.CACHE_CONTROL, "no-store");

        String browserBindingValue = ssoBrowserBindingCookie.readValue(request).orElse(null);
        String tenant = TenantDomainFilter.getCurrentTenant(request);

        switch (ssoLoginCompletionWorkflow.complete(handle, browserBindingValue, tenant)) {
            case SsoLoginCompletionWorkflow.Outcome.Completed completed -> {
                if (completed.login().ssoEligible()) {
                    establishSsoSession(request, response, completed.login());
                }
                response.sendRedirect(completed.login().redirectUrl());
            }
            case SsoLoginCompletionWorkflow.Outcome.Rejected rejected ->
                    response.sendRedirect(rejected.errorRedirectUrl());
            case SsoLoginCompletionWorkflow.Outcome.Unknown unknown -> {
                log.info("event=sso_login_completion_unknown_handle tenant={}", tenant);
                response.setStatus(HttpServletResponse.SC_BAD_REQUEST);
            }
        }
    }

    /**
     * Fail-open, as on the pre-EUD-252 path: the VP is verified and the code issued, so an SSO
     * establishment failure (already audited by the handler) must not block the login itself.
     */
    private void establishSsoSession(HttpServletRequest request, HttpServletResponse response,
                                     PendingSsoLogin login) {
        try {
            ssoSessionHandler.onAuthenticationSuccess(request, response, buildSsoAuthentication(login));
        } catch (Exception e) {
            log.warn("event=sso_establish_skipped tenant={} reason={}", login.tenant(), e.getClass().getSimpleName());
        }
    }

    private Authentication buildSsoAuthentication(PendingSsoLogin login) {
        Map<String, Object> principal = new HashMap<>();
        principal.put("tenant", login.tenant());
        principal.put("holderHash", login.holderSubject()); // raw sub — workflow applies SHA-256(sub)
        principal.put("clientId", login.tenant());          // fallback: tenant as clientId for audit (unchanged)
        principal.put("tenantSlug", login.tenant());
        // Snapshot for SSO reuse (prompt=none, no VP re-presentation) — see ReuseSsoSessionWorkflowImpl.
        principal.put("credentialJson", login.credentialJson());
        return new UsernamePasswordAuthenticationToken(principal, null);
    }
}
