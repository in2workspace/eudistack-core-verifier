package es.in2.vcverifier.verifier.application.workflow;

import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.shared.crypto.CertificateSubjectService;
import es.in2.vcverifier.shared.crypto.ClientCertificateReader;
import es.in2.vcverifier.shared.domain.model.AssuranceLevel;
import es.in2.vcverifier.shared.domain.model.CertificateAuthentication;
import es.in2.vcverifier.shared.domain.model.CertificateIdentity;
import es.in2.vcverifier.shared.domain.model.ClientCertificate;
import es.in2.vcverifier.shared.domain.model.LoginMethod;
import es.in2.vcverifier.sso.application.workflow.SsoLoginCompletionWorkflow;
import es.in2.vcverifier.sso.domain.exception.LoginCompletionUnavailableException;
import es.in2.vcverifier.verifier.domain.model.AuthResponseResult;
import es.in2.vcverifier.verifier.domain.model.CertificateLoginReason;
import es.in2.vcverifier.verifier.domain.model.CertificateTrust;
import es.in2.vcverifier.verifier.domain.model.audit.AuditedPerson;
import es.in2.vcverifier.verifier.domain.model.audit.CertificateAuthenticationAudit;
import es.in2.vcverifier.verifier.domain.port.AuthenticationAuditPort;
import es.in2.vcverifier.verifier.domain.port.CertificateTrustValidationPort;
import es.in2.vcverifier.verifier.domain.service.AuthorizationResponseProcessorService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.security.oauth2.core.endpoint.OAuth2AuthorizationRequest;
import org.springframework.stereotype.Service;

import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Optional;
import java.util.UUID;
import java.util.function.Supplier;

import static es.in2.vcverifier.shared.domain.util.Constants.ACR_ESSENTIAL;
import static es.in2.vcverifier.shared.domain.util.Constants.ACR_REQUESTED;
import static es.in2.vcverifier.shared.domain.util.Constants.AUDIT_CORRELATION_ID;
import static es.in2.vcverifier.shared.domain.util.Constants.AUTHORIZE_TENANT;
import static es.in2.vcverifier.shared.domain.util.Constants.EXPIRATION;
import static es.in2.vcverifier.shared.domain.util.Constants.LOGIN_METHODS;
import static es.in2.vcverifier.shared.domain.util.LogSanitizer.sanitize;

@Slf4j
@Service
@RequiredArgsConstructor
public class CertificateLoginWorkflow {

    private final CacheStore<OAuth2AuthorizationRequest> cacheStoreForOAuth2AuthorizationRequest;
    private final ClientCertificateReader clientCertificateReader;
    private final CertificateTrustValidationPort certificateTrustValidationPort;
    private final CertificateSubjectService certificateSubjectService;
    private final AuthorizationResponseProcessorService authorizationResponseProcessorService;
    private final SsoLoginCompletionWorkflow ssoLoginCompletionWorkflow;
    private final AuthenticationAuditPort authenticationAuditPort;
    private final Clock clock;

    public sealed interface Outcome {

        record Completed(String redirectUri) implements Outcome {
        }

        record Rejected(CertificateLoginReason reason) implements Outcome {
        }
    }

    public Outcome login(String state, String tenant, String clientCert, List<String> clientCertChain) {
        Optional<OAuth2AuthorizationRequest> login = openCertificateLogin(state, tenant);
        if (login.isEmpty()) {
            return rejected(CertificateLoginReason.LOGIN_NOT_FOUND);
        }
        String clientId = login.get().getClientId();
        String correlationId = correlationId(login.get());
        List<X509Certificate> chain;
        try {
            chain = clientCertificateReader.readChain(clientCert, clientCertChain);
        } catch (IllegalArgumentException e) {
            log.warn("event=certificate_login_unreadable_certificate clientId={} reason=\"{}\" certificateLength={} "
                            + "chainHeaders={} chainLength={}",
                    sanitize(login.get().getClientId()), e.getMessage(),
                    clientCert == null ? 0 : clientCert.length(),
                    clientCertChain.size(), clientCertChain.stream().mapToInt(String::length).sum());
            return audited(tenant, correlationId, clientId, CertificateLoginReason.CERTIFICATE_MISSING, null);
        }

        ClientCertificate certificate = clientCertificateReader.read(chain.getFirst());
        CertificateTrust trust = certificateTrustValidationPort.validate(chain.getFirst(), chain.subList(1, chain.size()));
        if (!(trust instanceof CertificateTrust.Trusted(AssuranceLevel level, List<String> amr))) {
            return audited(tenant, correlationId, clientId, ((CertificateTrust.Rejected) trust).reason(), certificate);
        }

        CertificateIdentity identity = certificate.identity();
        if (identity.personalAdministrativeNumber() == null) {
            log.warn("event=certificate_login_without_number clientId={}", sanitize(clientId));
            return audited(tenant, correlationId, clientId, CertificateLoginReason.CERTIFICATE_NOT_QUALIFIED, certificate);
        }
        if (!meetsEssentialLevel(login.get(), level)) {
            return audited(tenant, correlationId, clientId, CertificateLoginReason.LEVEL_NOT_MET, certificate);
        }

        String subject = certificateSubjectService.subject(tenant, identity.country(), identity.personalAdministrativeNumber());
        CertificateAuthentication authentication = new CertificateAuthentication(subject, identity,
                certificate.issuer(), certificate.fingerprintSha256(), certificate.notAfter(),
                level, amr, clock.instant());

        Optional<AuthResponseResult> issued =
                authorizationResponseProcessorService.issueCodeForCertificateLogin(state, tenant, authentication);
        if (issued.isEmpty()) {
            return rejected(CertificateLoginReason.LOGIN_NOT_FOUND);
        }
        audit(clientId, () -> CertificateAuthenticationAudit.success(tenant, correlationId, clientId, certificate,
                level, amr.isEmpty() ? null : amr.getFirst(), AuditedPerson.of(identity)));
        try {
            String redirectUri = ssoLoginCompletionWorkflow.resolveBrowserRedirect(
                    tenant, issued.get(), () -> subject, UUID.randomUUID().toString());
            log.info("event=certificate_login_completed clientId={} level={}",
                    sanitize(issued.get().clientId()), level.name());
            return new Outcome.Completed(redirectUri);
        } catch (LoginCompletionUnavailableException _) {
            log.warn("event=certificate_login_completion_failed clientId={}", sanitize(issued.get().clientId()));
            return rejected(CertificateLoginReason.INTERNAL_ERROR);
        }
    }

    private Optional<OAuth2AuthorizationRequest> openCertificateLogin(String state, String tenant) {
        if (state == null || state.isBlank() || tenant == null) {
            return Optional.empty();
        }
        OAuth2AuthorizationRequest login = cacheStoreForOAuth2AuthorizationRequest.getIfPresent(state);
        if (login == null) {
            return Optional.empty();
        }
        Map<String, Object> parameters = login.getAdditionalParameters();
        boolean open = Objects.equals(parameters.get(AUTHORIZE_TENANT), tenant)
                && parameters.get(EXPIRATION) instanceof Number expiration
                && clock.instant().getEpochSecond() < expiration.longValue()
                && parameters.get(LOGIN_METHODS) instanceof List<?> methods
                && methods.contains(LoginMethod.X509.value());
        if (!open) {
            log.warn("event=certificate_login_not_open clientId={}", sanitize(login.getClientId()));
            return Optional.empty();
        }
        return Optional.of(login);
    }

    private static boolean meetsEssentialLevel(OAuth2AuthorizationRequest login, AssuranceLevel level) {
        Map<String, Object> parameters = login.getAdditionalParameters();
        if (!Boolean.TRUE.equals(parameters.get(ACR_ESSENTIAL))) {
            return true;
        }
        return !(parameters.get(ACR_REQUESTED) instanceof String requested)
                || AssuranceLevel.fromAcrValue(requested).map(level::satisfies).orElse(true);
    }

    private Outcome audited(String tenant, String correlationId, String clientId, CertificateLoginReason reason,
                            ClientCertificate certificate) {
        audit(clientId, () -> CertificateAuthenticationAudit.rejected(tenant, correlationId, clientId, reason,
                certificate));
        return rejected(reason);
    }

    private void audit(String clientId, Supplier<CertificateAuthenticationAudit> event) {
        try {
            authenticationAuditPort.certificateAuthentication(event.get());
        } catch (RuntimeException e) {
            log.warn("event=certificate_authentication_audit_failed clientId={} error={}",
                    sanitize(clientId), e.getClass().getSimpleName());
        }
    }

    private static String correlationId(OAuth2AuthorizationRequest login) {
        return login.getAdditionalParameters().get(AUDIT_CORRELATION_ID) instanceof String id
                ? id
                : UUID.randomUUID().toString();
    }

    private static Outcome rejected(CertificateLoginReason reason) {
        return new Outcome.Rejected(reason);
    }
}
