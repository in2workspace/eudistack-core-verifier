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

import static es.in2.vcverifier.shared.domain.util.Constants.ACR_ESSENTIAL;
import static es.in2.vcverifier.shared.domain.util.Constants.ACR_REQUESTED;
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
    private final Clock clock;

    public sealed interface Outcome {

        record Completed(String redirectUri) implements Outcome {
        }

        record Rejected(CertificateLoginReason reason) implements Outcome {
        }
    }

    public Outcome login(String state, String tenant, String certificateHeader) {
        Optional<OAuth2AuthorizationRequest> login = openCertificateLogin(state, tenant);
        if (login.isEmpty()) {
            return rejected(CertificateLoginReason.LOGIN_NOT_FOUND);
        }
        if (certificateHeader == null || certificateHeader.isBlank()) {
            return rejected(CertificateLoginReason.CERTIFICATE_MISSING);
        }
        List<X509Certificate> chain;
        try {
            chain = clientCertificateReader.readChain(certificateHeader);
        } catch (IllegalArgumentException _) {
            log.warn("event=certificate_login_unreadable_certificate clientId={}", sanitize(login.get().getClientId()));
            return rejected(CertificateLoginReason.CERTIFICATE_MISSING);
        }

        CertificateTrust trust = certificateTrustValidationPort.validate(chain.getFirst(), chain.subList(1, chain.size()));
        if (!(trust instanceof CertificateTrust.Trusted trusted)) {
            return rejected(((CertificateTrust.Rejected) trust).reason());
        }

        ClientCertificate certificate = clientCertificateReader.read(chain.getFirst());
        CertificateIdentity identity = certificate.identity();
        if (identity.personalAdministrativeNumber() == null) {
            log.warn("event=certificate_login_without_number clientId={}", sanitize(login.get().getClientId()));
            return rejected(CertificateLoginReason.CERTIFICATE_NOT_QUALIFIED);
        }
        if (!meetsEssentialLevel(login.get(), trusted.level())) {
            return rejected(CertificateLoginReason.LEVEL_NOT_MET);
        }

        String subject = certificateSubjectService.subject(tenant, identity.country(), identity.personalAdministrativeNumber());
        CertificateAuthentication authentication = new CertificateAuthentication(subject, identity,
                certificate.issuer(), certificate.fingerprintSha256(), certificate.notAfter(),
                trusted.level(), trusted.amr(), clock.instant());

        Optional<AuthResponseResult> issued =
                authorizationResponseProcessorService.issueCodeForCertificateLogin(state, tenant, authentication);
        if (issued.isEmpty()) {
            return rejected(CertificateLoginReason.LOGIN_NOT_FOUND);
        }
        try {
            String redirectUri = ssoLoginCompletionWorkflow.resolveBrowserRedirect(
                    tenant, issued.get(), () -> subject, UUID.randomUUID().toString());
            log.info("event=certificate_login_completed clientId={} level={}",
                    sanitize(issued.get().clientId()), trusted.level().name());
            return new Outcome.Completed(redirectUri);
        } catch (LoginCompletionUnavailableException _) {
            return rejected(CertificateLoginReason.VALIDATION_UNAVAILABLE);
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

    private static Outcome rejected(CertificateLoginReason reason) {
        return new Outcome.Rejected(reason);
    }
}
