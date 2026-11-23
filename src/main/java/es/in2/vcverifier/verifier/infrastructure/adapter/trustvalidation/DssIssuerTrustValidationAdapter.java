package es.in2.vcverifier.verifier.infrastructure.adapter.trustvalidation;

import es.in2.vcverifier.shared.domain.util.LogSanitizer;
import es.in2.vcverifier.verifier.domain.model.IssuerTrust;
import es.in2.vcverifier.verifier.domain.port.IssuerTrustValidationPort;
import es.in2.vcverifier.verifier.infrastructure.config.TrustValidationProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class DssIssuerTrustValidationAdapter implements IssuerTrustValidationPort {

    private static final String EVENT = "business.credential.issuer_trust";

    private final DssCertificateValidationClient dssClient;
    private final TrustValidationProperties trustValidationProperties;
    private final Clock clock;

    @Override
    public IssuerTrust validate(List<X509Certificate> issuerChain, String credentialConfigurationId,
                                String declaredIssuer) {
        IssuerTrust trust = evaluate(issuerChain, credentialConfigurationId, declaredIssuer);
        logDecision(trust, credentialConfigurationId, declaredIssuer);
        return trust;
    }

    private IssuerTrust evaluate(List<X509Certificate> issuerChain, String credentialConfigurationId,
                                 String declaredIssuer) {
        if (issuerChain == null || issuerChain.isEmpty()) {
            return new IssuerTrust.NotTrusted("The attestation carries no issuer certificate chain (x5c)");
        }
        if (credentialConfigurationId == null || credentialConfigurationId.isBlank()) {
            return new IssuerTrust.NotTrusted("The attestation type is unknown");
        }
        try {
            return DssIssuerReportTranslator.translate(
                    dssClient.validateCertificate(issuerChain.getFirst(), issuerChain.subList(1, issuerChain.size())),
                    credentialConfigurationId, declaredIssuer, clock.instant(), trustValidationProperties.maxListAge());
        } catch (DssUnavailableException e) {
            return new IssuerTrust.Unavailable(e.getMessage());
        }
    }

    private static void logDecision(IssuerTrust trust, String credentialConfigurationId, String declaredIssuer) {
        String configurationId = LogSanitizer.sanitize(credentialConfigurationId);
        String issuer = LogSanitizer.sanitize(declaredIssuer);
        switch (trust) {
            case IssuerTrust.Trusted(String entity, String serviceType, String listUrl, String listType,
                                     Integer sequence) ->
                    log.info("event={} configurationId={} issuer={} outcome=trusted entity={} serviceType={} "
                                    + "list={} listType={} listSequence={}",
                            EVENT, configurationId, issuer, LogSanitizer.sanitize(entity), serviceType,
                            LogSanitizer.sanitize(listUrl), listType, sequence);
            case IssuerTrust.NotTrusted(String reason) ->
                    log.warn("event={} configurationId={} issuer={} outcome=IssuerNotTrusted reason={}",
                            EVENT, configurationId, issuer, LogSanitizer.sanitize(reason));
            case IssuerTrust.Unavailable(String reason) ->
                    log.warn("event={} configurationId={} issuer={} outcome=TrustListUnavailable reason={}",
                            EVENT, configurationId, issuer, LogSanitizer.sanitize(reason));
        }
    }
}
