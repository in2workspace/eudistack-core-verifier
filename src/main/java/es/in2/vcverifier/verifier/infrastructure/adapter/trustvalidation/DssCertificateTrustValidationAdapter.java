package es.in2.vcverifier.verifier.infrastructure.adapter.trustvalidation;

import es.in2.vcverifier.shared.domain.model.AssuranceLevel;
import es.in2.vcverifier.verifier.domain.model.CertificateLoginReason;
import es.in2.vcverifier.verifier.domain.model.CertificateTrust;
import es.in2.vcverifier.verifier.domain.port.CertificateTrustValidationPort;
import es.in2.vcverifier.verifier.infrastructure.config.TrustValidationProperties;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.springframework.stereotype.Component;

import java.security.cert.X509Certificate;
import java.time.Clock;
import java.util.List;

@Slf4j
@Component
@RequiredArgsConstructor
public class DssCertificateTrustValidationAdapter implements CertificateTrustValidationPort {

    private static final ASN1ObjectIdentifier ORGANIZATION_IDENTIFIER = new ASN1ObjectIdentifier("2.5.4.97");

    private final DssCertificateValidationClient dssClient;
    private final TrustValidationProperties trustValidationProperties;
    private final Clock clock;

    @Override
    public CertificateTrust validate(X509Certificate certificate, List<X509Certificate> chain) {
        try {
            CertificateTrust trust = DssReportTranslator.translate(dssClient.validateCertificate(certificate, chain),
                    hasOrganizationIdentifier(certificate), clock.instant(), trustValidationProperties.maxListAge());
            log.info("event=trust_validation_done result={}", describe(trust));
            return trust;
        } catch (DssUnavailableException _) {
            return new CertificateTrust.Rejected(CertificateLoginReason.VALIDATION_UNAVAILABLE);
        }
    }

    private static boolean hasOrganizationIdentifier(X509Certificate certificate) {
        X500Name subject = X500Name.getInstance(certificate.getSubjectX500Principal().getEncoded());
        return subject.getRDNs(ORGANIZATION_IDENTIFIER).length > 0;
    }

    private static String describe(CertificateTrust trust) {
        return switch (trust) {
            case CertificateTrust.Trusted(AssuranceLevel level, _) -> "trusted level=" + level.name();
            case CertificateTrust.Rejected(CertificateLoginReason reason) -> reason.value();
        };
    }
}
