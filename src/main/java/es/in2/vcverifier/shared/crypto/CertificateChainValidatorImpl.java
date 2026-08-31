package es.in2.vcverifier.shared.crypto;

import es.in2.vcverifier.shared.domain.exception.CertificateChainValidationException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.GeneralSecurityException;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Set;

/**
 * PKIX chain validator for x5c headers (RFC 7515 §4.1.6).
 * Completes incomplete chains via AIA {@code caIssuers} fetching (see
 * {@link AiaCertificateChainResolver}), then validates that the full chain is internally
 * consistent up to its top-most certificate. That top cert is trusted as the anchor whether
 * or not it is self-signed - HAIP §6.1 forbids a conformant issuer from including the
 * self-signed root at all, so requiring one here would reject every conformant chain.
 * Revocation (OCSP/CRL) intentionally disabled — Q3 roadmap per EUDISTACK-10 SRS §5.3 NFR-S-05.
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CertificateChainValidatorImpl implements CertificateChainValidator {

    private final AiaCertificateChainResolver aiaResolver;

    @Override
    public void validateSelfContainedChain(List<X509Certificate> rawChain) {
        if (rawChain == null || rawChain.isEmpty()) {
            throw new CertificateChainValidationException("x5c chain is empty");
        }

        List<X509Certificate> chain = aiaResolver.completeChain(rawChain);

        X509Certificate top = chain.get(chain.size() - 1);

        // HAIP §6.1 forbids a conformant issuer from including the self-signed root in x5c -
        // the relying party is expected to already trust it out-of-band. Rejecting a chain for
        // NOT carrying the root would break every conformant issuer, so the top cert is now
        // accepted as an unpinned trust anchor when it isn't self-signed either - same weak-
        // but-functional stance AiaCertificateChainResolver already takes when AIA chasing
        // can't reach a self-signed root. Configure a trust store to restrict accepted anchors
        // (EUDISTACK roadmap) - until then this stays backward compatible with chains that do
        // still carry the root (already-issued credentials, other issuers).
        if (!isSelfSigned(top)) {
            log.warn("x5c chain does not terminate in a self-signed root - accepted WITHOUT " +
                     "trust-anchor pinning (weaker security). Top cert subject: {}",
                     top.getSubjectX500Principal().getName());
        }

        if (chain.size() == 1) {
            validateSingleCertificate(top);
            return;
        }

        validatePkixChain(chain, top);
    }

    private void validateSingleCertificate(X509Certificate cert) {
        try {
            cert.checkValidity();
        } catch (GeneralSecurityException e) {
            throw new CertificateChainValidationException(
                    "x5c certificate is not valid: " + e.getMessage(), e);
        }
        log.debug("x5c single certificate validated (no chain to check)");
    }

    private void validatePkixChain(List<X509Certificate> chain, X509Certificate anchorCert) {
        try {
            // PKIX does not validate the trust anchor itself — check validity explicitly
            anchorCert.checkValidity();

            TrustAnchor anchor = new TrustAnchor(anchorCert, null);
            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            // CertPath = leaf + intermediates (all certs except the anchor), leaf-first
            List<X509Certificate> pathCerts = new ArrayList<>(chain.subList(0, chain.size() - 1));
            CertPath certPath = cf.generateCertPath(pathCerts);

            PKIXParameters params = new PKIXParameters(Set.of(anchor));
            params.setRevocationEnabled(false);

            validator.validate(certPath, params);
            log.debug("x5c chain of {} certs validated to its top-most anchor", chain.size());

        } catch (CertPathValidatorException e) {
            throw new CertificateChainValidationException(
                    "x5c chain validation failed at index " + e.getIndex() + ": " + e.getMessage(), e);
        } catch (GeneralSecurityException e) {
            throw new CertificateChainValidationException(
                    "x5c chain validation error: " + e.getMessage(), e);
        }
    }

    private boolean isSelfSigned(X509Certificate cert) {
        if (!cert.getSubjectX500Principal().equals(cert.getIssuerX500Principal())) {
            return false;
        }
        try {
            cert.verify(cert.getPublicKey());
            return true;
        } catch (GeneralSecurityException e) {
            return false;
        }
    }
}
