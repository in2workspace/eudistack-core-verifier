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
 * {@link AiaCertificateChainResolver}), then validates that the full chain
 * is internally consistent and terminates in a self-signed root.
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

        X509Certificate root = chain.get(chain.size() - 1);

        if (!isSelfSigned(root)) {
            throw new CertificateChainValidationException(
                    "x5c chain does not terminate in a self-signed root. Top cert subject: "
                    + root.getSubjectX500Principal().getName());
        }

        if (chain.size() == 1) {
            validateSelfSignedLeaf(root);
            return;
        }

        validatePkixChain(chain, root);
    }

    private void validateSelfSignedLeaf(X509Certificate cert) {
        try {
            cert.checkValidity();
        } catch (GeneralSecurityException e) {
            throw new CertificateChainValidationException(
                    "x5c self-signed certificate is not valid: " + e.getMessage(), e);
        }
        log.debug("x5c single self-signed certificate validated");
    }

    private void validatePkixChain(List<X509Certificate> chain, X509Certificate root) {
        try {
            // PKIX does not validate the trust anchor itself — check validity explicitly
            root.checkValidity();

            TrustAnchor anchor = new TrustAnchor(root, null);
            CertPathValidator validator = CertPathValidator.getInstance("PKIX");
            CertificateFactory cf = CertificateFactory.getInstance("X.509");

            // CertPath = leaf + intermediates (all certs except the root/anchor), leaf-first
            List<X509Certificate> pathCerts = new ArrayList<>(chain.subList(0, chain.size() - 1));
            CertPath certPath = cf.generateCertPath(pathCerts);

            PKIXParameters params = new PKIXParameters(Set.of(anchor));
            params.setRevocationEnabled(false);

            validator.validate(certPath, params);
            log.debug("x5c chain of {} certs validated to self-contained root", chain.size());

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
