package es.in2.vcverifier.shared.crypto;

import java.security.cert.X509Certificate;
import java.util.List;

public interface CertificateChainValidator {

    /**
     * Self-contained PKIX validation of an x5c chain (leaf-first, RFC 7515 §4.1.6).
     * The last element must be a self-signed root certificate. Revocation (OCSP/CRL)
     * is not checked — see EUDISTACK-10 SRS §5.3 NFR-S-05 for Q3 roadmap.
     *
     * @throws es.in2.vcverifier.shared.domain.exception.CertificateChainValidationException
     *         if the chain does not validate to a self-signed root
     */
    void validateSelfContainedChain(List<X509Certificate> chain);
}
