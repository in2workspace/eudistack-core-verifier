package es.in2.vcverifier.verifier.domain.port;

import es.in2.vcverifier.verifier.domain.model.CertificateTrust;

import java.security.cert.X509Certificate;
import java.util.List;

public interface CertificateTrustValidationPort {

    CertificateTrust validate(X509Certificate certificate, List<X509Certificate> chain);
}
