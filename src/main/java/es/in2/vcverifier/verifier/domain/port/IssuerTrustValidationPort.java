package es.in2.vcverifier.verifier.domain.port;

import es.in2.vcverifier.verifier.domain.model.IssuerTrust;

import java.security.cert.X509Certificate;
import java.util.List;

public interface IssuerTrustValidationPort {

    IssuerTrust validate(List<X509Certificate> issuerChain, String credentialConfigurationId, String declaredIssuer);
}
