package es.in2.vcverifier.shared.domain.port;

import java.util.Optional;

public interface CredentialIssuerTenantResolverPort {

    Optional<String> resolveTenantByIssuer(String issuer);

}
