package es.in2.vcverifier.verifier.infrastructure.adapter.trustframework;

import es.in2.vcverifier.verifier.domain.exception.IssuerNotAuthorizedException;
import es.in2.vcverifier.verifier.domain.model.issuer.IssuerCredentialsCapabilities;
import es.in2.vcverifier.verifier.domain.service.TrustFrameworkService;
import es.in2.vcverifier.verifier.domain.service.TrustedIssuersProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.ObjectProvider;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class TrustFrameworkServiceImpl implements TrustFrameworkService {

    private final ObjectProvider<TrustedIssuersProvider> trustedIssuersProvider;

    @Override
    public List<IssuerCredentialsCapabilities> getTrustedIssuerListData(String id) {
        TrustedIssuersProvider provider = trustedIssuersProvider.getIfAvailable();
        if (provider == null) {
            throw new IssuerNotAuthorizedException("No trusted issuers list is configured");
        }
        return provider.getIssuerCapabilities(id);
    }
}
