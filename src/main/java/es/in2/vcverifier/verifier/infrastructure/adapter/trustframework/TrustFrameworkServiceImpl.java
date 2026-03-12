package es.in2.vcverifier.verifier.infrastructure.adapter.trustframework;

import es.in2.vcverifier.verifier.domain.model.issuer.IssuerCredentialsCapabilities;
import es.in2.vcverifier.verifier.domain.service.TrustFrameworkService;
import es.in2.vcverifier.verifier.domain.service.TrustedIssuersProvider;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.util.List;

@Service
@RequiredArgsConstructor
@Slf4j
public class TrustFrameworkServiceImpl implements TrustFrameworkService {

    private final TrustedIssuersProvider trustedIssuersProvider;

    @Override
    public List<IssuerCredentialsCapabilities> getTrustedIssuerListData(String id) {
        return trustedIssuersProvider.getIssuerCapabilities(id);
    }
}
