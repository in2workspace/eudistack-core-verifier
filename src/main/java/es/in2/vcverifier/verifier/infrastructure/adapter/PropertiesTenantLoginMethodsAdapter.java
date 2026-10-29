package es.in2.vcverifier.verifier.infrastructure.adapter;

import es.in2.vcverifier.verifier.domain.model.LoginMethod;
import es.in2.vcverifier.verifier.domain.port.TenantLoginMethodsPort;
import es.in2.vcverifier.verifier.infrastructure.config.CertificateLoginProperties;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Set;

@Component
@RequiredArgsConstructor
public class PropertiesTenantLoginMethodsAdapter implements TenantLoginMethodsPort {

    private final CertificateLoginProperties certificateLoginProperties;

    @Override
    public Set<LoginMethod> activeLoginMethods(String tenant) {
        if (tenant != null && certificateLoginProperties.tenants().containsKey(tenant)) {
            return Set.of(LoginMethod.WALLET, LoginMethod.X509);
        }
        return Set.of(LoginMethod.WALLET);
    }
}
