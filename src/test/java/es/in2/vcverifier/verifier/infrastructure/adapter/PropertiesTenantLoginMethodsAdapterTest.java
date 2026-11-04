package es.in2.vcverifier.verifier.infrastructure.adapter;

import es.in2.vcverifier.shared.domain.model.LoginMethod;
import es.in2.vcverifier.shared.config.properties.CertificateLoginProperties;
import org.junit.jupiter.api.Test;

import java.util.Map;

import static org.assertj.core.api.Assertions.assertThat;

class PropertiesTenantLoginMethodsAdapterTest {

    private final PropertiesTenantLoginMethodsAdapter adapter = new PropertiesTenantLoginMethodsAdapter(
            new CertificateLoginProperties(Map.of(
                    "cgcom", new CertificateLoginProperties.Tenant(
                            "cgcom-cert.stg.eudistack.net", "https://cgcom.stg.eudistack.net"))));

    @Test
    void activeLoginMethods_withCertificateLoginEntry_offersWalletAndCertificate() {
        assertThat(adapter.activeLoginMethods("cgcom"))
                .containsExactlyInAnyOrder(LoginMethod.WALLET, LoginMethod.X509);
    }

    @Test
    void activeLoginMethods_withoutCertificateLoginEntry_offersOnlyTheWallet() {
        assertThat(adapter.activeLoginMethods("sandbox")).containsExactly(LoginMethod.WALLET);
    }

    @Test
    void activeLoginMethods_withoutTenant_offersOnlyTheWallet() {
        assertThat(adapter.activeLoginMethods(null)).containsExactly(LoginMethod.WALLET);
    }

    @Test
    void activeLoginMethods_withoutAnyEntry_offersOnlyTheWallet() {
        PropertiesTenantLoginMethodsAdapter withoutEntries =
                new PropertiesTenantLoginMethodsAdapter(new CertificateLoginProperties(null));

        assertThat(withoutEntries.activeLoginMethods("cgcom")).containsExactly(LoginMethod.WALLET);
    }
}
