package es.in2.vcverifier.oauth2.domain.service;

import es.in2.vcverifier.oauth2.domain.model.RequestedAssuranceLevel;
import es.in2.vcverifier.shared.domain.model.AssuranceLevel;
import es.in2.vcverifier.shared.domain.model.LoginMethod;
import org.junit.jupiter.api.Test;

import java.util.List;
import java.util.Set;

import static es.in2.vcverifier.shared.domain.model.AssuranceLevel.HIGH;
import static es.in2.vcverifier.shared.domain.model.AssuranceLevel.SUBSTANTIAL;
import static es.in2.vcverifier.shared.domain.model.LoginMethod.WALLET;
import static es.in2.vcverifier.shared.domain.model.LoginMethod.X509;
import static org.assertj.core.api.Assertions.assertThat;

class LoginMethodsResolverTest {

    private static final List<LoginMethod> BOTH = List.of(X509, WALLET);
    private static final Set<LoginMethod> TENANT_WITH_CERTIFICATE = Set.of(WALLET, X509);
    private static final Set<LoginMethod> TENANT_WITHOUT_CERTIFICATE = Set.of(WALLET);

    private final LoginMethodsResolver resolver = new LoginMethodsResolver();

    @Test
    void withoutRequestedLevel_offersTheClientMethodsInTheirOrder() {
        assertThat(resolver.resolve(BOTH, TENANT_WITH_CERTIFICATE, null, null)).containsExactly(X509, WALLET);
    }

    @Test
    void walletOnlyClient_offersOnlyTheWallet() {
        assertThat(resolver.resolve(List.of(WALLET), TENANT_WITH_CERTIFICATE, null, null)).containsExactly(WALLET);
    }

    @Test
    void methodNotActiveInTheTenant_isNotOffered() {
        assertThat(resolver.resolve(BOTH, TENANT_WITHOUT_CERTIFICATE, null, null)).containsExactly(WALLET);
    }

    @Test
    void certificateOnlyClientInATenantWithoutCertificate_offersNothing() {
        assertThat(resolver.resolve(List.of(X509), TENANT_WITHOUT_CERTIFICATE, null, null)).isEmpty();
    }

    @Test
    void essentialLevelThatOnlyTheCertificateMeets_offersOnlyTheCertificate() {
        assertThat(resolver.resolve(BOTH, TENANT_WITH_CERTIFICATE, SUBSTANTIAL, essential(HIGH)))
                .containsExactly(X509);
    }

    @Test
    void essentialLevelThatBothMethodsMeet_offersBoth() {
        assertThat(resolver.resolve(BOTH, TENANT_WITH_CERTIFICATE, HIGH, essential(HIGH)))
                .containsExactly(X509, WALLET);
    }

    @Test
    void essentialLevelThatNoMethodMeets_offersNothing() {
        assertThat(resolver.resolve(List.of(WALLET), TENANT_WITH_CERTIFICATE, SUBSTANTIAL, essential(HIGH)))
                .isEmpty();
    }

    @Test
    void essentialLevelWithAWalletWithoutDeclaredLevel_doesNotOfferTheWallet() {
        assertThat(resolver.resolve(BOTH, TENANT_WITH_CERTIFICATE, null, essential(SUBSTANTIAL)))
                .containsExactly(X509);
    }

    @Test
    void preferredLevelThatNoMethodMeets_isIgnored() {
        assertThat(resolver.resolve(List.of(WALLET), TENANT_WITH_CERTIFICATE, SUBSTANTIAL, preferred(HIGH)))
                .containsExactly(WALLET);
    }

    @Test
    void preferredLevelThatSomeMethodMeets_offersOnlyThoseMethods() {
        assertThat(resolver.resolve(BOTH, TENANT_WITH_CERTIFICATE, SUBSTANTIAL, preferred(HIGH)))
                .containsExactly(X509);
    }

    @Test
    void lowerRequestedLevel_isMetByAHigherWallet() {
        assertThat(resolver.resolve(List.of(WALLET), TENANT_WITH_CERTIFICATE, HIGH, essential(SUBSTANTIAL)))
                .containsExactly(WALLET);
    }

    @Test
    void essentialLevelInATenantWithoutCertificate_offersNothingWhenTheWalletFallsShort() {
        assertThat(resolver.resolve(BOTH, TENANT_WITHOUT_CERTIFICATE, SUBSTANTIAL, essential(HIGH))).isEmpty();
    }

    private static RequestedAssuranceLevel essential(AssuranceLevel level) {
        return new RequestedAssuranceLevel(level, true);
    }

    private static RequestedAssuranceLevel preferred(AssuranceLevel level) {
        return new RequestedAssuranceLevel(level, false);
    }
}
