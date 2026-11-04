package es.in2.vcverifier.sso.domain.model;

import es.in2.vcverifier.shared.domain.model.AssuranceLevel;
import es.in2.vcverifier.shared.domain.model.AuthenticationResult;
import es.in2.vcverifier.shared.domain.model.CertificateAuthentication;
import es.in2.vcverifier.shared.domain.model.LoginMethod;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

public record SsoSessionAuthentication(
        LoginMethod method,
        AssuranceLevel acr,
        List<String> amr,
        Instant certificateNotAfter
) {

    public static final SsoSessionAuthentication WALLET_WITHOUT_LEVEL =
            new SsoSessionAuthentication(LoginMethod.WALLET, null, List.of(), null);

    public SsoSessionAuthentication {
        Objects.requireNonNull(method, "method");
        amr = amr == null ? List.of() : List.copyOf(amr);
    }

    public static SsoSessionAuthentication of(AuthenticationResult authentication) {
        Instant certificateNotAfter = authentication instanceof CertificateAuthentication certificate
                ? certificate.notAfter()
                : null;
        return new SsoSessionAuthentication(authentication.method(), authentication.acr(),
                authentication.amr(), certificateNotAfter);
    }
}
