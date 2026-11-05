package es.in2.vcverifier.shared.domain.model;

import java.time.Instant;
import java.util.List;

public sealed interface AuthenticationResult permits CredentialAuthentication, CertificateAuthentication {

    LoginMethod method();

    AssuranceLevel acr();

    List<String> amr();

    Instant authTime();
}
