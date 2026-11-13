package es.in2.vcverifier.shared.domain.model;

import com.fasterxml.jackson.databind.JsonNode;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

public record CredentialAuthentication(
        JsonNode credential,
        AssuranceLevel acr,
        Instant authTime
) implements AuthenticationResult {

    private static final List<String> AMR = List.of("pop");

    public CredentialAuthentication {
        Objects.requireNonNull(credential, "credential");
        Objects.requireNonNull(authTime, "authTime");
    }

    @Override
    public LoginMethod method() {
        return LoginMethod.WALLET;
    }

    @Override
    public List<String> amr() {
        return AMR;
    }
}
