package es.in2.vcverifier.sso;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.shared.domain.model.CredentialAuthentication;

import java.time.Instant;

public final class SsoTestAuthentications {

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private SsoTestAuthentications() {
    }

    public static CredentialAuthentication credential(String json) {
        try {
            return new CredentialAuthentication(MAPPER.readTree(json), null, Instant.now());
        } catch (JsonProcessingException e) {
            throw new IllegalArgumentException(e);
        }
    }
}
