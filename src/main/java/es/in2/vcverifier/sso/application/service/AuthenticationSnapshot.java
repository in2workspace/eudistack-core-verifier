package es.in2.vcverifier.sso.application.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ArrayNode;
import com.fasterxml.jackson.databind.node.ObjectNode;
import es.in2.vcverifier.shared.domain.model.AssuranceLevel;
import es.in2.vcverifier.shared.domain.model.AuthenticationResult;
import es.in2.vcverifier.shared.domain.model.CertificateAuthentication;
import es.in2.vcverifier.shared.domain.model.CertificateIdentity;
import es.in2.vcverifier.shared.domain.model.CredentialAuthentication;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;

public final class AuthenticationSnapshot {

    static final String TYPE = "snapshot_type";
    static final String CREDENTIAL = "credential";
    static final String CERTIFICATE = "certificate";

    private static final ObjectMapper MAPPER = new ObjectMapper();

    private AuthenticationSnapshot() {
    }

    public static String write(AuthenticationResult authentication) {
        ObjectNode snapshot = MAPPER.createObjectNode();
        switch (authentication) {
            case CredentialAuthentication credential -> {
                snapshot.put(TYPE, CREDENTIAL);
                snapshot.set(CREDENTIAL, credential.credential());
            }
            case CertificateAuthentication certificate -> {
                snapshot.put(TYPE, CERTIFICATE);
                snapshot.put("subject", certificate.subject());
                CertificateIdentity identity = certificate.identity();
                snapshot.putObject("identity")
                        .put("given_name", identity.givenName())
                        .put("family_name", identity.surname())
                        .put("name", identity.commonName())
                        .put("email", identity.email())
                        .put("country", identity.country())
                        .put("personal_administrative_number", identity.personalAdministrativeNumber());
                snapshot.put("issuer", certificate.issuer());
                snapshot.put("fingerprint_sha256", certificate.fingerprintSha256());
                snapshot.put("not_after", certificate.notAfter().getEpochSecond());
                ArrayNode amr = snapshot.putArray("amr");
                certificate.amr().forEach(amr::add);
            }
        }
        if (authentication.acr() != null) {
            snapshot.put("acr", authentication.acr().acrValue());
        }
        snapshot.put("auth_time", authentication.authTime().getEpochSecond());
        try {
            return MAPPER.writeValueAsString(snapshot);
        } catch (JsonProcessingException e) {
            throw new IllegalStateException("Cannot write the authentication snapshot", e);
        }
    }

    public static Optional<AuthenticationResult> read(String json, Instant establishedAt) {
        JsonNode snapshot;
        try {
            snapshot = MAPPER.readTree(json);
        } catch (JsonProcessingException _) {
            return Optional.empty();
        }
        if (snapshot == null || !snapshot.isObject()) {
            return Optional.empty();
        }
        JsonNode type = snapshot.get(TYPE);
        if (type == null) {
            return Optional.of(new CredentialAuthentication(snapshot, null, establishedAt));
        }
        try {
            return switch (type.asText()) {
                case CREDENTIAL -> Optional.of(new CredentialAuthentication(
                        snapshot.get(CREDENTIAL), acr(snapshot), authTime(snapshot, establishedAt)));
                case CERTIFICATE -> Optional.of(certificate(snapshot, establishedAt));
                default -> Optional.empty();
            };
        } catch (RuntimeException _) {
            return Optional.empty();
        }
    }

    private static CertificateAuthentication certificate(JsonNode snapshot, Instant establishedAt) {
        JsonNode identity = snapshot.path("identity");
        List<String> amr = new ArrayList<>();
        snapshot.path("amr").forEach(value -> amr.add(value.asText()));
        return new CertificateAuthentication(
                text(snapshot, "subject"),
                new CertificateIdentity(
                        text(identity, "given_name"),
                        text(identity, "family_name"),
                        text(identity, "name"),
                        text(identity, "email"),
                        text(identity, "country"),
                        text(identity, "personal_administrative_number")),
                text(snapshot, "issuer"),
                text(snapshot, "fingerprint_sha256"),
                Instant.ofEpochSecond(snapshot.path("not_after").asLong()),
                acr(snapshot),
                amr,
                authTime(snapshot, establishedAt));
    }

    private static AssuranceLevel acr(JsonNode snapshot) {
        String acr = text(snapshot, "acr");
        return acr == null ? null : AssuranceLevel.fromAcrValue(acr).orElse(null);
    }

    private static Instant authTime(JsonNode snapshot, Instant establishedAt) {
        JsonNode authTime = snapshot.get("auth_time");
        return authTime != null && authTime.canConvertToLong() ? Instant.ofEpochSecond(authTime.asLong()) : establishedAt;
    }

    private static String text(JsonNode node, String field) {
        JsonNode value = node.get(field);
        return value != null && value.isTextual() ? value.asText() : null;
    }
}
