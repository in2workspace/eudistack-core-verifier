package es.in2.vcverifier.verifier.domain.util;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.vcverifier.verifier.domain.exception.InvalidCredentialTypeException;

import java.util.Set;

/**
 * Resolves the credential configuration ID from a credential's JSON representation.
 * Works for both W3C VCDM (type[] array) and SD-JWT VC (vct claim) formats.
 */
public final class CredentialTypeResolver {

    private static final Set<String> GENERIC_TYPES = Set.of("VerifiableCredential", "VerifiableAttestation");

    private CredentialTypeResolver() {} // utility class

    public static String resolveConfigId(JsonNode credential) {
        // W3C VCDM: type[] array — pick the first non-generic type
        JsonNode typeNode = credential.get("type");
        if (typeNode != null && typeNode.isArray()) {
            for (JsonNode t : typeNode) {
                String type = t.asText();
                if (!GENERIC_TYPES.contains(type)) {
                    return type;
                }
            }
        }
        // SD-JWT VC: vct claim
        JsonNode vctNode = credential.get("vct");
        if (vctNode != null && vctNode.isTextual()) {
            return vctNode.asText();
        }
        throw new InvalidCredentialTypeException(
                "Cannot resolve credential type: no 'type' array or 'vct' claim found");
    }
}
