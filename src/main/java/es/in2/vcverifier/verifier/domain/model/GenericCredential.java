package es.in2.vcverifier.verifier.domain.model;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.vcverifier.verifier.domain.model.validation.SchemaProfile;

import java.time.Instant;
import java.time.format.DateTimeParseException;
import java.util.List;
import java.util.Optional;

/**
 * Generic credential backed by a JsonNode and a SchemaProfile.
 * Extracts fields dynamically using dot-notation paths declared in the profile.
 */
public record GenericCredential(
        JsonNode root,
        SchemaProfile profile,
        String credentialConfigurationId,
        List<String> types,
        List<String> context
) {
    /**
     * Extract a text field by dot-notation path
     * (e.g., "credentialSubject.mandate.mandator.organizationIdentifier").
     */
    public Optional<String> field(String path) {
        if (path == null) {
            return Optional.empty();
        }
        JsonNode node = navigatePath(path);
        return node != null && !node.isMissingNode() && !node.isNull()
                ? Optional.of(node.asText())
                : Optional.empty();
    }

    /**
     * Extract a time field by path. Supports ISO-8601 strings and epoch seconds (numeric).
     */
    public Optional<Instant> timeField(String path) {
        if (path == null) {
            return Optional.empty();
        }
        JsonNode node = navigatePath(path);
        if (node == null || node.isMissingNode() || node.isNull()) {
            return Optional.empty();
        }
        if (node.isNumber()) {
            return Optional.of(Instant.ofEpochSecond(node.longValue()));
        }
        try {
            return Optional.of(Instant.parse(node.asText()));
        } catch (DateTimeParseException e) {
            return Optional.empty();
        }
    }

    /**
     * Extract a JsonNode subtree by dot-notation path.
     */
    public Optional<JsonNode> node(String path) {
        if (path == null) {
            return Optional.empty();
        }
        JsonNode node = navigatePath(path);
        return node != null && !node.isMissingNode() && !node.isNull()
                ? Optional.of(node)
                : Optional.empty();
    }

    private JsonNode navigatePath(String dotPath) {
        String[] segments = dotPath.split("\\.");
        JsonNode current = root;
        for (String segment : segments) {
            if (current == null || current.isMissingNode()) {
                return null;
            }
            current = current.get(segment);
        }
        return current;
    }
}
