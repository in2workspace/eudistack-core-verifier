package es.in2.vcverifier.sso.domain.model;

import org.junit.jupiter.api.Test;

import java.util.List;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

class TenantSsoCatalogTest {

    // =========================================================
    // empty() — AC-03 fail-closed
    // =========================================================

    @Test
    void empty_contains_returnsFalse_forAnyClientId() {
        TenantSsoCatalog catalog = TenantSsoCatalog.empty();

        assertThat(catalog.contains("any-client")).isFalse();
    }

    @Test
    void empty_contains_returnsFalse_forNullClientId() {
        TenantSsoCatalog catalog = TenantSsoCatalog.empty();

        assertThat(catalog.contains(null)).isFalse();
    }

    // =========================================================
    // contains — catálogo con entradas
    // =========================================================

    @Test
    void contains_returnsTrue_forRegisteredClient() {
        TenantSsoCatalog catalog = TenantSsoCatalog.of(List.of("client-a", "client-b"));

        assertThat(catalog.contains("client-a")).isTrue();
        assertThat(catalog.contains("client-b")).isTrue();
    }

    @Test
    void contains_returnsFalse_forAbsentClient() {
        TenantSsoCatalog catalog = TenantSsoCatalog.of(List.of("client-a"));

        assertThat(catalog.contains("client-x")).isFalse();
    }

    @Test
    void contains_normalizesInputClientId_byTrimming() {
        TenantSsoCatalog catalog = TenantSsoCatalog.of(List.of("client-a"));

        assertThat(catalog.contains("  client-a  ")).isTrue();
    }

    @Test
    void contains_returnsFalse_whenClientIdIsNull() {
        TenantSsoCatalog catalog = TenantSsoCatalog.of(List.of("client-a"));

        assertThat(catalog.contains(null)).isFalse();
    }

    @Test
    void contains_returnsFalse_whenClientIdIsBlank() {
        TenantSsoCatalog catalog = TenantSsoCatalog.of(List.of("client-a"));

        assertThat(catalog.contains("   ")).isFalse();
    }

    // =========================================================
    // of() — normalización de entradas al construir
    // =========================================================

    @Test
    void of_normalizesEntries_byTrimmingWhitespace() {
        TenantSsoCatalog catalog = TenantSsoCatalog.of(List.of("  client-a  "));

        assertThat(catalog.contains("client-a")).isTrue();
    }

    // =========================================================
    // Idempotencia — duplicados en la lista de entrada
    // =========================================================

    @Test
    void of_deduplicatesDuplicateEntries() {
        TenantSsoCatalog withDuplicates  = TenantSsoCatalog.of(List.of("client-a", "client-a", "client-b"));
        TenantSsoCatalog withoutDuplicates = TenantSsoCatalog.of(List.of("client-a", "client-b"));

        assertThat(withDuplicates).isEqualTo(withoutDuplicates);
    }

    @Test
    void of_deduplicatesEntries_afterNormalization() {
        // "client-a" y "  client-a  " son el mismo valor normalizado
        TenantSsoCatalog catalog = TenantSsoCatalog.of(List.of("client-a", "  client-a  "));
        TenantSsoCatalog reference = TenantSsoCatalog.of(List.of("client-a"));

        assertThat(catalog).isEqualTo(reference);
    }

    // =========================================================
    // of() — validación de entrada
    // =========================================================

    @Test
    void of_throwsNullPointerException_whenRawListIsNull() {
        assertThatThrownBy(() -> TenantSsoCatalog.of(null))
                .isInstanceOf(NullPointerException.class);
    }

    // =========================================================
    // equals / hashCode
    // =========================================================

    @Test
    void equals_returnsTrue_forCatalogsWithSameClients_regardlessOfInputOrder() {
        TenantSsoCatalog a = TenantSsoCatalog.of(List.of("client-a", "client-b"));
        TenantSsoCatalog b = TenantSsoCatalog.of(List.of("client-b", "client-a"));

        assertThat(a).isEqualTo(b);
        assertThat(a.hashCode()).isEqualTo(b.hashCode());
    }

    @Test
    void equals_returnsFalse_forCatalogsWithDifferentClients() {
        TenantSsoCatalog a = TenantSsoCatalog.of(List.of("client-a"));
        TenantSsoCatalog b = TenantSsoCatalog.of(List.of("client-b"));

        assertThat(a).isNotEqualTo(b);
    }

    @Test
    void equals_returnsFalse_betweenEmptyAndNonEmpty() {
        TenantSsoCatalog empty    = TenantSsoCatalog.empty();
        TenantSsoCatalog nonEmpty = TenantSsoCatalog.of(List.of("client-a"));

        assertThat(empty).isNotEqualTo(nonEmpty);
    }
}
