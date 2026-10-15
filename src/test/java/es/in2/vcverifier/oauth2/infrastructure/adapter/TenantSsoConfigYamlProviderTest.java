package es.in2.vcverifier.oauth2.infrastructure.adapter;

import es.in2.vcverifier.oauth2.domain.exception.SsoConfigLoadingException;
import es.in2.vcverifier.shared.config.properties.BackendProperties;
import es.in2.vcverifier.shared.domain.model.EligibleClientConfig;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfigYamlData;
import es.in2.vcverifier.shared.domain.model.TenantSsoEntry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertInstanceOf;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;

class TenantSsoConfigYamlProviderTest {

    private static final String YAML = """
            tenants:
              - tenant: Sandbox
                rootDomain: sandbox.example.com
                ssoEnabled: true
                eligibleClients:
                  - clientId: app-a
                  - clientId: app-b
                    backchannelLogoutUri: https://b.example.com/logout
                ttlAbsolute: PT8H
                ttlIdle: PT30M
              - tenant: other
                rootDomain: other.example.com
                ssoEnabled: false
            """;

    @TempDir
    Path dir;

    private static BackendProperties props(String ssoConfigPath) {
        return new BackendProperties("http://localhost", null, null, null,
                new BackendProperties.LocalFiles(null, null, null, ssoConfigPath),
                null, null, null, null, null);
    }

    private static BackendProperties propsWithoutLocalFiles() {
        return new BackendProperties("http://localhost", null, null, null, null, null, null, null, null, null);
    }

    private Path writeYaml(String content) throws Exception {
        Path file = dir.resolve("sso-config.yaml");
        Files.writeString(file, content);
        return file;
    }

    /** The {@code sso-config.yaml} shipped in the test classpath: three tenants, only the first one has a client. */
    private static void assertIsTestClasspathConfig(TenantSsoConfigYamlData data) {
        assertEquals(List.of("sandbox", "sandboxDos", "sandboxTres"),
                data.tenants().stream().map(TenantSsoEntry::tenant).toList());
        assertEquals(List.of("verifier-client"),
                data.tenants().get(0).eligibleClients().stream().map(EligibleClientConfig::clientId).toList());
        assertTrue(data.tenants().get(1).eligibleClients().isEmpty());
    }

    // --- retrieve ---

    @Test
    void retrieve_fromExternalFile_parsesTenantsAndNormalizesMissingClients() throws Exception {
        Path file = writeYaml(YAML);

        TenantSsoConfigYamlData data = new TenantSsoConfigYamlProvider(props(file.toString())).retrieve();

        assertEquals(2, data.tenants().size());
        assertEquals(2, data.tenants().get(0).eligibleClients().size());
        assertEquals("https://b.example.com/logout", data.tenants().get(0).eligibleClients().get(1).backchannelLogoutUri());
        assertTrue(data.tenants().get(1).eligibleClients().isEmpty());
    }

    @Test
    void retrieve_externalFileWithUnknownKey_throwsSsoConfigLoadingException() throws Exception {
        Path file = writeYaml("other: 1\n");

        var provider = new TenantSsoConfigYamlProvider(props(file.toString()));

        assertThrows(SsoConfigLoadingException.class, provider::retrieve);
    }

    @Test
    void retrieve_externalFileWithNullTenants_returnsEmptyList() throws Exception {
        Path file = writeYaml("tenants:\n");

        TenantSsoConfigYamlData data = new TenantSsoConfigYamlProvider(props(file.toString())).retrieve();

        assertTrue(data.tenants().isEmpty());
    }

    @Test
    void retrieve_missingExternalFile_fallsBackToClasspath() {
        TenantSsoConfigYamlData data = new TenantSsoConfigYamlProvider(
                props(dir.resolve("absent.yaml").toString())).retrieve();

        assertIsTestClasspathConfig(data);
    }

    @Test
    void retrieve_blankPath_usesClasspath() {
        assertIsTestClasspathConfig(new TenantSsoConfigYamlProvider(props("  ")).retrieve());
    }

    @Test
    void retrieve_noLocalFiles_usesClasspath() {
        assertIsTestClasspathConfig(new TenantSsoConfigYamlProvider(propsWithoutLocalFiles()).retrieve());
    }

    @Test
    void retrieve_invalidYaml_throwsSsoConfigLoadingException() throws Exception {
        Path file = writeYaml("tenants: [unclosed");

        var provider = new TenantSsoConfigYamlProvider(props(file.toString()));

        assertThrows(SsoConfigLoadingException.class, provider::retrieve);
    }

    // --- addEligibleClient ---

    @Test
    void addEligibleClient_newClient_persistsAndReturnsTrue() throws Exception {
        Path file = writeYaml(YAML);
        var provider = new TenantSsoConfigYamlProvider(props(file.toString()));

        assertTrue(provider.addEligibleClient("sandbox", "app-c"));

        TenantSsoEntry sandbox = provider.retrieve().tenants().get(0);
        assertEquals(3, sandbox.eligibleClients().size());
        assertEquals("app-c", sandbox.eligibleClients().get(2).clientId());
        assertEquals("other", provider.retrieve().tenants().get(1).tenant());
        assertFalse(Files.exists(dir.resolve("sso-config.yaml.tmp")));
    }

    @Test
    void addEligibleClient_alreadyPresent_returnsFalse() throws Exception {
        Path file = writeYaml(YAML);
        var provider = new TenantSsoConfigYamlProvider(props(file.toString()));

        assertFalse(provider.addEligibleClient("sandbox", "app-a"));

        assertEquals(YAML, Files.readString(file));
    }

    @Test
    void addEligibleClient_tenantNameIsCaseInsensitive() throws Exception {
        Path file = writeYaml(YAML);
        var provider = new TenantSsoConfigYamlProvider(props(file.toString()));

        assertTrue(provider.addEligibleClient("SANDBOX", "app-z"));

        TenantSsoEntry sandbox = provider.retrieve().tenants().get(0);
        assertEquals("Sandbox", sandbox.tenant());
        assertEquals(List.of("app-a", "app-b", "app-z"),
                sandbox.eligibleClients().stream().map(EligibleClientConfig::clientId).toList());
        assertTrue(provider.retrieve().tenants().get(1).eligibleClients().isEmpty());
    }

    @Test
    void addEligibleClient_unknownTenant_returnsFalse() throws Exception {
        Path file = writeYaml(YAML);
        var provider = new TenantSsoConfigYamlProvider(props(file.toString()));

        assertFalse(provider.addEligibleClient("missing", "app-a"));

        assertEquals(YAML, Files.readString(file));
    }

    @Test
    void addEligibleClient_entryWithoutTenantName_isSkipped() throws Exception {
        Path file = writeYaml("""
                tenants:
                  - rootDomain: nameless.example.com
                    ssoEnabled: true
                  - tenant: sandbox
                    ssoEnabled: true
                """);
        var provider = new TenantSsoConfigYamlProvider(props(file.toString()));

        assertTrue(provider.addEligibleClient("sandbox", "app-a"));
        assertEquals(2, provider.retrieve().tenants().size());
    }

    // --- removeEligibleClient ---

    @Test
    void removeEligibleClient_existing_persistsAndReturnsTrue() throws Exception {
        var provider = new TenantSsoConfigYamlProvider(props(writeYaml(YAML).toString()));

        assertTrue(provider.removeEligibleClient("sandbox", "app-a"));

        var clients = provider.retrieve().tenants().get(0).eligibleClients();
        assertEquals(1, clients.size());
        assertEquals(EligibleClientConfig.of("app-b", "https://b.example.com/logout"), clients.get(0));
    }

    @Test
    void removeEligibleClient_absentClient_returnsFalse() throws Exception {
        Path file = writeYaml(YAML);
        var provider = new TenantSsoConfigYamlProvider(props(file.toString()));

        assertFalse(provider.removeEligibleClient("sandbox", "nope"));

        assertEquals(YAML, Files.readString(file));
    }

    @Test
    void removeEligibleClient_unknownTenant_returnsFalse() throws Exception {
        Path file = writeYaml(YAML);
        var provider = new TenantSsoConfigYamlProvider(props(file.toString()));

        assertFalse(provider.removeEligibleClient("missing", "app-a"));

        assertEquals(YAML, Files.readString(file));
    }

    // --- write errors ---

    @Test
    void modify_withoutConfiguredPath_throws() {
        var provider = new TenantSsoConfigYamlProvider(props(null));

        var ex = assertThrows(SsoConfigLoadingException.class, () -> provider.addEligibleClient("sandbox", "a"));
        assertTrue(ex.getMessage().contains("not configured"));
    }

    @Test
    void modify_withBlankPath_throws() {
        var provider = new TenantSsoConfigYamlProvider(props(" "));

        assertThrows(SsoConfigLoadingException.class, () -> provider.removeEligibleClient("sandbox", "a"));
    }

    @Test
    void modify_withoutLocalFiles_throws() {
        var provider = new TenantSsoConfigYamlProvider(propsWithoutLocalFiles());

        assertThrows(SsoConfigLoadingException.class, () -> provider.addEligibleClient("sandbox", "a"));
    }

    @Test
    void modify_missingFile_wrapsIoException() {
        var provider = new TenantSsoConfigYamlProvider(props(dir.resolve("absent.yaml").toString()));

        var ex = assertThrows(SsoConfigLoadingException.class, () -> provider.addEligibleClient("sandbox", "a"));

        assertInstanceOf(IOException.class, ex.getCause());
    }

    @Test
    void modify_nullTenant_failsWithNullPointerAndLeavesFileUntouched() throws Exception {
        Path file = writeYaml(YAML);
        var provider = new TenantSsoConfigYamlProvider(props(file.toString()));

        // Documents current behaviour: `normalizedTenant.equals(...)` is not null-safe. Fixing
        // production (reject or return false) is tracked separately.
        assertThrows(NullPointerException.class, () -> provider.addEligibleClient(null, "a"));

        assertEquals(YAML, Files.readString(file));
    }
}
