package es.in2.vcverifier.oauth2.infrastructure.adapter;

import es.in2.vcverifier.oauth2.domain.exception.SsoConfigLoadingException;
import es.in2.vcverifier.shared.config.properties.BackendProperties;
import es.in2.vcverifier.shared.domain.model.EligibleClientConfig;
import es.in2.vcverifier.shared.domain.model.TenantSsoConfigYamlData;
import es.in2.vcverifier.shared.domain.model.TenantSsoEntry;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
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

        assertNotNull(data);
        assertNotNull(data.tenants());
    }

    @Test
    void retrieve_blankPath_usesClasspath() {
        assertNotNull(new TenantSsoConfigYamlProvider(props("  ")).retrieve().tenants());
    }

    @Test
    void retrieve_noLocalFiles_usesClasspath() {
        assertNotNull(new TenantSsoConfigYamlProvider(propsWithoutLocalFiles()).retrieve().tenants());
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
        var provider = new TenantSsoConfigYamlProvider(props(writeYaml(YAML).toString()));

        assertFalse(provider.addEligibleClient("sandbox", "app-a"));
    }

    @Test
    void addEligibleClient_tenantNameIsCaseInsensitive() throws Exception {
        var provider = new TenantSsoConfigYamlProvider(props(writeYaml(YAML).toString()));

        assertTrue(provider.addEligibleClient("SANDBOX", "app-z"));
    }

    @Test
    void addEligibleClient_unknownTenant_returnsFalse() throws Exception {
        var provider = new TenantSsoConfigYamlProvider(props(writeYaml(YAML).toString()));

        assertFalse(provider.addEligibleClient("missing", "app-a"));
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
        var provider = new TenantSsoConfigYamlProvider(props(writeYaml(YAML).toString()));

        assertFalse(provider.removeEligibleClient("sandbox", "nope"));
    }

    @Test
    void removeEligibleClient_unknownTenant_returnsFalse() throws Exception {
        var provider = new TenantSsoConfigYamlProvider(props(writeYaml(YAML).toString()));

        assertFalse(provider.removeEligibleClient("missing", "app-a"));
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

        assertThrows(SsoConfigLoadingException.class, () -> provider.addEligibleClient("sandbox", "a"));
    }
}
