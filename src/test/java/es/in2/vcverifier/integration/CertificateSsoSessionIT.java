package es.in2.vcverifier.integration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.integration.support.DssStub;
import es.in2.vcverifier.integration.support.TestCertificates;
import es.in2.vcverifier.integration.support.TestCertificates.Person;
import es.in2.vcverifier.shared.config.CertificatePortFilter;
import es.in2.vcverifier.verifier.domain.model.ClientData;
import es.in2.vcverifier.verifier.domain.model.ExternalTrustedListYamlData;
import es.in2.vcverifier.verifier.domain.service.ClientRegistryProvider;
import es.in2.vcverifier.verifier.domain.service.TenantConfigPort;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.security.oauth2.core.oidc.StandardClaimNames;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.web.util.UriComponentsBuilder;
import org.testcontainers.containers.PostgreSQLContainer;
import org.testcontainers.junit.jupiter.Container;
import org.testcontainers.junit.jupiter.Testcontainers;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

import static es.in2.vcverifier.shared.domain.util.Constants.X_TENANT_HEADER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

@SpringBootTest(properties = {
        "verifier.certificate-login.tenants.cgcom.login-origin=" + CertificateSsoSessionIT.LOGIN_ORIGIN,
        "verifier.certificate-login.subject-key=0123456789abcdef0123456789abcdef",
        "verifier.dcql.profiles.learcredential.credentials[0].id=learcredential",
        "verifier.dcql.profiles.learcredential.credentials[0].format=dc+sd-jwt",
        "verifier.dcql.profiles.learcredential.credentials[0].meta.vct-values[0]=learcredential.employee.w3c.4",
        "verifier.dcql.profiles.learcredential.assurance-level=substantial"
})
@Testcontainers
@AutoConfigureMockMvc
@ActiveProfiles("test")
class CertificateSsoSessionIT {

    static final String HOST = "cgcom.example.com";
    static final String SECURE_HOST = "secure.example.com";
    static final String LOGIN_ORIGIN = "https://cgcom.example.com";
    private static final String TENANT = "cgcom";
    private static final String FIRST_CLIENT = "issuance-portal-cgcom";
    private static final String SECOND_CLIENT = "second-portal-cgcom";
    private static final String WALLET_CLIENT = "wallet-portal-cgcom";
    private static final String REDIRECT_URI = "https://cgcom.example.com/callback";
    private static final String DCQL_SCOPE = "learcredential";
    private static final String HIGH = "http://eidas.europa.eu/LoA/high";
    private static final String ESSENTIAL_HIGH =
            "{\"id_token\":{\"acr\":{\"essential\":true,\"values\":[\"" + HIGH + "\"]}}}";
    private static final String COMPLETION_PATH = "/api/login/complete";
    private static final String SESSION_COOKIE = "__Secure-sso-" + TENANT;
    private static final int CERTIFICATE_PORT = 8081;
    private static final Person PERSON = new Person("99999999R", "JOSE ANTONIO", "GARCIA FERNANDEZ", "jgarcia@example.com");

    @Container
    static PostgreSQLContainer<?> postgres = new PostgreSQLContainer<>("postgres:16-alpine")
            .withDatabaseName("vcverifier")
            .withUsername("test")
            .withPassword("test");

    private static final DssStub DSS = new DssStub();

    @DynamicPropertySource
    static void props(DynamicPropertyRegistry registry) {
        registry.add("spring.datasource.url", postgres::getJdbcUrl);
        registry.add("spring.datasource.username", postgres::getUsername);
        registry.add("spring.datasource.password", postgres::getPassword);
        registry.add("spring.flyway.url", postgres::getJdbcUrl);
        registry.add("spring.flyway.user", postgres::getUsername);
        registry.add("spring.flyway.password", postgres::getPassword);
        registry.add("verifier.trust-validation.url", DSS::url);
        registry.add("verifier.backend.local-files.sso-config-path", CertificateSsoSessionIT::ssoConfig);
    }

    @AfterAll
    static void stopDss() {
        DSS.close();
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @Autowired
    private JdbcTemplate jdbcTemplate;

    @MockitoBean
    private TenantConfigPort tenantConfigPort;

    private final Map<String, String> browser = new LinkedHashMap<>();

    @BeforeEach
    void newBrowser() {
        browser.clear();
        jdbcTemplate.update("DELETE FROM sso_session");
    }

    @TestConfiguration
    static class Clients {

        @Bean
        @Primary
        ClientRegistryProvider testClientRegistryProvider() {
            return () -> new ExternalTrustedListYamlData(List.of(
                    client(FIRST_CLIENT, List.of("openid", "profile", DCQL_SCOPE), List.of("x509", "wallet")),
                    client(SECOND_CLIENT, List.of("openid", "profile", DCQL_SCOPE), List.of("x509", "wallet")),
                    client(WALLET_CLIENT, List.of("openid", DCQL_SCOPE), List.of("wallet"))));
        }
    }

    @Test
    void cardCertificateSession_isReusedWithItsLevelAndWithoutValidatingAgain() throws Exception {
        X509Certificate card = DSS.answer(TestCertificates.naturalPerson(PERSON, true), DssStub.QC_WITH_QSCD);
        JsonNode first = loginWithCertificate(FIRST_CLIENT, card);
        int callsBefore = DSS.calls();

        Login reuse = authorize(SECOND_CLIENT, "openid profile", Map.of("claims", ESSENTIAL_HIGH));

        assertThat(reuse.query()).containsKey("code");
        JsonNode idToken = exchange(SECOND_CLIENT, reuse, reuse.query().get("code"));
        assertThat(idToken.path("acr").asText()).isEqualTo(HIGH);
        assertThat(idToken.path("amr").toString()).isEqualTo("[\"hwk\"]");
        assertThat(idToken.path("sub").asText()).isEqualTo(first.path("sub").asText());
        assertThat(idToken.path("given_name").asText()).isEqualTo(PERSON.givenName());
        assertThat(DSS.calls()).isEqualTo(callsBefore);
    }

    @Test
    void certificateSession_isNotReusedForAnApplicationThatOnlyOffersTheWallet() throws Exception {
        X509Certificate card = DSS.answer(TestCertificates.naturalPerson(PERSON, true), DssStub.QC_WITH_QSCD);
        loginWithCertificate(FIRST_CLIENT, card);

        Login walletLogin = authorize(WALLET_CLIENT, "openid " + DCQL_SCOPE, Map.of());

        assertThat(walletLogin.query()).containsKey("authRequest").doesNotContainKey("code");
        assertThat(activeSessions()).isEqualTo(1);
    }

    @Test
    void certificateSession_isNotReusedWhenTheApplicationAsksForAnAttestation() throws Exception {
        X509Certificate card = DSS.answer(TestCertificates.naturalPerson(PERSON, true), DssStub.QC_WITH_QSCD);
        loginWithCertificate(FIRST_CLIENT, card);

        Login login = authorize(SECOND_CLIENT, "openid " + DCQL_SCOPE, Map.of());

        assertThat(login.query()).doesNotContainKeys("code", "authRequest");
        assertThat(methods(login).path("methods").toString()).isEqualTo("[\"x509\",\"wallet\"]");
    }

    @Test
    void sessionOfAnExpiredCertificate_isTerminatedAndTheLoginShowsTheMethods() throws Exception {
        X509Certificate card = DSS.answer(TestCertificates.naturalPerson(PERSON, true), DssStub.QC_WITH_QSCD);
        loginWithCertificate(FIRST_CLIENT, card);
        jdbcTemplate.update("UPDATE sso_session SET certificate_not_after = now() - interval '1 day' WHERE tenant = ?",
                TENANT);

        Login login = authorize(SECOND_CLIENT, "openid profile", Map.of());

        assertThat(login.query()).doesNotContainKeys("code", "authRequest");
        assertThat(methods(login).path("methods").toString()).isEqualTo("[\"x509\"]");
        assertThat(activeSessions()).isZero();
    }

    @Test
    void loginOfAnotherPersonInTheSameBrowser_replacesTheSession() throws Exception {
        X509Certificate first = DSS.answer(TestCertificates.naturalPerson(PERSON, true), DssStub.QC_WITH_QSCD);
        X509Certificate second = DSS.answer(TestCertificates.naturalPerson(
                new Person("12345678Z", "ANA", "LOPEZ RUIZ", null), true), DssStub.QC_WITH_QSCD);
        loginWithCertificate(FIRST_CLIENT, first);
        String firstCookie = browser.get(SESSION_COOKIE);

        Login login = authorize(SECOND_CLIENT, "openid profile", Map.of("prompt", "login"));
        JsonNode idToken = completeWithCertificate(SECOND_CLIENT, login, second);

        assertThat(idToken.path(StandardClaimNames.GIVEN_NAME).asText()).isEqualTo("ANA");
        assertThat(browser.get(SESSION_COOKIE)).isNotEqualTo(firstCookie);
        assertThat(activeSessions()).isEqualTo(1);
    }

    @Test
    void rejectedLoginInATenantWithSso_canBeAbortedSoTheApplicationReceivesAccessDenied() throws Exception {
        X509Certificate revoked = DSS.answer(TestCertificates.naturalPerson(PERSON, false), DssStub.REVOKED);
        Login login = authorize(FIRST_CLIENT, "openid profile", Map.of());
        assertThat(certificate(login, revoked).getResponse().getStatus()).isEqualTo(403);

        MvcResult abort = perform(post("/api/login/abort").param("state", login.state()).with(origin(HOST, 443)));

        assertThat(abort.getResponse().getStatus()).isEqualTo(200);
        assertThat(objectMapper.readTree(abort.getResponse().getContentAsString()).path("redirectUrl").asText())
                .startsWith(REDIRECT_URI).contains("error=access_denied");
    }

    private JsonNode loginWithCertificate(String clientId, X509Certificate certificate) throws Exception {
        return completeWithCertificate(clientId, authorize(clientId, "openid profile", Map.of()), certificate);
    }

    private MvcResult certificate(Login login, X509Certificate certificate) throws Exception {
        return perform(post("/api/login/certificate")
                .with(origin(SECURE_HOST, CERTIFICATE_PORT))
                .header(X_TENANT_HEADER, TENANT)
                .header(HttpHeaders.ORIGIN, LOGIN_ORIGIN)
                .header(CertificatePortFilter.MTLS_CLIENT_CERT_HEADER, TestCertificates.header(certificate))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("state", login.state()))));
    }

    private JsonNode completeWithCertificate(String clientId, Login login, X509Certificate certificate) throws Exception {
        MvcResult result = certificate(login, certificate);
        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        String redirectUri = objectMapper.readTree(result.getResponse().getContentAsString()).path("redirect_uri").asText();
        assertThat(redirectUri).contains(COMPLETION_PATH);

        String completion = redirectUri.substring(redirectUri.indexOf(COMPLETION_PATH));
        String location = perform(get(completion).with(origin(HOST, 443))).getResponse().getHeader(HttpHeaders.LOCATION);
        assertThat(location).as("completion redirect").startsWith(REDIRECT_URI);
        String code = UriComponentsBuilder.fromUriString(location).build().getQueryParams().getFirst("code");
        assertThat(browser).containsKey(SESSION_COOKIE);
        return exchange(clientId, login, code);
    }

    private Login authorize(String clientId, String scope, Map<String, String> parameters) throws Exception {
        String codeVerifier = UUID.randomUUID() + "-" + UUID.randomUUID();
        MockHttpServletRequestBuilder request = get("/oidc/authorize")
                .with(origin(HOST, 443))
                .param("response_type", "code")
                .param("client_id", clientId)
                .param("redirect_uri", REDIRECT_URI)
                .param("scope", scope)
                .param("state", "state-" + UUID.randomUUID())
                .param("nonce", "nonce-" + UUID.randomUUID())
                .param("code_challenge", challenge(codeVerifier))
                .param("code_challenge_method", "S256");
        parameters.forEach(request::param);
        String location = perform(request).getResponse().getHeader(HttpHeaders.LOCATION);
        assertThat(location).as("authorization redirect").isNotNull();
        Map<String, String> query = UriComponentsBuilder.fromUriString(location).build().getQueryParams()
                .toSingleValueMap();
        return new Login(query.get("state"), codeVerifier, query);
    }

    private JsonNode exchange(String clientId, Login login, String code) throws Exception {
        MvcResult token = perform(post("/oidc/token")
                .with(origin(HOST, 443))
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .param("grant_type", "authorization_code")
                .param("code", code)
                .param("redirect_uri", REDIRECT_URI)
                .param("client_id", clientId)
                .param("code_verifier", login.codeVerifier()));
        assertThat(token.getResponse().getStatus()).isEqualTo(200);
        String idToken = objectMapper.readTree(token.getResponse().getContentAsString()).path("id_token").asText();
        return objectMapper.readTree(Base64.getUrlDecoder().decode(idToken.split("\\.")[1]));
    }

    private JsonNode methods(Login login) throws Exception {
        MvcResult result = perform(get("/api/login/methods").param("state", login.state()).with(origin(HOST, 443)));
        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        return objectMapper.readTree(result.getResponse().getContentAsString());
    }

    private MvcResult perform(MockHttpServletRequestBuilder request) throws Exception {
        browser.forEach((name, value) -> request.cookie(new Cookie(name, value)));
        MvcResult result = mockMvc.perform(request).andReturn();
        for (Cookie cookie : result.getResponse().getCookies()) {
            if (cookie.getMaxAge() == 0) {
                browser.remove(cookie.getName());
            } else {
                browser.put(cookie.getName(), cookie.getValue());
            }
        }
        return result;
    }

    private Integer activeSessions() {
        return jdbcTemplate.queryForObject(
                "SELECT count(*) FROM sso_session WHERE tenant = ? AND state = 'ACTIVE'", Integer.class, TENANT);
    }

    private static RequestPostProcessor origin(String host, int localPort) {
        return request -> {
            request.setScheme("https");
            request.setSecure(true);
            request.setServerPort(443);
            request.setServerName(host);
            request.setLocalPort(localPort);
            ThreadLocalRandom random = ThreadLocalRandom.current();
            request.setRemoteAddr("10." + random.nextInt(256) + "." + random.nextInt(256) + "." + random.nextInt(1, 255));
            return request;
        };
    }

    private static String challenge(String verifier) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    private static String ssoConfig() {
        try {
            Path file = Files.createTempFile("sso-config", ".yaml");
            Files.writeString(file, """
                    tenants:
                      - tenant: "%s"
                        rootDomain: "%s"
                        ssoEnabled: true
                        eligibleClients:
                          - clientId: "%s"
                          - clientId: "%s"
                          - clientId: "%s"
                    """.formatted(TENANT, HOST, FIRST_CLIENT, SECOND_CLIENT, WALLET_CLIENT));
            file.toFile().deleteOnExit();
            return file.toString();
        } catch (IOException e) {
            throw new IllegalStateException(e);
        }
    }

    private static ClientData client(String clientId, List<String> scopes, List<String> loginMethods) {
        return new ClientData(clientId, REDIRECT_URI, clientId, null, List.of(REDIRECT_URI), scopes, List.of("none"),
                List.of("authorization_code"), false, List.of(), true, null, null, TENANT, null, null, null,
                loginMethods);
    }

    private record Login(String state, String codeVerifier, Map<String, String> query) {
    }
}
