package es.in2.vcverifier.integration;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import es.in2.vcverifier.integration.support.DssStub;
import es.in2.vcverifier.integration.support.TestCertificates;
import es.in2.vcverifier.integration.support.TestCertificates.Person;
import es.in2.vcverifier.shared.config.CertificatePortFilter;
import es.in2.vcverifier.sso.infrastructure.web.SsoBrowserBindingCookie;
import es.in2.vcverifier.verifier.domain.model.ClientData;
import es.in2.vcverifier.verifier.domain.model.ExternalTrustedListYamlData;
import es.in2.vcverifier.verifier.domain.service.ClientRegistryProvider;
import es.in2.vcverifier.verifier.domain.service.TenantConfigPort;
import jakarta.servlet.http.Cookie;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.context.TestConfiguration;
import org.springframework.boot.test.system.CapturedOutput;
import org.springframework.boot.test.system.OutputCaptureExtension;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Primary;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.web.util.UriComponentsBuilder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ThreadLocalRandom;
import java.util.concurrent.TimeUnit;

import static es.in2.vcverifier.shared.domain.util.Constants.X_TENANT_HEADER;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

@SpringBootTest(properties = {
        "spring.flyway.enabled=false",
        "verifier.certificate-login.tenants.cgcom.login-origin=" + CertificateLoginIT.LOGIN_ORIGIN,
        "verifier.certificate-login.tenants.kpmg.login-origin=" + CertificateLoginIT.OTHER_LOGIN_ORIGIN,
        "verifier.certificate-login.subject-key=0123456789abcdef0123456789abcdef",
        "verifier.trust-validation.timeout=PT2S",
        "verifier.dcql.profiles.learcredential.credentials[0].id=learcredential",
        "verifier.dcql.profiles.learcredential.credentials[0].format=dc+sd-jwt",
        "verifier.dcql.profiles.learcredential.credentials[0].meta.vct-values[0]=learcredential.employee.w3c.4",
        "verifier.dcql.profiles.learcredential.assurance-level=substantial"
})
@AutoConfigureMockMvc
@ActiveProfiles("test")
class CertificateLoginIT {

    static final String TENANT = "cgcom";
    static final String HOST = "cgcom.example.com";
    static final String SECURE_HOST = "secure.example.com";
    static final String LOGIN_ORIGIN = "https://cgcom.example.com";
    static final String OTHER_LOGIN_ORIGIN = "https://kpmg.example.com";
    private static final int CERTIFICATE_PORT = 8081;
    private static final String CLIENT_ID = "issuance-portal-cgcom";
    private static final String WALLET_CLIENT_ID = "wallet-portal-cgcom";
    private static final String LEGACY_CLIENT_ID = "legacy-portal-cgcom";
    private static final String DCQL_SCOPE = "learcredential";
    private static final String AUTH_REQUEST = "authRequest";
    private static final String REDIRECT_URI = "https://cgcom.example.com/issuance-portal/callback";
    private static final String COMPLETION_PATH = "/api/login/complete";
    private static final String NUMBER_SCOPE = "personal_administrative_number";
    private static final String HIGH = "http://eidas.europa.eu/LoA/high";
    private static final String SUBSTANTIAL = "http://eidas.europa.eu/LoA/substantial";
    private static final String ESSENTIAL_HIGH =
            "{\"id_token\":{\"acr\":{\"essential\":true,\"values\":[\"" + HIGH + "\"]}}}";
    private static final Person PERSON = new Person("99999999R", "JOSE ANTONIO", "GARCIA FERNANDEZ", "jgarcia@example.com");

    private static final DssStub DSS = new DssStub();

    @DynamicPropertySource
    static void trustValidation(DynamicPropertyRegistry registry) {
        registry.add("verifier.trust-validation.url", DSS::url);
    }

    @AfterAll
    static void stopDss() {
        DSS.close();
    }

    @Autowired
    private MockMvc mockMvc;

    @Autowired
    private ObjectMapper objectMapper;

    @MockitoBean
    private TenantConfigPort tenantConfigPort;

    @AfterEach
    void makeDssAvailable() {
        DSS.unavailable(false);
    }

    @TestConfiguration
    static class Clients {

        @Bean
        @Primary
        ClientRegistryProvider testClientRegistryProvider() {
            return () -> new ExternalTrustedListYamlData(List.of(
                    client(CLIENT_ID, List.of("openid", "profile", "email", NUMBER_SCOPE, DCQL_SCOPE),
                            List.of("x509", "wallet")),
                    client(WALLET_CLIENT_ID, List.of("openid", DCQL_SCOPE), List.of("wallet")),
                    client(LEGACY_CLIENT_ID, List.of("openid", DCQL_SCOPE), null)));
        }
    }

    @Test
    void cardCertificate_logsInWithHighLevelAndHardwareKey() throws Exception {
        X509Certificate certificate = DSS.answer(TestCertificates.naturalPerson(PERSON, true), DssStub.QC_WITH_QSCD);

        JsonNode idToken = loginAndExchange(certificate, "openid profile email");

        assertThat(idToken.path("acr").asText()).isEqualTo(HIGH);
        assertThat(idToken.path("amr").toString()).isEqualTo("[\"hwk\"]");
        assertThat(idToken.path("given_name").asText()).isEqualTo(PERSON.givenName());
        assertThat(idToken.path("family_name").asText()).isEqualTo(PERSON.surname());
        assertThat(idToken.path("email").asText()).isEqualTo(PERSON.email());
    }

    @Test
    void softwareCertificate_logsInWithSubstantialLevelAndSoftwareKey() throws Exception {
        X509Certificate certificate = DSS.answer(TestCertificates.naturalPerson(PERSON, false), DssStub.QC);

        JsonNode idToken = loginAndExchange(certificate, "openid profile");

        assertThat(idToken.path("acr").asText()).isEqualTo(SUBSTANTIAL);
        assertThat(idToken.path("amr").toString()).isEqualTo("[\"swk\"]");
    }

    @Test
    void identificationNumber_isReleasedOnlyWithItsScope() throws Exception {
        X509Certificate certificate = DSS.answer(TestCertificates.naturalPerson(PERSON, false), DssStub.QC);

        JsonNode withScope = loginAndExchange(certificate, "openid profile " + NUMBER_SCOPE);
        JsonNode withoutScope = loginAndExchange(certificate, "openid profile");

        assertThat(withScope.path(NUMBER_SCOPE).asText()).isEqualTo(PERSON.number());
        assertThat(withoutScope.has(NUMBER_SCOPE)).isFalse();
    }

    @Test
    void subject_isStableAcrossCertificatesOfThePersonAndDoesNotContainTheNumber() throws Exception {
        X509Certificate first = DSS.answer(TestCertificates.naturalPerson(PERSON, false), DssStub.QC);
        X509Certificate renewed = DSS.answer(TestCertificates.naturalPerson(PERSON, true), DssStub.QC_WITH_QSCD);
        X509Certificate other = DSS.answer(TestCertificates.naturalPerson(
                new Person("12345678Z", "ANA", "LOPEZ RUIZ", null), false), DssStub.QC);

        String subject = loginAndExchange(first, "openid").path("sub").asText();

        assertThat(loginAndExchange(renewed, "openid").path("sub").asText()).isEqualTo(subject);
        assertThat(loginAndExchange(other, "openid").path("sub").asText()).isNotEqualTo(subject);
        assertThat(subject).doesNotContain(PERSON.number());
    }

    @Test
    void representativeCertificate_isRejectedAsNotANaturalPerson() throws Exception {
        X509Certificate certificate = DSS.answer(
                TestCertificates.representative(PERSON, "VATES-Q0000000J"), DssStub.QC);

        assertRejected(certificateLogin(openLogin("openid"), TestCertificates.header(certificate)),
                403, "certificate_not_natural_person");
    }

    @Test
    void revokedCertificate_isRejectedAsRevoked() throws Exception {
        X509Certificate certificate = DSS.answer(TestCertificates.naturalPerson(PERSON, false), DssStub.REVOKED);

        assertRejected(certificateLogin(openLogin("openid"), TestCertificates.header(certificate)),
                403, "certificate_revoked");
    }

    @Test
    void expiredCertificate_isRejectedAsExpired() throws Exception {
        X509Certificate certificate = DSS.answer(TestCertificates.expired(PERSON), DssStub.EXPIRED);

        assertRejected(certificateLogin(openLogin("openid"), TestCertificates.header(certificate)),
                403, "certificate_expired");
    }

    @Test
    void selfSignedCertificate_isRejectedAsNotQualified() throws Exception {
        X509Certificate certificate = TestCertificates.selfSigned(PERSON);

        assertRejected(certificateLogin(openLogin("openid"), TestCertificates.header(certificate)),
                403, "certificate_not_qualified");
    }

    @Test
    void callWithoutCertificate_isRejectedAsMissing() throws Exception {
        int callsBefore = DSS.calls();

        assertRejected(certificateLogin(openLogin("openid"), null), 401, "certificate_missing");
        assertThat(DSS.calls()).isEqualTo(callsBefore);
    }

    @Test
    void unavailableTrustValidation_isAFailureWithRetryAfter() throws Exception {
        X509Certificate certificate = DSS.answer(TestCertificates.naturalPerson(PERSON, false), DssStub.QC);
        DSS.unavailable(true);

        MvcResult result = certificateLogin(openLogin("openid"), TestCertificates.header(certificate));

        assertRejected(result, 503, "trust_validation_unavailable");
        assertThat(result.getResponse().getHeader(HttpHeaders.RETRY_AFTER)).isNotBlank();
    }

    @Test
    void rejection_neverEchoesTheCertificate() throws Exception {
        X509Certificate certificate = DSS.answer(TestCertificates.naturalPerson(PERSON, false), DssStub.REVOKED);

        String body = certificateLogin(openLogin("openid"), TestCertificates.header(certificate))
                .getResponse().getContentAsString();

        assertThat(body).doesNotContain(PERSON.number(), PERSON.surname(), TestCertificates.base64(certificate));
    }

    @Test
    @ExtendWith(OutputCaptureExtension.class)
    void logs_neverContainTheCertificateOrTheIdentificationNumber(CapturedOutput output) throws Exception {
        X509Certificate accepted = DSS.answer(TestCertificates.naturalPerson(PERSON, false), DssStub.QC);
        X509Certificate revoked = DSS.answer(TestCertificates.naturalPerson(PERSON, false), DssStub.REVOKED);

        loginAndExchange(accepted, "openid profile " + NUMBER_SCOPE);
        certificateLogin(openLogin("openid"), TestCertificates.header(revoked));

        assertThat(output.getAll()).doesNotContain(PERSON.number(),
                TestCertificates.base64(accepted), TestCertificates.base64(revoked),
                TestCertificates.header(accepted), TestCertificates.header(revoked));
    }

    @Test
    void essentialLevelNotMet_isRejectedAndTheLoginStaysOpen() throws Exception {
        X509Certificate software = DSS.answer(TestCertificates.naturalPerson(PERSON, false), DssStub.QC);
        Login login = openLogin(CLIENT_ID, "openid", Map.of("claims", ESSENTIAL_HIGH));

        assertRejected(certificateLogin(login, TestCertificates.header(software)), 403, "level_not_met");

        assertThat(methods(login).path("methods").toString()).isEqualTo("[\"x509\"]");
    }

    @Test
    void rejectedLogin_canBeAbortedSoTheApplicationReceivesAccessDenied() throws Exception {
        X509Certificate software = DSS.answer(TestCertificates.naturalPerson(PERSON, false), DssStub.QC);
        Login login = openLogin(CLIENT_ID, "openid", Map.of("claims", ESSENTIAL_HIGH));
        certificateLogin(login, TestCertificates.header(software));

        MvcResult abort = mockMvc.perform(post("/api/login/abort").with(host(HOST)).with(browser(login))
                        .param("state", login.state()))
                .andReturn();
        assertThat(abort.getResponse().getStatus()).isEqualTo(200);
        String redirectUrl = objectMapper.readTree(abort.getResponse().getContentAsString()).path("redirectUrl").asText();
        assertThat(redirectUrl).startsWith(REDIRECT_URI).contains("error=access_denied");
    }

    @Test
    void loginInProgress_cannotBeAbortedFromAnotherBrowser() throws Exception {
        Login login = openLogin("openid");

        assertThat(status(post("/api/login/abort").with(host(HOST)).param("state", login.state()))).isEqualTo(404);
        assertThat(methods(login).path("methods").toString()).isEqualTo("[\"x509\"]");
    }

    @Test
    void certificateHeaderOnTheNormalPort_isRejected() throws Exception {
        X509Certificate certificate = DSS.answer(TestCertificates.naturalPerson(PERSON, true), DssStub.QC_WITH_QSCD);
        String header = TestCertificates.header(certificate);
        int callsBefore = DSS.calls();

        assertThat(status(get("/api/login/methods").param("state", "s").with(host(HOST))
                .header(CertificatePortFilter.MTLS_CLIENT_CERT_HEADER, header))).isEqualTo(400);
        assertThat(status(post("/oidc/token").with(host(HOST))
                .header(CertificatePortFilter.MTLS_CLIENT_CERT_HEADER, header))).isEqualTo(400);
        assertThat(status(post("/api/login/certificate").with(host(HOST))
                .header(CertificatePortFilter.MTLS_CLIENT_CERT_HEADER, header)
                .contentType(MediaType.APPLICATION_JSON).content("{\"state\":\"s\"}"))).isEqualTo(400);
        assertThat(DSS.calls()).isEqualTo(callsBefore);
    }

    @Test
    void certificateLogin_doesNotExistOnTheNormalPort() throws Exception {
        assertThat(status(post("/api/login/certificate").with(host(HOST))
                .contentType(MediaType.APPLICATION_JSON).content("{\"state\":\"s\"}"))).isEqualTo(404);
    }

    @Test
    void certificatePort_servesOnlyTheCertificateLogin() throws Exception {
        assertThat(status(get("/oidc/authorize").with(certificatePort(SECURE_HOST)))).isEqualTo(404);
        assertThat(status(post("/oidc/token").with(certificatePort(SECURE_HOST)))).isEqualTo(404);
        assertThat(status(post("/api/login/wallet").param("state", "s").with(certificatePort(SECURE_HOST))))
                .isEqualTo(404);
    }

    @Test
    void certificateLoginWithoutTenantHeader_isNotFoundWithoutCallingTheTrustValidation() throws Exception {
        X509Certificate certificate = DSS.answer(TestCertificates.naturalPerson(PERSON, false), DssStub.QC);
        Login login = openLogin("openid");
        int callsBefore = DSS.calls();

        assertRejected(certificateLogin(login.state(), TestCertificates.header(certificate), null, null, Map.of()),
                404, "login_not_found");
        assertThat(DSS.calls()).isEqualTo(callsBefore);
    }

    @Test
    void unknownState_isNotFoundWithoutCallingTheTrustValidation() throws Exception {
        X509Certificate certificate = DSS.answer(TestCertificates.naturalPerson(PERSON, false), DssStub.QC);
        int callsBefore = DSS.calls();

        assertRejected(certificateLogin("state-that-does-not-exist", TestCertificates.header(certificate),
                TENANT, LOGIN_ORIGIN, Map.of()), 404, "login_not_found");
        assertThat(DSS.calls()).isEqualTo(callsBefore);
    }

    @Test
    void loginThatDoesNotOfferTheCertificate_isNotFound() throws Exception {
        X509Certificate certificate = DSS.answer(TestCertificates.naturalPerson(PERSON, false), DssStub.QC);
        Login walletLogin = openLogin(WALLET_CLIENT_ID, "openid " + DCQL_SCOPE, Map.of());
        int callsBefore = DSS.calls();

        assertRejected(certificateLogin(walletLogin, TestCertificates.header(certificate)), 404, "login_not_found");
        assertThat(DSS.calls()).isEqualTo(callsBefore);
    }

    @Test
    void loginOfAnotherTenant_isNotFound() throws Exception {
        X509Certificate certificate = DSS.answer(TestCertificates.naturalPerson(PERSON, false), DssStub.QC);
        Login login = openLogin("openid");
        int callsBefore = DSS.calls();

        assertRejected(certificateLogin(login.state(), TestCertificates.header(certificate), "kpmg",
                OTHER_LOGIN_ORIGIN, Map.of()), 404, "login_not_found");
        assertThat(DSS.calls()).isEqualTo(callsBefore);
    }

    @Test
    void loginMethods_followTheClientRegistration() throws Exception {
        Login selection = openLogin(CLIENT_ID, "openid " + DCQL_SCOPE, Map.of());
        Login walletOnly = openLogin(WALLET_CLIENT_ID, "openid " + DCQL_SCOPE, Map.of());

        assertThat(selection.query()).doesNotContainKey(AUTH_REQUEST);
        assertThat(methods(selection).path("methods").toString()).isEqualTo("[\"x509\",\"wallet\"]");
        assertThat(walletOnly.query()).containsKey(AUTH_REQUEST);
    }

    @Test
    void essentialLevelOnlyTheCertificateMeets_offersOnlyTheCertificate() throws Exception {
        Login login = openLogin(CLIENT_ID, "openid " + DCQL_SCOPE, Map.of("claims", ESSENTIAL_HIGH));

        JsonNode methods = methods(login);

        assertThat(login.query()).doesNotContainKey(AUTH_REQUEST);
        assertThat(methods.path("methods").toString()).isEqualTo("[\"x509\"]");
        assertThat(methods.path("essential_level").asText()).isEqualTo(HIGH);
    }

    @Test
    void essentialLevelNoMethodMeets_returnsUnmetAuthenticationRequirements() throws Exception {
        Login login = openLogin(WALLET_CLIENT_ID, "openid " + DCQL_SCOPE, Map.of("claims", ESSENTIAL_HIGH));

        assertThat(login.location()).startsWith(REDIRECT_URI);
        assertThat(login.query()).containsEntry("error", "unmet_authentication_requirements");
    }

    @Test
    void levelAsAPreference_isIgnoredWhenNoMethodMeetsIt() throws Exception {
        Login withAcrValues = openLogin(WALLET_CLIENT_ID, "openid " + DCQL_SCOPE, Map.of("acr_values", HIGH));
        Login withoutEssential = openLogin(WALLET_CLIENT_ID, "openid " + DCQL_SCOPE,
                Map.of("claims", "{\"id_token\":{\"acr\":{\"values\":[\"" + HIGH + "\"]}}}"));

        assertThat(withAcrValues.query()).containsKey(AUTH_REQUEST);
        assertThat(withoutEssential.query()).containsKey(AUTH_REQUEST);
    }

    @Test
    void loginThatAsksForNoAttestation_offersOnlyTheCertificate() throws Exception {
        Login login = openLogin(CLIENT_ID, "openid profile " + NUMBER_SCOPE, Map.of());

        assertThat(methods(login).path("methods").toString()).isEqualTo("[\"x509\"]");
        assertThat(status(post("/api/login/wallet").param("state", login.state()).with(host(HOST)))).isEqualTo(409);
    }

    @Test
    void loginThatAsksForAnAttestationAndTheNumber_offersBothMethodsAndCreatesTheWalletRequest() throws Exception {
        Login login = openLogin(CLIENT_ID, "openid profile " + NUMBER_SCOPE + " " + DCQL_SCOPE, Map.of());

        assertThat(methods(login).path("methods").toString()).isEqualTo("[\"x509\",\"wallet\"]");
        MvcResult wallet = mockMvc.perform(post("/api/login/wallet").param("state", login.state()).with(host(HOST)))
                .andReturn();
        assertThat(wallet.getResponse().getStatus()).isEqualTo(200);
        assertThat(objectMapper.readTree(wallet.getResponse().getContentAsString()).path(AUTH_REQUEST).asText())
                .isNotBlank();
    }

    @Test
    void walletOnlyLoginThatAsksForNoAttestation_returnsInvalidScopeToTheApplication() throws Exception {
        Login login = openLogin(WALLET_CLIENT_ID, "openid", Map.of());

        assertThat(login.location()).startsWith(REDIRECT_URI);
        assertThat(login.query()).containsEntry("error", "invalid_scope");
    }

    @Test
    void clientWithoutLoginMethods_goesStraightToTheWallet() throws Exception {
        Login login = openLogin(LEGACY_CLIENT_ID, "openid " + DCQL_SCOPE, Map.of());

        assertThat(login.query()).containsKey(AUTH_REQUEST);
    }

    @Test
    void concurrentCompletionsOfOneLogin_issueASingleCode() throws Exception {
        X509Certificate certificate = DSS.answer(TestCertificates.naturalPerson(PERSON, false), DssStub.QC);
        Login login = openLogin(CLIENT_ID, "openid " + DCQL_SCOPE, Map.of());
        String header = TestCertificates.header(certificate);
        CountDownLatch start = new CountDownLatch(1);
        ExecutorService executor = Executors.newFixedThreadPool(2);
        try {
            Callable<Integer> attempt = () -> {
                start.await();
                return certificateLogin(login, header).getResponse().getStatus();
            };
            Future<Integer> first = executor.submit(attempt);
            Future<Integer> second = executor.submit(attempt);
            start.countDown();

            assertThat(List.of(first.get(10, TimeUnit.SECONDS), second.get(10, TimeUnit.SECONDS)))
                    .containsExactlyInAnyOrder(200, 404);
        } finally {
            executor.shutdownNow();
        }
        assertThat(status(post("/api/login/wallet").param("state", login.state()).with(host(HOST)))).isEqualTo(404);
    }

    private JsonNode methods(Login login) throws Exception {
        MvcResult result = mockMvc.perform(get("/api/login/methods").param("state", login.state()).with(host(HOST)))
                .andReturn();
        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        return objectMapper.readTree(result.getResponse().getContentAsString());
    }

    private int status(MockHttpServletRequestBuilder request) throws Exception {
        return mockMvc.perform(request).andReturn().getResponse().getStatus();
    }

    private JsonNode loginAndExchange(X509Certificate certificate, String scope) throws Exception {
        Login login = openLogin(scope);
        MvcResult result = certificateLogin(login, TestCertificates.header(certificate));
        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        String redirectUri = objectMapper.readTree(result.getResponse().getContentAsString())
                .path("redirect_uri").asText();
        assertThat(redirectUri).contains(COMPLETION_PATH);
        String location = mockMvc.perform(get(redirectUri.substring(redirectUri.indexOf(COMPLETION_PATH)))
                        .with(host(HOST)).with(browser(login)))
                .andReturn().getResponse().getHeader(HttpHeaders.LOCATION);
        assertThat(location).as("completion redirect").startsWith(REDIRECT_URI);
        String code = UriComponentsBuilder.fromUriString(location).build().getQueryParams().getFirst("code");
        assertThat(code).isNotBlank();

        MvcResult token = mockMvc.perform(post("/oidc/token")
                        .with(host(HOST))
                        .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                        .param("grant_type", "authorization_code")
                        .param("code", code)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("client_id", CLIENT_ID)
                        .param("code_verifier", login.codeVerifier()))
                .andReturn();
        assertThat(token.getResponse().getStatus()).isEqualTo(200);
        return claims(objectMapper.readTree(token.getResponse().getContentAsString()).path("id_token").asText());
    }

    private Login openLogin(String scope) throws Exception {
        return openLogin(CLIENT_ID, scope, Map.of());
    }

    private Login openLogin(String clientId, String scope, Map<String, String> parameters) throws Exception {
        String codeVerifier = UUID.randomUUID() + "-" + UUID.randomUUID();
        var request = get("/oidc/authorize")
                .with(host(HOST))
                .param("response_type", "code")
                .param("client_id", clientId)
                .param("redirect_uri", REDIRECT_URI)
                .param("scope", scope)
                .param("state", "state-" + UUID.randomUUID())
                .param("nonce", "nonce-" + UUID.randomUUID())
                .param("code_challenge", challenge(codeVerifier))
                .param("code_challenge_method", "S256");
        parameters.forEach(request::param);
        MockHttpServletResponse response = mockMvc.perform(request).andReturn().getResponse();
        String location = response.getHeader(HttpHeaders.LOCATION);
        assertThat(location).as("authorization redirect").isNotNull();
        Map<String, String> query = UriComponentsBuilder.fromUriString(location).build().getQueryParams()
                .toSingleValueMap();
        assertThat(query.get("state")).as("state in %s", location).isNotBlank();
        Cookie binding = response.getCookie(SsoBrowserBindingCookie.COOKIE_NAME);
        return new Login(query.get("state"), codeVerifier, location, query, binding == null ? null : binding.getValue());
    }

    private MvcResult certificateLogin(Login login, String certificateHeader) throws Exception {
        return certificateLogin(login.state(), certificateHeader, TENANT, LOGIN_ORIGIN, Map.of());
    }

    private MvcResult certificateLogin(String state, String certificateHeader, String tenant, String origin,
                                       Map<String, String> headers) throws Exception {
        var request = post("/api/login/certificate")
                .with(certificatePort(SECURE_HOST))
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("state", state)));
        if (tenant != null) {
            request.header(X_TENANT_HEADER, tenant);
        }
        if (origin != null) {
            request.header(HttpHeaders.ORIGIN, origin);
        }
        if (certificateHeader != null) {
            request.header(CertificatePortFilter.MTLS_CLIENT_CERT_HEADER, certificateHeader);
        }
        headers.forEach(request::header);
        return mockMvc.perform(request).andReturn();
    }

    private void assertRejected(MvcResult result, int status, String type) throws Exception {
        assertThat(result.getResponse().getStatus()).isEqualTo(status);
        assertThat(result.getResponse().getContentType()).isEqualTo(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        assertThat(objectMapper.readTree(result.getResponse().getContentAsString()).path("type").asText())
                .isEqualTo(type);
    }

    private JsonNode claims(String jwt) throws Exception {
        return objectMapper.readTree(Base64.getUrlDecoder().decode(jwt.split("\\.")[1]));
    }

    private static RequestPostProcessor host(String host) {
        return request -> {
            request.setScheme("https");
            request.setSecure(true);
            request.setServerPort(443);
            request.setServerName(host);
            request.setRemoteAddr(randomAddress());
            return request;
        };
    }

    private static RequestPostProcessor browser(Login login) {
        return request -> {
            request.setCookies(new Cookie(SsoBrowserBindingCookie.COOKIE_NAME, login.binding()));
            return request;
        };
    }

    private static RequestPostProcessor certificatePort(String host) {
        return request -> {
            host(host).postProcessRequest(request);
            request.setLocalPort(CERTIFICATE_PORT);
            return request;
        };
    }

    private static String randomAddress() {
        ThreadLocalRandom random = ThreadLocalRandom.current();
        return "10." + random.nextInt(256) + "." + random.nextInt(256) + "." + random.nextInt(1, 255);
    }

    private static String challenge(String verifier) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(verifier.getBytes(StandardCharsets.US_ASCII));
        return Base64.getUrlEncoder().withoutPadding().encodeToString(digest);
    }

    private static ClientData client(String clientId, List<String> scopes, List<String> loginMethods) {
        return new ClientData(clientId, REDIRECT_URI, clientId, null, List.of(REDIRECT_URI), scopes, List.of("none"),
                List.of("authorization_code"), false, List.of(), true, null, null, TENANT, null, null, null,
                loginMethods);
    }

    private record Login(String state, String codeVerifier, String location, Map<String, String> query,
                         String binding) {
    }
}
