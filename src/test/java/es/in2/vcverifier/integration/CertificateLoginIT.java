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
import org.springframework.test.context.bean.override.mockito.MockitoBean;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.MvcResult;
import org.springframework.test.web.servlet.request.RequestPostProcessor;
import org.springframework.web.util.UriComponentsBuilder;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.cert.X509Certificate;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ThreadLocalRandom;

import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.post;

@SpringBootTest(properties = {
        "spring.flyway.enabled=false",
        "verifier.certificate-login.tenants.cgcom.host=" + CertificateLoginIT.CERTIFICATE_HOST,
        "verifier.certificate-login.tenants.cgcom.login-origin=" + CertificateLoginIT.LOGIN_ORIGIN,
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
    static final String CERTIFICATE_HOST = "cgcom-cert.example.com";
    static final String LOGIN_ORIGIN = "https://cgcom.example.com";
    private static final String CLIENT_ID = "issuance-portal-cgcom";
    private static final String REDIRECT_URI = "https://cgcom.example.com/issuance-portal/callback";
    private static final String NUMBER_SCOPE = "personal_administrative_number";
    private static final String HIGH = "http://eidas.europa.eu/LoA/high";
    private static final String SUBSTANTIAL = "http://eidas.europa.eu/LoA/substantial";
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
                    client(CLIENT_ID, List.of("openid", "profile", "email", NUMBER_SCOPE), List.of("x509", "wallet"))));
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

    private JsonNode loginAndExchange(X509Certificate certificate, String scope) throws Exception {
        Login login = openLogin(scope);
        MvcResult result = certificateLogin(login, TestCertificates.header(certificate));
        assertThat(result.getResponse().getStatus()).isEqualTo(200);
        String redirectUri = objectMapper.readTree(result.getResponse().getContentAsString())
                .path("redirect_uri").asText();
        String code = UriComponentsBuilder.fromUriString(redirectUri).build().getQueryParams().getFirst("code");
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
        String codeVerifier = UUID.randomUUID() + "-" + UUID.randomUUID();
        String state = "state-" + UUID.randomUUID();
        MvcResult result = mockMvc.perform(get("/oidc/authorize")
                        .with(host(HOST))
                        .param("response_type", "code")
                        .param("client_id", CLIENT_ID)
                        .param("redirect_uri", REDIRECT_URI)
                        .param("scope", scope)
                        .param("state", state)
                        .param("nonce", "nonce-" + UUID.randomUUID())
                        .param("code_challenge", challenge(codeVerifier))
                        .param("code_challenge_method", "S256"))
                .andReturn();
        String location = result.getResponse().getHeader(HttpHeaders.LOCATION);
        assertThat(location).as("authorization redirect").isNotNull();
        String loginState = UriComponentsBuilder.fromUriString(location).build().getQueryParams().getFirst("state");
        assertThat(loginState).as("login state in %s", location).isNotBlank();
        return new Login(loginState, codeVerifier);
    }

    private MvcResult certificateLogin(Login login, String certificateHeader) throws Exception {
        var request = post("/api/login/certificate")
                .with(certificatePort())
                .header(HttpHeaders.ORIGIN, LOGIN_ORIGIN)
                .contentType(MediaType.APPLICATION_JSON)
                .content(objectMapper.writeValueAsString(Map.of("state", login.state())));
        if (certificateHeader != null) {
            request.header(CertificatePortFilter.MTLS_CLIENT_CERT_HEADER, certificateHeader);
        }
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

    private static RequestPostProcessor certificatePort() {
        return request -> {
            host(CERTIFICATE_HOST).postProcessRequest(request);
            request.setLocalPort(8081);
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

    private record Login(String state, String codeVerifier) {
    }
}
