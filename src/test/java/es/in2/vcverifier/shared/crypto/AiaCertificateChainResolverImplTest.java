package es.in2.vcverifier.shared.crypto;

import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.config.CacheStore;
import es.in2.vcverifier.shared.domain.exception.CertificateChainValidationException;
import es.in2.vcverifier.shared.domain.exception.FailedCommunicationException;
import es.in2.vcverifier.shared.domain.exception.SsrfProtectionException;
import es.in2.vcverifier.shared.domain.util.SafeUrlValidator;
import org.bouncycastle.asn1.x509.AccessDescription;
import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.X509ObjectIdentifiers;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.security.auth.x500.X500Principal;
import java.io.IOException;
import java.math.BigInteger;
import java.net.http.HttpClient;
import java.net.http.HttpHeaders;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.NoSuchElementException;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class AiaCertificateChainResolverImplTest {

    private static final String AIA_URL = "http://ca.example.com/issuer.crt";

    @Mock private HttpClient httpClient;
    @Mock private SafeUrlValidator safeUrlValidator;
    @Mock private BackendConfig backendConfig;
    @Mock private CacheStore<List<X509Certificate>> aiaCertCacheStore;
    @Mock private HttpResponse<byte[]> httpResponse;

    @InjectMocks
    private AiaCertificateChainResolverImpl resolver;

    @BeforeAll
    static void addBcProvider() {
        Security.addProvider(new BouncyCastleProvider());
    }

    // ── Cert helpers ────────────────────────────────────────────────────────

    private static KeyPair generateEc() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC", "BC");
        gen.initialize(256);
        return gen.generateKeyPair();
    }

    private static X509Certificate buildCert(
            KeyPair subjectKp, String subjectDn,
            KeyPair issuerKp, String issuerDn,
            boolean isCA) throws Exception {
        return buildCert(subjectKp, subjectDn, issuerKp, issuerDn, isCA, null);
    }

    private static X509Certificate buildCert(
            KeyPair subjectKp, String subjectDn,
            KeyPair issuerKp, String issuerDn,
            boolean isCA,
            String caIssuersUrl) throws Exception {

        Date notBefore = new Date(System.currentTimeMillis() - 86_400_000L);
        Date notAfter  = new Date(System.currentTimeMillis() + 365L * 86_400_000L);

        ContentSigner signer = new JcaContentSignerBuilder("SHA256WithECDSA")
                .setProvider("BC").build(issuerKp.getPrivate());

        JcaX509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                new X500Principal(issuerDn),
                BigInteger.valueOf(System.nanoTime()),
                notBefore, notAfter,
                new X500Principal(subjectDn),
                subjectKp.getPublic());

        builder.addExtension(Extension.basicConstraints, true, new BasicConstraints(isCA));

        if (caIssuersUrl != null) {
            GeneralName gn = new GeneralName(GeneralName.uniformResourceIdentifier, caIssuersUrl);
            AccessDescription ad = new AccessDescription(X509ObjectIdentifiers.id_ad_caIssuers, gn);
            builder.addExtension(Extension.authorityInfoAccess, false, new AuthorityInformationAccess(ad));
        }

        X509CertificateHolder holder = builder.build(signer);
        return new JcaX509CertificateConverter().setProvider("BC").getCertificate(holder);
    }

    // Typed send stub to avoid generic type-erasure issues with Mockito
    @SuppressWarnings("unchecked")
    private void stubSend(HttpResponse<byte[]> response) throws Exception {
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(response);
    }

    @SuppressWarnings("unchecked")
    private void stubSendSequence(HttpResponse<byte[]>... responses) throws Exception {
        var stub = when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)));
        for (HttpResponse<byte[]> r : responses) {
            stub = stub.thenReturn(r);
        }
    }

    // ── Tests ────────────────────────────────────────────────────────────────

    @Test
    @DisplayName("Leaf with AIA → single root fetched → chain completed")
    void completeChain_leafWithAia_fetchesRoot() throws Exception {
        KeyPair rootKp = generateEc();
        KeyPair leafKp = generateEc();
        X509Certificate root = buildCert(rootKp, "CN=Root CA", rootKp, "CN=Root CA", true);
        X509Certificate leaf = buildCert(leafKp, "CN=Leaf", rootKp, "CN=Root CA", false, AIA_URL);

        when(backendConfig.isAiaChasingEnabled()).thenReturn(true);
        when(aiaCertCacheStore.get(AIA_URL)).thenThrow(NoSuchElementException.class);
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn(root.getEncoded());
        stubSend(httpResponse);

        List<X509Certificate> result = resolver.completeChain(List.of(leaf));

        assertThat(result).containsExactly(leaf, root);
        verify(safeUrlValidator).validate(AIA_URL);
    }

    @Test
    @DisplayName("Two-hop chase: leaf→intermediate (AIA)→root (AIA)")
    @SuppressWarnings("unchecked")
    void completeChain_twoHop_fetchesIntermediateAndRoot() throws Exception {
        KeyPair rootKp  = generateEc();
        KeyPair intKp   = generateEc();
        KeyPair leafKp  = generateEc();

        String intUrl  = "http://ca.example.com/intermediate.crt";
        String rootUrl = "http://ca.example.com/root.crt";

        X509Certificate root         = buildCert(rootKp, "CN=Root CA", rootKp, "CN=Root CA", true);
        X509Certificate intermediate = buildCert(intKp,  "CN=Int CA",  rootKp, "CN=Root CA", true,  rootUrl);
        X509Certificate leaf         = buildCert(leafKp, "CN=Leaf",    intKp,  "CN=Int CA",  false, intUrl);

        when(backendConfig.isAiaChasingEnabled()).thenReturn(true);
        when(aiaCertCacheStore.get(intUrl)).thenThrow(NoSuchElementException.class);
        when(aiaCertCacheStore.get(rootUrl)).thenThrow(NoSuchElementException.class);

        HttpResponse<byte[]> intResp  = mock(HttpResponse.class);
        HttpResponse<byte[]> rootResp = mock(HttpResponse.class);
        when(intResp.statusCode()).thenReturn(200);
        when(intResp.body()).thenReturn(intermediate.getEncoded());
        when(rootResp.statusCode()).thenReturn(200);
        when(rootResp.body()).thenReturn(root.getEncoded());
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(intResp)
                .thenReturn(rootResp);

        List<X509Certificate> result = resolver.completeChain(List.of(leaf));

        assertThat(result).containsExactly(leaf, intermediate, root);
        verify(safeUrlValidator).validate(intUrl);
        verify(safeUrlValidator).validate(rootUrl);
    }

    @Test
    @DisplayName("Leaf already self-signed → no fetch, returns input")
    void completeChain_leafSelfSigned_noFetch() throws Exception {
        KeyPair kp = generateEc();
        X509Certificate selfSigned = buildCert(kp, "CN=Root", kp, "CN=Root", true);

        when(backendConfig.isAiaChasingEnabled()).thenReturn(true);

        List<X509Certificate> result = resolver.completeChain(List.of(selfSigned));

        assertThat(result).containsExactly(selfSigned);
        verifyNoInteractions(httpClient, safeUrlValidator);
    }

    @Test
    @DisplayName("Leaf with no AIA extension → returns input unchanged")
    void completeChain_noAia_returnsUnchanged() throws Exception {
        KeyPair rootKp = generateEc();
        KeyPair leafKp = generateEc();
        X509Certificate leaf = buildCert(leafKp, "CN=Leaf", rootKp, "CN=Root CA", false);

        when(backendConfig.isAiaChasingEnabled()).thenReturn(true);

        List<X509Certificate> result = resolver.completeChain(List.of(leaf));

        assertThat(result).containsExactly(leaf);
        verifyNoInteractions(httpClient, safeUrlValidator);
    }

    @Test
    @DisplayName("Fetched cert subject does not match top issuer → stops, returns partial chain")
    void completeChain_fetchedSubjectMismatch_stopsChasing() throws Exception {
        KeyPair rootKp  = generateEc();
        KeyPair wrongKp = generateEc();
        KeyPair leafKp  = generateEc();
        X509Certificate wrongCert = buildCert(wrongKp, "CN=Wrong CA", wrongKp, "CN=Wrong CA", true);
        X509Certificate leaf      = buildCert(leafKp, "CN=Leaf", rootKp, "CN=Root CA", false, AIA_URL);

        when(backendConfig.isAiaChasingEnabled()).thenReturn(true);
        when(aiaCertCacheStore.get(AIA_URL)).thenThrow(NoSuchElementException.class);
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn(wrongCert.getEncoded());
        stubSend(httpResponse);

        List<X509Certificate> result = resolver.completeChain(List.of(leaf));

        assertThat(result).containsExactly(leaf);
    }

    @Test
    @DisplayName("AIA cycle detected → terminates without infinite loop")
    @SuppressWarnings("unchecked")
    void completeChain_aiaCycle_terminates() throws Exception {
        KeyPair rootKp = generateEc();
        KeyPair leafKp = generateEc();
        X509Certificate root = buildCert(rootKp, "CN=Root CA", rootKp, "CN=Root CA", true, AIA_URL);
        X509Certificate leaf = buildCert(leafKp, "CN=Leaf", rootKp, "CN=Root CA", false, AIA_URL);

        when(backendConfig.isAiaChasingEnabled()).thenReturn(true);
        when(aiaCertCacheStore.get(AIA_URL)).thenThrow(NoSuchElementException.class);
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn(root.getEncoded());
        stubSend(httpResponse);

        List<X509Certificate> result = resolver.completeChain(List.of(leaf));

        assertThat(result).hasSize(2);
        verify(httpClient, atMostOnce()).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    @DisplayName("Fetch returns 404 → FailedCommunicationException")
    void completeChain_fetch404_throwsFailedCommunication() throws Exception {
        KeyPair rootKp = generateEc();
        KeyPair leafKp = generateEc();
        X509Certificate leaf = buildCert(leafKp, "CN=Leaf", rootKp, "CN=Root CA", false, AIA_URL);

        when(backendConfig.isAiaChasingEnabled()).thenReturn(true);
        when(aiaCertCacheStore.get(AIA_URL)).thenThrow(NoSuchElementException.class);
        when(httpResponse.statusCode()).thenReturn(404);
        stubSend(httpResponse);

        assertThatThrownBy(() -> resolver.completeChain(List.of(leaf)))
                .isInstanceOf(FailedCommunicationException.class)
                .hasMessageContaining(AIA_URL);
    }

    @Test
    @DisplayName("Fetch returns 500 → FailedCommunicationException")
    void completeChain_fetch500_throwsFailedCommunication() throws Exception {
        KeyPair rootKp = generateEc();
        KeyPair leafKp = generateEc();
        X509Certificate leaf = buildCert(leafKp, "CN=Leaf", rootKp, "CN=Root CA", false, AIA_URL);

        when(backendConfig.isAiaChasingEnabled()).thenReturn(true);
        when(aiaCertCacheStore.get(AIA_URL)).thenThrow(NoSuchElementException.class);
        when(httpResponse.statusCode()).thenReturn(500);
        stubSend(httpResponse);

        assertThatThrownBy(() -> resolver.completeChain(List.of(leaf)))
                .isInstanceOf(FailedCommunicationException.class);
    }

    @Test
    @DisplayName("SafeUrlValidator throws SsrfProtectionException → propagates, no fetch")
    void completeChain_ssrfRejected_propagates() throws Exception {
        KeyPair rootKp = generateEc();
        KeyPair leafKp = generateEc();
        X509Certificate leaf = buildCert(leafKp, "CN=Leaf", rootKp, "CN=Root CA", false, AIA_URL);

        when(backendConfig.isAiaChasingEnabled()).thenReturn(true);
        doThrow(new SsrfProtectionException("blocked")).when(safeUrlValidator).validate(AIA_URL);

        assertThatThrownBy(() -> resolver.completeChain(List.of(leaf)))
                .isInstanceOf(SsrfProtectionException.class);
        verifyNoInteractions(httpClient);
    }

    @Test
    @DisplayName("Unparseable response body → CertificateChainValidationException")
    void completeChain_unparseableBody_throwsCertificateChainValidation() throws Exception {
        KeyPair rootKp = generateEc();
        KeyPair leafKp = generateEc();
        X509Certificate leaf = buildCert(leafKp, "CN=Leaf", rootKp, "CN=Root CA", false, AIA_URL);

        when(backendConfig.isAiaChasingEnabled()).thenReturn(true);
        when(aiaCertCacheStore.get(AIA_URL)).thenThrow(NoSuchElementException.class);
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn("not-a-cert".getBytes());
        stubSend(httpResponse);

        assertThatThrownBy(() -> resolver.completeChain(List.of(leaf)))
                .isInstanceOf(CertificateChainValidationException.class);
    }

    @Test
    @DisplayName("Fetch throws IOException → FailedCommunicationException")
    @SuppressWarnings("unchecked")
    void completeChain_fetchIOException_throwsFailedCommunication() throws Exception {
        KeyPair rootKp = generateEc();
        KeyPair leafKp = generateEc();
        X509Certificate leaf = buildCert(leafKp, "CN=Leaf", rootKp, "CN=Root CA", false, AIA_URL);

        when(backendConfig.isAiaChasingEnabled()).thenReturn(true);
        when(aiaCertCacheStore.get(AIA_URL)).thenThrow(NoSuchElementException.class);
        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenThrow(new IOException("connection refused"));

        assertThatThrownBy(() -> resolver.completeChain(List.of(leaf)))
                .isInstanceOf(FailedCommunicationException.class)
                .hasMessageContaining(AIA_URL);
    }

    @Test
    @DisplayName("AIA chasing disabled → returns input unchanged, no fetch")
    void completeChain_aiaChasingDisabled_returnsUnchanged() throws Exception {
        KeyPair rootKp = generateEc();
        KeyPair leafKp = generateEc();
        X509Certificate leaf = buildCert(leafKp, "CN=Leaf", rootKp, "CN=Root CA", false, AIA_URL);

        when(backendConfig.isAiaChasingEnabled()).thenReturn(false);

        List<X509Certificate> result = resolver.completeChain(List.of(leaf));

        assertThat(result).containsExactly(leaf);
        verifyNoInteractions(httpClient, safeUrlValidator, aiaCertCacheStore);
    }

    @Test
    @DisplayName("Cache hit on second call → no additional HTTP request")
    @SuppressWarnings("unchecked")
    void completeChain_cacheHit_noSecondFetch() throws Exception {
        KeyPair rootKp = generateEc();
        KeyPair leafKp = generateEc();
        X509Certificate root = buildCert(rootKp, "CN=Root CA", rootKp, "CN=Root CA", true);
        X509Certificate leaf = buildCert(leafKp, "CN=Leaf", rootKp, "CN=Root CA", false, AIA_URL);

        when(backendConfig.isAiaChasingEnabled()).thenReturn(true);
        when(aiaCertCacheStore.get(AIA_URL))
                .thenThrow(NoSuchElementException.class)
                .thenReturn(List.of(root));
        when(httpResponse.statusCode()).thenReturn(200);
        when(httpResponse.body()).thenReturn(root.getEncoded());
        stubSend(httpResponse);

        resolver.completeChain(List.of(leaf)); // first call — cache miss → fetch
        resolver.completeChain(List.of(leaf)); // second call — cache hit

        verify(httpClient, times(1)).send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class));
    }

    @Test
    @DisplayName("AIA URL returns 301 → follows redirect with SSRF check on Location")
    @SuppressWarnings("unchecked")
    void completeChain_aiaRedirect_followsWithSsrfCheck() throws Exception {
        String redirectUrl = "http://cdn.example.com/issuer.crt";

        KeyPair rootKp = generateEc();
        KeyPair leafKp = generateEc();
        X509Certificate root = buildCert(rootKp, "CN=Root CA", rootKp, "CN=Root CA", true);
        X509Certificate leaf = buildCert(leafKp, "CN=Leaf", rootKp, "CN=Root CA", false, AIA_URL);

        when(backendConfig.isAiaChasingEnabled()).thenReturn(true);
        when(aiaCertCacheStore.get(AIA_URL)).thenThrow(NoSuchElementException.class);

        HttpResponse<byte[]> redirectResponse = mock(HttpResponse.class);
        when(redirectResponse.statusCode()).thenReturn(301);
        when(redirectResponse.headers()).thenReturn(
                HttpHeaders.of(Map.of("Location", List.of(redirectUrl)), (a, b) -> true));

        HttpResponse<byte[]> finalResponse = mock(HttpResponse.class);
        when(finalResponse.statusCode()).thenReturn(200);
        when(finalResponse.body()).thenReturn(root.getEncoded());

        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(redirectResponse)
                .thenReturn(finalResponse);

        List<X509Certificate> result = resolver.completeChain(List.of(leaf));

        assertThat(result).containsExactly(leaf, root);
        verify(safeUrlValidator).validate(AIA_URL);
        verify(safeUrlValidator).validate(redirectUrl);
    }

    @Test
    @DisplayName("Too many redirects → FailedCommunicationException")
    @SuppressWarnings("unchecked")
    void completeChain_tooManyRedirects_throwsFailedCommunication() throws Exception {
        KeyPair rootKp = generateEc();
        KeyPair leafKp = generateEc();
        X509Certificate leaf = buildCert(leafKp, "CN=Leaf", rootKp, "CN=Root CA", false, AIA_URL);

        when(backendConfig.isAiaChasingEnabled()).thenReturn(true);
        when(aiaCertCacheStore.get(AIA_URL)).thenThrow(NoSuchElementException.class);

        HttpResponse<byte[]> redirectResponse = mock(HttpResponse.class);
        when(redirectResponse.statusCode()).thenReturn(301);
        when(redirectResponse.headers()).thenReturn(
                HttpHeaders.of(Map.of("Location", List.of("http://redirect.example.com/issuer.crt")), (a, b) -> true));

        when(httpClient.send(any(HttpRequest.class), any(HttpResponse.BodyHandler.class)))
                .thenReturn(redirectResponse);

        assertThatThrownBy(() -> resolver.completeChain(List.of(leaf)))
                .isInstanceOf(FailedCommunicationException.class)
                .hasMessageContaining("Too many redirects");
    }

    @Test
    @DisplayName("Null chain → returns null without errors")
    void completeChain_null_returnsNull() {
        when(backendConfig.isAiaChasingEnabled()).thenReturn(true);
        assertThat(resolver.completeChain(null)).isNull();
    }

    @Test
    @DisplayName("Empty chain → returns empty list without errors")
    void completeChain_empty_returnsEmpty() {
        when(backendConfig.isAiaChasingEnabled()).thenReturn(true);
        assertThat(resolver.completeChain(List.of())).isEmpty();
    }
}
