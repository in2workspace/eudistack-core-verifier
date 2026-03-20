package es.in2.vcverifier.shared.crypto;

import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jose.jwk.KeyUse;
import es.in2.vcverifier.shared.config.VerifierConfig;
import org.junit.jupiter.api.Test;

import java.security.KeyPairGenerator;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

class CryptoComponentTest {

    @Test
    void getECKey_withConfiguredPrivateKey_buildsFromConfig() throws Exception {
        VerifierConfig verifierConfig = mock(VerifierConfig.class);
        when(verifierConfig.hasIdentityConfigured()).thenReturn(true);
        // A valid P-256 private key (hex)
        when(verifierConfig.getPrivateKey()).thenReturn("73e509a7681d4a395b1ced75681c4dc4020dbab02da868512276dd766733d5b5");
        when(verifierConfig.getDidKey()).thenReturn("did:key:zConfigured");

        CryptoComponent component = new CryptoComponent(verifierConfig);
        ECKey ecKey = component.getECKey();

        assertNotNull(ecKey);
        assertEquals(Curve.P_256, ecKey.getCurve());
        assertEquals("did:key:zConfigured", ecKey.getKeyID());
        assertEquals(KeyUse.SIGNATURE, ecKey.getKeyUse());
        assertNotNull(ecKey.toECPrivateKey());
        assertNotNull(ecKey.toECPublicKey());
    }

    @Test
    void getECKey_withConfiguredPrivateKeyButNoDidKey_derivesDidKey() {
        VerifierConfig verifierConfig = mock(VerifierConfig.class);
        when(verifierConfig.hasIdentityConfigured()).thenReturn(true);
        when(verifierConfig.getPrivateKey()).thenReturn("73e509a7681d4a395b1ced75681c4dc4020dbab02da868512276dd766733d5b5");
        when(verifierConfig.getDidKey()).thenReturn(null);

        CryptoComponent component = new CryptoComponent(verifierConfig);
        ECKey ecKey = component.getECKey();

        assertNotNull(ecKey);
        assertTrue(ecKey.getKeyID().startsWith("did:key:z"));
    }

    @Test
    void getECKey_withoutConfig_generatesEphemeral() {
        VerifierConfig verifierConfig = mock(VerifierConfig.class);
        when(verifierConfig.hasIdentityConfigured()).thenReturn(false);

        CryptoComponent component = new CryptoComponent(verifierConfig);
        ECKey ecKey = component.getECKey();

        assertNotNull(ecKey);
        assertEquals(Curve.P_256, ecKey.getCurve());
        assertTrue(ecKey.getKeyID().startsWith("did:key:z"));
        assertEquals(KeyUse.SIGNATURE, ecKey.getKeyUse());
    }

    @Test
    void getECKey_ephemeral_generatesUniqueKeysEachTime() {
        VerifierConfig verifierConfig = mock(VerifierConfig.class);
        when(verifierConfig.hasIdentityConfigured()).thenReturn(false);

        CryptoComponent component1 = new CryptoComponent(verifierConfig);
        CryptoComponent component2 = new CryptoComponent(verifierConfig);

        ECKey key1 = component1.getECKey();
        ECKey key2 = component2.getECKey();

        assertNotEquals(key1.getKeyID(), key2.getKeyID());
    }

    @Test
    void deriveDidKey_producesValidDidKeyFormat() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        ECPublicKey publicKey = (ECPublicKey) gen.generateKeyPair().getPublic();

        String didKey = CryptoComponent.deriveDidKey(publicKey);

        assertNotNull(didKey);
        assertTrue(didKey.startsWith("did:key:z"), "did:key must start with 'did:key:z', got: " + didKey);
        assertTrue(didKey.length() > 20, "did:key should be longer than 20 chars");
    }

    @Test
    void deriveDidKey_samePublicKey_sameResult() throws Exception {
        KeyPairGenerator gen = KeyPairGenerator.getInstance("EC");
        gen.initialize(new ECGenParameterSpec("secp256r1"));
        ECPublicKey publicKey = (ECPublicKey) gen.generateKeyPair().getPublic();

        String didKey1 = CryptoComponent.deriveDidKey(publicKey);
        String didKey2 = CryptoComponent.deriveDidKey(publicKey);

        assertEquals(didKey1, didKey2);
    }
}
