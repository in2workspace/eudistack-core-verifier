package es.in2.vcverifier.verifier.infrastructure.adapter;

import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.shared.crypto.DIDService;
import es.in2.vcverifier.shared.crypto.JWTService;
import es.in2.vcverifier.verifier.domain.exception.InvalidScopeException;
import es.in2.vcverifier.verifier.domain.exception.InvalidVPtokenException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;

import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.util.Map;

/**
 * Validates VP signature (PoP) and cryptographic binding between VP holder and VC subject
 * via cnf.jwk thumbprint comparison (RFC 7638).
 */
@Slf4j
@Service
@RequiredArgsConstructor
public class CryptographicBindingValidator {

    private final JWTService jwtService;
    private final DIDService didService;

    /**
     * Verifies the VP signature and returns the signer's EC public key.
     * Tries embedded JWK first; falls back to DID resolution from kid/iss/sub.
     *
     * @param verifiablePresentation the raw VP JWT string
     * @param vpJwt                  the parsed VP JWT
     * @return the EC public key of the VP signer
     */
    public ECPublicKey validateVpSignature(String verifiablePresentation, SignedJWT vpJwt) {
        // Strategy 1: Embedded JWK in VP header
        ECKey vpHeaderJwk = extractJwkFromHeader(vpJwt);
        if (vpHeaderJwk != null) {
            log.info("[BIND] VP signed with embedded JWK (kid={})", vpHeaderJwk.getKeyID());
            ECPublicKey signerKey;
            try {
                signerKey = vpHeaderJwk.toECPublicKey();
            } catch (JOSEException e) {
                throw new InvalidVPtokenException("Cannot extract EC public key from VP header JWK");
            }
            jwtService.verifyJWTWithECKey(verifiablePresentation, signerKey);
            log.info("VP signature verified via embedded JWK");
            return signerKey;
        }

        // Strategy 2: Legacy DID resolution from kid/iss/sub
        String vpKid = vpJwt.getHeader().getKeyID();
        String vpIss;
        String vpSub;
        try {
            var claims = vpJwt.getJWTClaimsSet();
            vpIss = claims.getIssuer();
            vpSub = claims.getSubject();
        } catch (Exception e) {
            throw new InvalidVPtokenException("Cannot read vp_token claims");
        }

        String holderDid = normalizeDid(extractDidFromKidIssSub(vpKid, vpIss, vpSub));
        if (holderDid == null || holderDid.isBlank()) {
            throw new InvalidScopeException("Cannot extract holder identity from VP (no jwk header and no DID in kid/iss/sub)");
        }

        log.info("[BIND] VP holder DID resolved as {}", holderDid);
        PublicKey holderPublicKey = didService.resolvePublicKeyFromDid(holderDid);

        if (!(holderPublicKey instanceof ECPublicKey ecPub)) {
            throw new InvalidVPtokenException("Resolved DID public key is not an EC public key");
        }

        jwtService.verifyJWTWithECKey(verifiablePresentation, ecPub);
        log.info("VP signature verified via DID resolution (legacy)");

        return ecPub;
    }

    /**
     * Validates cryptographic binding between the VP signer and the VC subject
     * via cnf.jwk thumbprint comparison (RFC 7638 / RFC 7800).
     *
     * @param vpSignerKey   the EC public key of the VP signer
     * @param jwtCredential the parsed VC JWT
     */
    public void validateCryptographicBinding(ECPublicKey vpSignerKey, SignedJWT jwtCredential) {
        ECKey vcCnfJwk = extractCnfJwkFromVc(jwtCredential);
        if (vcCnfJwk == null) {
            throw new InvalidScopeException("Credential missing cnf.jwk — cannot validate cryptographic binding");
        }
        if (vpSignerKey == null) {
            throw new InvalidScopeException("Cannot extract VP signer key — cannot validate cryptographic binding");
        }
        validateBindingByJwkThumbprint(vpSignerKey, vcCnfJwk);
    }

    String normalizeDid(String did) {
        if (did == null) return null;
        if (!did.startsWith("did:")) return did;
        return did.contains("#") ? did.substring(0, did.indexOf('#')) : did;
    }

    private ECKey extractJwkFromHeader(SignedJWT signedJwt) {
        var jwk = signedJwt.getHeader().getJWK();
        if (jwk instanceof ECKey ecKey) {
            return ecKey;
        }
        return null;
    }

    private String extractDidFromKidIssSub(String kid, String iss, String sub) {
        if (kid != null && kid.startsWith("did:")) {
            return kid.contains("#") ? kid.substring(0, kid.indexOf('#')) : kid;
        }
        if (iss != null && iss.startsWith("did:")) return iss;
        if (sub != null && sub.startsWith("did:")) return sub;
        return null;
    }

    @SuppressWarnings("unchecked")
    private ECKey extractCnfJwkFromVc(SignedJWT vcJwt) {
        try {
            Map<String, Object> cnf = (Map<String, Object>) vcJwt.getJWTClaimsSet().getClaim("cnf");
            if (cnf == null) return null;

            Map<String, Object> jwk = (Map<String, Object>) cnf.get("jwk");
            if (jwk == null) return null;

            return ECKey.parse(jwk);
        } catch (Exception e) {
            log.warn("Failed to extract cnf.jwk from VC: {}", e.getMessage());
            return null;
        }
    }

    private void validateBindingByJwkThumbprint(ECPublicKey vpSignerKey, ECKey vcCnfJwk) {
        try {
            ECKey vpSignerEcKey = new ECKey.Builder(Curve.P_256, vpSignerKey).build();
            String vpThumbprint = vpSignerEcKey.computeThumbprint().toString();
            String vcThumbprint = vcCnfJwk.computeThumbprint().toString();

            log.debug("[BIND] VP signer thumbprint: {}", vpThumbprint);
            log.debug("[BIND] VC cnf.jwk thumbprint: {}", vcThumbprint);

            if (!vpThumbprint.equals(vcThumbprint)) {
                throw new InvalidScopeException(
                        "Cryptographic binding mismatch: VP signer JWK Thumbprint (" + vpThumbprint +
                        ") != VC cnf.jwk Thumbprint (" + vcThumbprint + ")"
                );
            }
            log.info("Cryptographic binding validated via JWK Thumbprint (RFC 7638)");
        } catch (InvalidScopeException e) {
            throw e;
        } catch (JOSEException e) {
            throw new InvalidScopeException("Failed to compute JWK Thumbprint for binding validation: " + e.getMessage());
        }
    }

}
