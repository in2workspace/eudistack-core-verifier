package es.in2.vcverifier.verifier.infrastructure.controller;

import es.in2.vcverifier.shared.domain.model.CustomJWK;
import es.in2.vcverifier.shared.domain.model.CustomJWKS;
import es.in2.vcverifier.shared.crypto.DIDService;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;
import io.swagger.v3.oas.annotations.media.Content;
import io.swagger.v3.oas.annotations.media.Schema;
import io.swagger.v3.oas.annotations.responses.ApiResponse;
import io.swagger.v3.oas.annotations.tags.Tag;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.http.HttpStatus;
import org.springframework.web.bind.annotation.*;

import java.math.BigInteger;
import java.security.PublicKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.util.Base64;
import java.util.List;

@Slf4j
@RestController
@RequestMapping("/oidc/did")
@RequiredArgsConstructor
@Tag(name = "DID Resolution", description = "DID to JWK resolution")
public class ResolverController {

    private final DIDService didService;

    @Operation(
            summary = "Resolve DID to JWKS",
            description = "Resolves a DID identifier to its JSON Web Key Set")
    @ApiResponse(responseCode = "200", description = "JWKS for the DID",
            content = @Content(mediaType = "application/json",
                    schema = @Schema(implementation = CustomJWKS.class)))
    @ApiResponse(responseCode = "404", description = "DID not found")
    @GetMapping("/{id}")
    @ResponseStatus(HttpStatus.OK)
    public CustomJWKS resolveDid(
            @Parameter(description = "DID identifier to resolve", required = true)
            @PathVariable String id) {
        PublicKey publicKey = didService.resolvePublicKeyFromDid(id);
        ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
        ECPoint point = ecPublicKey.getW();

        // Normalize to 32 bytes
        byte[] xFixed = bigIntegerTo32Bytes(point.getAffineX());
        byte[] yFixed = bigIntegerTo32Bytes(point.getAffineY());

        CustomJWKS customJWKS = CustomJWKS.builder()
                .keys(List.of(CustomJWK.builder()
                        .kty("EC")
                        .crv("P-256")
                        .kid(id)
                        .x(Base64.getUrlEncoder().withoutPadding().encodeToString(xFixed))
                        .y(Base64.getUrlEncoder().withoutPadding().encodeToString(yFixed))
                        .build()
                ))
                .build();

        log.info("Resolved DID {} to JWK {}", id, customJWKS);
        return customJWKS;
    }

    /**
     * Converts a BigInteger to a fixed-length byte array (32 bytes) for the P-256 curve.
     */
    private byte[] bigIntegerTo32Bytes(BigInteger value) {
        byte[] temp = value.toByteArray();

        // If it's exactly 32 bytes, return it as is
        if (temp.length == 32) {
            return temp;
        }
        // If it's 33 bytes and the first byte is 0, remove that extra byte
        else if (temp.length == 33 && temp[0] == 0) {
            byte[] result = new byte[32];
            System.arraycopy(temp, 1, result, 0, 32);
            return result;
        }
        // If it's less than 32 bytes, pad with leading zeros
        else if (temp.length < 32) {
            byte[] result = new byte[32];
            System.arraycopy(temp, 0, result, 32 - temp.length, temp.length);
            return result;
        }

        // Otherwise, it's too large for a P-256 coordinate
        throw new IllegalArgumentException("ECPublicKey coordinate is too long (" + temp.length + " bytes)");
    }
}
