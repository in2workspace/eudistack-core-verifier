package es.in2.vcverifier.shared.domain.util;

import org.junit.jupiter.api.Test;

import static org.assertj.core.api.Assertions.assertThat;

class AuthorizationResponseUriTest {

    private static final String ISSUER = "https://tenant-a.example.com/verifier";
    private static final String ISS_PARAM = "iss=https%3A%2F%2Ftenant-a.example.com%2Fverifier";

    @Test
    void success_addsCodeStateAndIss() {
        // When
        String url = AuthorizationResponseUri.success("https://rp.example.com/cb", "c-1", "st", ISSUER);

        // Then
        assertThat(url).isEqualTo("https://rp.example.com/cb?code=c-1&state=st&" + ISS_PARAM);
    }

    @Test
    void success_redirectUriWithQuery_keepsItsParamsAndEncodingUntouched() {
        // Given: registered redirect_uri with its own (already encoded) query
        String redirectUri = "https://rp.example.com/cb?tenant=a&next=%2Fhome%3Fx%3D1";

        // When
        String url = AuthorizationResponseUri.success(redirectUri, "c-1", "st", ISSUER);

        // Then
        assertThat(url).isEqualTo(redirectUri + "&code=c-1&state=st&" + ISS_PARAM);
    }

    @Test
    void error_formEncodesStateAndDescription() {
        // When
        String url = AuthorizationResponseUri.error("https://rp.example.com/cb", "invalid_request",
                "max_age must be a non-negative integer", "a b&c=d+e", ISSUER);

        // Then
        assertThat(url).isEqualTo("https://rp.example.com/cb?error=invalid_request"
                + "&error_description=max_age+must+be+a+non-negative+integer"
                + "&state=a+b%26c%3Dd%2Be&" + ISS_PARAM);
    }

    @Test
    void error_blankStateAndDescription_areOmitted() {
        // When
        String url = AuthorizationResponseUri.error("https://rp.example.com/cb", "access_denied", null, " ", ISSUER);

        // Then
        assertThat(url).isEqualTo("https://rp.example.com/cb?error=access_denied&" + ISS_PARAM);
    }
}
