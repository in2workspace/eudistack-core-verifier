package es.in2.vcverifier.shared.domain.util;

import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;

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

    @Test
    void success_redirectUriWithQueryAndFragment_addsParamsToTheQueryAndKeepsTheFragmentLast() {
        // When
        String url = AuthorizationResponseUri.success("https://rp.example.com/cb?tenant=a#section/1?x=y",
                "c-1", "st", ISSUER);

        // Then
        assertThat(url).isEqualTo("https://rp.example.com/cb?tenant=a&code=c-1&state=st&" + ISS_PARAM
                + "#section/1?x=y");
    }

    @Test
    void error_nonAsciiAndReservedCharsInValues_areFormEncodedAsUtf8() {
        // When
        String url = AuthorizationResponseUri.error("https://rp.example.com/cb", "invalid_request",
                "a/b?c#d", "ñ€ /?#&=+%", ISSUER);

        // Then
        assertThat(url).isEqualTo("https://rp.example.com/cb?error=invalid_request"
                + "&error_description=a%2Fb%3Fc%23d"
                + "&state=%C3%B1%E2%82%AC+%2F%3F%23%26%3D%2B%25&" + ISS_PARAM);
    }

    @Test
    void success_normalisesSchemeEmptyPortAndEmptyPathSegments() {
        // When
        String url = AuthorizationResponseUri.success("HTTPS://RP.example.com://cb//x", "c-1", null, ISSUER);

        // Then: host case and the rest of the URI are kept as registered
        assertThat(url).isEqualTo("https://RP.example.com/cb/x?code=c-1&" + ISS_PARAM);
    }

    @Test
    void success_clientQueryWithRepeatedOrBareNames_isReSerializedGroupedByName() {
        // When
        String url = AuthorizationResponseUri.success("https://rp.example.com/cb?a=1&b&&a=2&c=&state=rp",
                "c-1", "st", ISSUER);

        // Then
        assertThat(url).isEqualTo("https://rp.example.com/cb?a=1&a=2&b&c=&state=rp&state=st&code=c-1&"
                + ISS_PARAM);
    }

    @Test
    void success_emptyFragment_isDropped() {
        assertThat(AuthorizationResponseUri.success("https://rp.example.com/cb#", "c-1", null, ISSUER))
                .isEqualTo("https://rp.example.com/cb?code=c-1&" + ISS_PARAM);
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "https://rp.example.com/c b",
            "https://rp.example.com/c{b}",
            "https://rp.example.com/c|b",
            "https://rp.example.com/café",
            "https://rp.example.com/cb?x=[1]",
            "https://rp.example.com/cb?x=%zz",
            "https://rp.example.com/cb#a#b",
            "urn:ietf:wg:oauth:2.0:oob"
    })
    void success_redirectUriThatCannotCarryAResponse_throwsIllegalArgumentException(String redirectUri) {
        assertThatThrownBy(() -> AuthorizationResponseUri.success(redirectUri, "c-1", "st", ISSUER))
                .isInstanceOf(IllegalArgumentException.class);
        assertThat(AuthorizationResponseUri.isUsable(redirectUri)).isFalse();
    }

    @ParameterizedTest
    @ValueSource(strings = {
            "https://rp.example.com/cb",
            "https://rp.example.com/cb?tenant=a&next=%2Fhome%3Fx%3D1",
            "https://rp.example.com:8443/c%20b#section",
            "http://127.0.0.1:4200/callback",
            "com.example.app:/oauth2redirect"
    })
    void isUsable_redirectUriAResponseCanBeBuiltOn_isTrue(String redirectUri) {
        assertThat(AuthorizationResponseUri.isUsable(redirectUri)).isTrue();
    }

    @Test
    void isUsable_null_isFalse() {
        assertThat(AuthorizationResponseUri.isUsable(null)).isFalse();
    }
}
