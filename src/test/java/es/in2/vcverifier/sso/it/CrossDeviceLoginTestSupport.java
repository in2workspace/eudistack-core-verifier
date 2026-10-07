package es.in2.vcverifier.sso.it;

import com.fasterxml.jackson.databind.JsonNode;
import es.in2.vcverifier.oauth2.infrastructure.adapter.SseEmitterStore;
import es.in2.vcverifier.verifier.domain.model.AuthResponseResult;
import jakarta.servlet.http.Cookie;
import org.mockito.ArgumentCaptor;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.ResultActions;
import org.springframework.test.web.servlet.request.MockHttpServletRequestBuilder;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;

import java.util.function.UnaryOperator;

import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.atLeastOnce;
import static org.mockito.Mockito.verify;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;

/**
 * EUD-252 test support for SSO ITs that stub {@code AuthorizationResponseProcessorService}: since
 * the wallet POST no longer sets the SSO cookie, establishing a session means following the
 * one-time close URL the browser receives over SSE, carrying its {@code __Host-sso-tx} cookie.
 */
public final class CrossDeviceLoginTestSupport {

    /** A well-formed browser-binding value (43 chars, base64url alphabet). */
    public static final String BINDING_VALUE = "itBrowserBindingValue0123456789abcdefghijkl";
    public static final String RP_REDIRECT_URI = "https://localhost/callback";

    private CrossDeviceLoginTestSupport() {
    }

    /** What a successful VP verification returns for a login bound to a browser at /authorize. */
    public static AuthResponseResult boundResult(JsonNode credentialJson, String state, String bindingHash) {
        return new AuthResponseResult(credentialJson, RP_REDIRECT_URI + "?code=it-code&state=" + state,
                RP_REDIRECT_URI, state, "clientA", "it-code", bindingHash, "https://localhost");
    }

    public static Cookie bindingCookie() {
        return new Cookie("__Host-sso-tx", BINDING_VALUE);
    }

    /** The URL the browser received over SSE for {@code state}. */
    public static String sseUrlFor(SseEmitterStore sseEmitterStore, String state) {
        ArgumentCaptor<String> url = ArgumentCaptor.forClass(String.class);
        verify(sseEmitterStore, atLeastOnce()).send(eq(state), url.capture());
        return url.getValue();
    }

    /** The browser follows the close URL it received over SSE, carrying its binding cookie. */
    public static ResultActions closeInBrowser(MockMvc mockMvc, SseEmitterStore sseEmitterStore, String state,
                                        UnaryOperator<MockHttpServletRequestBuilder> customizer) throws Exception {
        UriComponents close = UriComponentsBuilder.fromUriString(sseUrlFor(sseEmitterStore, state)).build();
        MockHttpServletRequestBuilder request = get(close.getPath())
                .param("h", close.getQueryParams().getFirst("h"))
                .cookie(bindingCookie());
        return mockMvc.perform(customizer.apply(request));
    }
}
