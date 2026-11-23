package es.in2.vcverifier.verifier.infrastructure.adapter.trustframework;

import es.in2.vcverifier.verifier.domain.exception.IssuerNotAuthorizedException;
import es.in2.vcverifier.verifier.domain.model.issuer.IssuerCredentialsCapabilities;
import es.in2.vcverifier.verifier.domain.service.TrustedIssuersProvider;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.beans.factory.ObjectProvider;

import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class TrustFrameworkServiceImpTest {

    @Mock
    private ObjectProvider<TrustedIssuersProvider> providerRef;

    @Mock
    private TrustedIssuersProvider trustedIssuersProvider;

    private TrustFrameworkServiceImpl trustFrameworkService;

    @BeforeEach
    void setUp() {
        trustFrameworkService = new TrustFrameworkServiceImpl(providerRef);
    }

    @Test
    void shouldReturnListOfIssuerCredentialsCapabilities_whenProviderReturnsData() {
        String id = "issuer-id";
        List<IssuerCredentialsCapabilities> expectedCapabilities = List.of(
                IssuerCredentialsCapabilities.builder()
                        .credentialsType("SomeType")
                        .build()
        );
        when(providerRef.getIfAvailable()).thenReturn(trustedIssuersProvider);
        when(trustedIssuersProvider.getIssuerCapabilities(id)).thenReturn(expectedCapabilities);

        List<IssuerCredentialsCapabilities> result = trustFrameworkService.getTrustedIssuerListData(id);

        assertEquals(1, result.size());
        assertEquals("SomeType", result.get(0).credentialsType());
        verify(trustedIssuersProvider).getIssuerCapabilities(id);
    }

    @Test
    void shouldReturnEmptyList_whenProviderReturnsEmpty() {
        when(providerRef.getIfAvailable()).thenReturn(trustedIssuersProvider);
        when(trustedIssuersProvider.getIssuerCapabilities("unknown")).thenReturn(List.of());

        List<IssuerCredentialsCapabilities> result = trustFrameworkService.getTrustedIssuerListData("unknown");

        assertTrue(result.isEmpty());
    }

    @Test
    void getTrustedIssuerListData_withoutConfiguredList_throwsIssuerNotAuthorized() {
        when(providerRef.getIfAvailable()).thenReturn(null);

        assertThrows(IssuerNotAuthorizedException.class,
                () -> trustFrameworkService.getTrustedIssuerListData("issuer-id"));
    }
}
