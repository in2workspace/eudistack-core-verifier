package es.in2.vcverifier.oauth2.infrastructure.filter;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.nimbusds.jose.crypto.ECDSAVerifier;
import com.nimbusds.jose.jwk.ECKey;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import es.in2.vcverifier.shared.config.BackendConfig;
import es.in2.vcverifier.shared.crypto.CryptoComponent;
import es.in2.vcverifier.shared.crypto.JWTServiceImpl;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.security.oauth2.core.endpoint.OAuth2ParameterNames;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

/**
 * Issues real ES256-signed access tokens and id tokens for local manual testing.
 * The verifiable credential is provided as a signed JWT VC (the same format the
 * verifier consumes in production), and the credential payload is extracted from
 * its JWT payload following the same logic as JWTServiceImpl.extractVCFromPayload
 * (VCDM v2.0: credential IS the payload; v1.1: credential is under the "vc" claim).
 *
 * The resulting access/id tokens are signed with the verifier's EC key, mirror the
 * claims produced by TokenGenerationWorkflow + SchemaProfileClaimsExtractor in
 * production, are valid for 1 year and are written to target/local-tokens/*.txt.
 *
 * Fill in PRIVATE_KEY_HEX, DID_KEY, VERIFIER_URL and the two *_VC_JWT constants
 * before running.
 */
@ExtendWith(MockitoExtension.class)
class LocalTokenIssuanceTest {

    // --- Verifier identity (fill in with values from local config) ---
    private static final String PRIVATE_KEY_HEX = "9c67dbf892a1e2b59fb92817aedd70c7d24325e70e096bb120a276050eb4ddf";
    private static final String DID_KEY         = "did:key:zDnaevN85Z7VJgcBoQeqQU7d8kZpuVhDSdm8hQtJYWjvek3VL";
    private static final String VERIFIER_URL    = "https://verifier.dome-marketplace-lcl.org";

    // --- Signed JWT VCs (paste here the VC JWTs as issued by the trusted issuer) ---
    private static final String MACHINE_VC_JWT  = "eyJzaWdUIjoiMjAyNi0wNS0yN1QxNDoyMDozOS4zNzA0OTA4NjlaIiwieDVjIjpbIk1JSUZCVENDQSsyZ0F3SUJBZ0lVYlNQdUFEVVFCK3pIUG1FazlwUHlXaTQxbU1nd0RRWUpLb1pJaHZjTkFRRUxCUUF3Z1k4eEN6QUpCZ05WQkFZVEFrVlRNUjR3SEFZRFZRUUtEQlZCVEZSSlFTQkRUMDVUVlV4VVQxSkZVeXdnVTBFeEdEQVdCZ05WQkdFTUQxWkJWRVZUTFVFeE5UUTFOalU0TlRFeU1EQUdBMVVFQXd3cFFVeFVTVUVnUTA5T1UxVk1WRTlTUlZNc0lGTkJJQzBnVTJWc2JHOGdSV3hsWTNSeWIyNXBZMjh4RWpBUUJnTlZCQVVUQ1VFeE5UUTFOalU0TlRBZUZ3MHlOakF5TWpjeU1UUTNNelZhRncweU9EQXlNamN5TVRRM016VmFNSUdQTVFzd0NRWURWUVFHRXdKRlV6RWVNQndHQTFVRUNnd1ZRVXhVU1VFZ1EwOU9VMVZNVkU5U1JWTXNJRk5CTVJnd0ZnWURWUVJoREE5V1FWUkZVeTFCTVRVME5UWTFPRFV4TWpBd0JnTlZCQU1NS1VGTVZFbEJJRU5QVGxOVlRGUlBVa1ZUTENCVFFTQXRJRk5sYkd4dklFVnNaV04wY205dWFXTnZNUkl3RUFZRFZRUUZFd2xCTVRVME5UWTFPRFV3Z2dFaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRREZvTE9iMXAxVjkvZ2R3SXJkbUJtRHlVTlAwUFJKZDkwVW9HUVlmbmRldGxzZkkybTJSNTYyc05wZjBzenplT0FrMTBIVmtHQXA0MUliWXpjN09BdTJMN2daRElWcjlEQ3k1bm1lWjdYWjZ2dlpWSkpFbnZSQWJWekJORmk2WGtXdG85STRrSis1RldxMkhvc25VVkJ6SG1NUFp2SVBxcXpzbHlER0d4SStlNFNNWmd4cHA3cWZ2UjAvTGNTK1pWYXBzVVZrUXoxQWNPTkdtOGtpMjJEdlRGZlkvUnh6cUl1TDFSK0gwZDJiSGQxSGRGRVNvY216WitqUU4vUjl6My9aSGNLWEVIbkJwczZJZzFqREpJOVNJa0I5L3NWbWdpVTJsVlFIZWhvdFFVczh0Q3BoWUI0elR5a2FXakJrNXJQeHpkQU9MWjdKVElzOURiN3A3NnluQWdNQkFBR2pnZ0ZWTUlJQlVUQU1CZ05WSFJNQkFmOEVBakFBTUE0R0ExVWREd0VCL3dRRUF3SUd3REJBQmdOVkhTQUVPVEEzTURVR0J3UUFpK3hBQVFJd0tqQW9CZ2dyQmdFRkJRY0NBUlljYUhSMGNITTZMeTkzZDNjdVpYaGhiWEJzWlM1amIyMHZZM0J6THpBZEJnTlZIUTRFRmdRVWRWd3l2bzV4Q2RsSURMOU1JUE1WMGYxOFVaZ3dnYzhHQTFVZEl3U0J4ekNCeElBVWRWd3l2bzV4Q2RsSURMOU1JUE1WMGYxOFVaaWhnWldrZ1pJd2dZOHhDekFKQmdOVkJBWVRBa1ZUTVI0d0hBWURWUVFLREJWQlRGUkpRU0JEVDA1VFZVeFVUMUpGVXl3Z1UwRXhHREFXQmdOVkJHRU1EMVpCVkVWVExVRXhOVFExTmpVNE5URXlNREFHQTFVRUF3d3BRVXhVU1VFZ1EwOU9VMVZNVkU5U1JWTXNJRk5CSUMwZ1UyVnNiRzhnUld4bFkzUnliMjVwWTI4eEVqQVFCZ05WQkFVVENVRXhOVFExTmpVNE5ZSVViU1B1QURVUUIrekhQbUVrOXBQeVdpNDFtTWd3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUQ1M0paWmZEaFJmckl2ZWQ4amd2WXdKankwMlFqMTlKWUZsWkRGT3lFSG5QVkptYTZhQytLbTNFaWhwd042VzlwM3VKNmtMNllWNHJQUXY5VzRzOEVIL2k0N080Y0NBRktEdGRXYmYvRWJodUFTY21rK2EwMXF5VnBPNmQvZDh5cWQ0RmNDakJTWXo5MWJLTEJXVFl4RGx1K01ISXN6dlp1RXk4TjhUUitwRTFLV01NVjBoN0pZZnJFN0txYmppWlZGVnJJWXhZTVd5TjNHZ0Y1QmE0L21TaWd3N0ZUcFRXYWU1SXJiU1FrczNjaTJiUzEzNU1MWk9wOGtTNVh3SmFFYlV2QWdvdndaZHpzYnVsbEsvOXZyc3k2NjdwbWMrZ3dKeWR5bURqa3E0dVRTamV0bGdkUmViZjUrcjVrM3YyOHZQYytkZkMvTGxCL0hnQ2RZbmZQYz0iXSwidHlwIjoidmMrand0IiwiYWxnIjoiUlMyNTYifQ.eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL2NyZWRlbnRpYWxzLmV1ZGlzdGFjay5ldS8ud2VsbC1rbm93bi9jcmVkZW50aWFscy9sZWFyX2NyZWRlbnRpYWxfbWFjaGluZS93M2MvdjIiXSwiaWQiOiJ1cm46dXVpZDoxZWRmYmNiYS0wYmI1LTQ3MmUtOTg2ZC05MDc5ZTQ4MTE3MWYiLCJ0eXBlIjpbIlZlcmlmaWFibGVDcmVkZW50aWFsIiwibGVhcmNyZWRlbnRpYWwubWFjaGluZS53M2MuMyJdLCJkZXNjcmlwdGlvbiI6IlZlcmlmaWFibGUgQ3JlZGVudGlhbCBmb3IgbWFjaGluZXMiLCJjcmVkZW50aWFsU3ViamVjdCI6eyJtYW5kYXRlIjp7Im1hbmRhdG9yIjp7ImNvbW1vbk5hbWUiOiJKb2huIERvZSIsInNlcmlhbE51bWJlciI6IkExNTQ1NjU4NSIsImVtYWlsIjoiam9obi5kb2VAYWx0aWEuZXMiLCJvcmdhbml6YXRpb24iOiJBTFRJQSBDT05TVUxUT1JFUywgU0EiLCJpZCI6ImRpZDplbHNpOlZBVEVTLUExNTQ1NjU4NSIsIm9yZ2FuaXphdGlvbklkZW50aWZpZXIiOiJWQVRFUy1BMTU0NTY1ODUiLCJjb3VudHJ5IjoiRVMifSwibWFuZGF0ZWUiOnsiaWQiOiJkaWQ6a2V5OnpEbmFlZTNpYjNEem9rZ1Vqc25ublRzVFNieEtVZjhmQlNLOUVuOHFZUUdGb0FKb3kiLCJkb21haW4iOiJzYngub25ib2FyZC5kb21lLW1hcmtldHBsYWNlLmV1In0sInBvd2VyIjpbeyJ0eXBlIjoiZG9tYWluIiwiZG9tYWluIjoiRE9NRSIsImZ1bmN0aW9uIjoiT25ib2FyZGluZyIsImFjdGlvbiI6WyJFeGVjdXRlIl19LHsidHlwZSI6ImRvbWFpbiIsImRvbWFpbiI6IkRPTUUiLCJmdW5jdGlvbiI6IkNlcnRpZmljYXRpb24iLCJhY3Rpb24iOlsiQXR0ZXN0Il19XX0sImlkIjoidXJuOnV1aWQ6N2JjMDE0ZjgtOTQ1OS00MTg2LTkyMjAtY2NhMDYxODZiNTlhIn0sInZhbGlkRnJvbSI6IjIwMjYtMDUtMjdUMTQ6MjA6MjcuNjE1NzA0NTE1WiIsInZhbGlkVW50aWwiOiIyMDI3LTA1LTI3VDE0OjIwOjI3LjYxNTcwNDUxNVoiLCJpc3N1ZXIiOnsiaWQiOiJkaWQ6ZWxzaTpWQVRFUy1BMTU0NTY1ODUiLCJvcmdhbml6YXRpb25JZGVudGlmaWVyIjoiVkFURVMtQTE1NDU2NTg1Iiwib3JnYW5pemF0aW9uIjoiQUxUSUEgQ09OU1VMVE9SRVMsIFNBIiwiY291bnRyeSI6IkVTIiwiY29tbW9uTmFtZSI6IkFMVElBIENPTlNVTFRPUkVTLCBTQSAtIFNlbGxvIEVsZWN0cm9uaWNvIiwic2VyaWFsTnVtYmVyIjoiNmQyM2VlMDAzNTEwMDdlY2M3M2U2MTI0ZjY5M2YyNWEyZTM1OThjOCJ9LCJjcmVkZW50aWFsU3RhdHVzIjp7ImlkIjoiaHR0cHM6Ly9kb21lLnN0Zy5ldWRpc3RhY2submV0L2lzc3Vlci93M2MvdjEvY3JlZGVudGlhbHMvc3RhdHVzLzEjMzM3MzYiLCJ0eXBlIjoiQml0c3RyaW5nU3RhdHVzTGlzdEVudHJ5Iiwic3RhdHVzUHVycG9zZSI6InJldm9jYXRpb24iLCJzdGF0dXNMaXN0SW5kZXgiOiIzMzczNiIsInN0YXR1c0xpc3RDcmVkZW50aWFsIjoiaHR0cHM6Ly9kb21lLnN0Zy5ldWRpc3RhY2submV0L2lzc3Vlci93M2MvdjEvY3JlZGVudGlhbHMvc3RhdHVzLzEifSwiY25mIjp7Imp3ayI6eyJrdHkiOiJFQyIsImNydiI6IlAtMjU2IiwieCI6IlpOZGJiZXA1bExkRVVZNlJzMXN5czAxTWtsanpMYjV2VWJwd2E2ZllHdDgiLCJ5IjoidTB3bjRGc3owSEN6OVFPSEFuaHdiRkZueDBRTzB1NmgtZzB1ci1mb2t3ayJ9fSwic3ViIjoidXJuOnV1aWQ6N2JjMDE0ZjgtOTQ1OS00MTg2LTkyMjAtY2NhMDYxODZiNTlhIn0.BQ--gVOZYI6u_EHV10U-yiXXfNW6VkFiVeVMA717HKcG2CKFr7dliHrUg7uT921QUEKiQpkM09IrU5un9I7K3ZrO8v2BNkrve51LKz_cLDC61S4Jtyltz6UF4m3t1ssdxtvvxtWQA5R7vLXAD2ppJEb85v-zHQkc7qvvmls9-cDxsXzRlM2cGipnswVhL6EuJp55qrnYjdO927XxZZilHfWmPhVN3Jm9r6mvowIKNOUTfHE4GTLrpe55lk3BPAuJWAMNylIjtCf0VpaJEx9nKAcqeyADhOb5JTReNkiSYgoZKLpfUKoWjxb9m36iNRWluQGjIwDJv3z8NJTAI_RIjw";
    private static final String EMPLOYEE_VC_JWT = "eyJzaWdUIjoiMjAyNi0wNS0xOVQxNDoyMTozNy42MzE5NzI4OTlaIiwieDVjIjpbIk1JSUZCVENDQSsyZ0F3SUJBZ0lVYlNQdUFEVVFCK3pIUG1FazlwUHlXaTQxbU1nd0RRWUpLb1pJaHZjTkFRRUxCUUF3Z1k4eEN6QUpCZ05WQkFZVEFrVlRNUjR3SEFZRFZRUUtEQlZCVEZSSlFTQkRUMDVUVlV4VVQxSkZVeXdnVTBFeEdEQVdCZ05WQkdFTUQxWkJWRVZUTFVFeE5UUTFOalU0TlRFeU1EQUdBMVVFQXd3cFFVeFVTVUVnUTA5T1UxVk1WRTlTUlZNc0lGTkJJQzBnVTJWc2JHOGdSV3hsWTNSeWIyNXBZMjh4RWpBUUJnTlZCQVVUQ1VFeE5UUTFOalU0TlRBZUZ3MHlOakF5TWpjeU1UUTNNelZhRncweU9EQXlNamN5TVRRM016VmFNSUdQTVFzd0NRWURWUVFHRXdKRlV6RWVNQndHQTFVRUNnd1ZRVXhVU1VFZ1EwOU9VMVZNVkU5U1JWTXNJRk5CTVJnd0ZnWURWUVJoREE5V1FWUkZVeTFCTVRVME5UWTFPRFV4TWpBd0JnTlZCQU1NS1VGTVZFbEJJRU5QVGxOVlRGUlBVa1ZUTENCVFFTQXRJRk5sYkd4dklFVnNaV04wY205dWFXTnZNUkl3RUFZRFZRUUZFd2xCTVRVME5UWTFPRFV3Z2dFaU1BMEdDU3FHU0liM0RRRUJBUVVBQTRJQkR3QXdnZ0VLQW9JQkFRREZvTE9iMXAxVjkvZ2R3SXJkbUJtRHlVTlAwUFJKZDkwVW9HUVlmbmRldGxzZkkybTJSNTYyc05wZjBzenplT0FrMTBIVmtHQXA0MUliWXpjN09BdTJMN2daRElWcjlEQ3k1bm1lWjdYWjZ2dlpWSkpFbnZSQWJWekJORmk2WGtXdG85STRrSis1RldxMkhvc25VVkJ6SG1NUFp2SVBxcXpzbHlER0d4SStlNFNNWmd4cHA3cWZ2UjAvTGNTK1pWYXBzVVZrUXoxQWNPTkdtOGtpMjJEdlRGZlkvUnh6cUl1TDFSK0gwZDJiSGQxSGRGRVNvY216WitqUU4vUjl6My9aSGNLWEVIbkJwczZJZzFqREpJOVNJa0I5L3NWbWdpVTJsVlFIZWhvdFFVczh0Q3BoWUI0elR5a2FXakJrNXJQeHpkQU9MWjdKVElzOURiN3A3NnluQWdNQkFBR2pnZ0ZWTUlJQlVUQU1CZ05WSFJNQkFmOEVBakFBTUE0R0ExVWREd0VCL3dRRUF3SUd3REJBQmdOVkhTQUVPVEEzTURVR0J3UUFpK3hBQVFJd0tqQW9CZ2dyQmdFRkJRY0NBUlljYUhSMGNITTZMeTkzZDNjdVpYaGhiWEJzWlM1amIyMHZZM0J6THpBZEJnTlZIUTRFRmdRVWRWd3l2bzV4Q2RsSURMOU1JUE1WMGYxOFVaZ3dnYzhHQTFVZEl3U0J4ekNCeElBVWRWd3l2bzV4Q2RsSURMOU1JUE1WMGYxOFVaaWhnWldrZ1pJd2dZOHhDekFKQmdOVkJBWVRBa1ZUTVI0d0hBWURWUVFLREJWQlRGUkpRU0JEVDA1VFZVeFVUMUpGVXl3Z1UwRXhHREFXQmdOVkJHRU1EMVpCVkVWVExVRXhOVFExTmpVNE5URXlNREFHQTFVRUF3d3BRVXhVU1VFZ1EwOU9VMVZNVkU5U1JWTXNJRk5CSUMwZ1UyVnNiRzhnUld4bFkzUnliMjVwWTI4eEVqQVFCZ05WQkFVVENVRXhOVFExTmpVNE5ZSVViU1B1QURVUUIrekhQbUVrOXBQeVdpNDFtTWd3RFFZSktvWklodmNOQVFFTEJRQURnZ0VCQUQ1M0paWmZEaFJmckl2ZWQ4amd2WXdKankwMlFqMTlKWUZsWkRGT3lFSG5QVkptYTZhQytLbTNFaWhwd042VzlwM3VKNmtMNllWNHJQUXY5VzRzOEVIL2k0N080Y0NBRktEdGRXYmYvRWJodUFTY21rK2EwMXF5VnBPNmQvZDh5cWQ0RmNDakJTWXo5MWJLTEJXVFl4RGx1K01ISXN6dlp1RXk4TjhUUitwRTFLV01NVjBoN0pZZnJFN0txYmppWlZGVnJJWXhZTVd5TjNHZ0Y1QmE0L21TaWd3N0ZUcFRXYWU1SXJiU1FrczNjaTJiUzEzNU1MWk9wOGtTNVh3SmFFYlV2QWdvdndaZHpzYnVsbEsvOXZyc3k2NjdwbWMrZ3dKeWR5bURqa3E0dVRTamV0bGdkUmViZjUrcjVrM3YyOHZQYytkZkMvTGxCL0hnQ2RZbmZQYz0iXSwidHlwIjoidmMrand0IiwiYWxnIjoiUlMyNTYifQ.eyJAY29udGV4dCI6WyJodHRwczovL3d3dy53My5vcmcvbnMvY3JlZGVudGlhbHMvdjIiLCJodHRwczovL2NyZWRlbnRpYWxzLmV1ZGlzdGFjay5ldS8ud2VsbC1rbm93bi9jcmVkZW50aWFscy9sZWFyX2NyZWRlbnRpYWxfZW1wbG95ZWUvdzNjL3YzIl0sImlkIjoidXJuOnV1aWQ6NjI3YTk4MDAtMTI0Ny00MzNiLWFmNmUtM2YyNDQ3ZjNhNGUxIiwidHlwZSI6WyJWZXJpZmlhYmxlQ3JlZGVudGlhbCIsImxlYXJjcmVkZW50aWFsLmVtcGxveWVlLnczYy40Il0sImRlc2NyaXB0aW9uIjoiVmVyaWZpYWJsZSBDcmVkZW50aWFsIGZvciBlbXBsb3llZXMgb2YgYW4gb3JnYW5pemF0aW9uIiwiY3JlZGVudGlhbFN1YmplY3QiOnsibWFuZGF0ZSI6eyJtYW5kYXRvciI6eyJpZCI6ImRpZDplbHNpOlZBVFBULTEyMzQ1NjciLCJlbWFpbCI6InJvZ2VyLm1pcmV0QGFsdGlhLmVzIiwib3JnYW5pemF0aW9uIjoiVUJJV0hFUkUiLCJjb3VudHJ5IjoiUFQiLCJjb21tb25OYW1lIjoiTWFuZGF0b3IgTGFzdCIsInNlcmlhbE51bWJlciI6IkFBQUFBQUFBIiwib3JnYW5pemF0aW9uSWRlbnRpZmllciI6IlZBVFBULTEyMzQ1NjcifSwibWFuZGF0ZWUiOnsiZmlyc3ROYW1lIjoiVWJpd2hlcmUgT25lIiwibGFzdE5hbWUiOiJlbXBsb3llZSIsImVtYWlsIjoicm9nZXIubWlyZXRAYWx0aWEuZXMifSwicG93ZXIiOlt7InR5cGUiOiJkb21haW4iLCJkb21haW4iOiJET01FIiwiZnVuY3Rpb24iOiJPbmJvYXJkaW5nIiwiYWN0aW9uIjpbIkV4ZWN1dGUiXX0seyJ0eXBlIjoiZG9tYWluIiwiZG9tYWluIjoiRE9NRSIsImZ1bmN0aW9uIjoiQ2VydGlmaWNhdGlvbiIsImFjdGlvbiI6WyJBdHRlc3QiXX1dfSwiaWQiOiJ1cm46dXVpZDo1Y2EyZDRmMi01YTEwLTQyMmEtYjQzYS1mYjkzOGE2MGRjNjMifSwidmFsaWRGcm9tIjoiMjAyNi0wNS0xOVQxNDoyMDo1Ny4yODk4NjIxOTdaIiwidmFsaWRVbnRpbCI6IjIwMjctMDUtMTlUMTQ6MjA6NTcuMjg5ODYyMTk3WiIsImlzc3VlciI6eyJpZCI6ImRpZDplbHNpOlZBVEVTLUExNTQ1NjU4NSIsIm9yZ2FuaXphdGlvbklkZW50aWZpZXIiOiJWQVRFUy1BMTU0NTY1ODUiLCJvcmdhbml6YXRpb24iOiJBTFRJQSBDT05TVUxUT1JFUywgU0EiLCJjb3VudHJ5IjoiRVMiLCJjb21tb25OYW1lIjoiQUxUSUEgQ09OU1VMVE9SRVMsIFNBIC0gU2VsbG8gRWxlY3Ryb25pY28iLCJzZXJpYWxOdW1iZXIiOiI2ZDIzZWUwMDM1MTAwN2VjYzczZTYxMjRmNjkzZjI1YTJlMzU5OGM4In0sImNyZWRlbnRpYWxTdGF0dXMiOnsiaWQiOiJodHRwczovL2RvbWUuMTI3LjAuMC4xLm5pcC5pbzo0NDQzL2lzc3Vlci93M2MvdjEvY3JlZGVudGlhbHMvc3RhdHVzLzEjODg0MzkiLCJ0eXBlIjoiQml0c3RyaW5nU3RhdHVzTGlzdEVudHJ5Iiwic3RhdHVzUHVycG9zZSI6InJldm9jYXRpb24iLCJzdGF0dXNMaXN0SW5kZXgiOiI4ODQzOSIsInN0YXR1c0xpc3RDcmVkZW50aWFsIjoiaHR0cHM6Ly9kb21lLjEyNy4wLjAuMS5uaXAuaW86NDQ0My9pc3N1ZXIvdzNjL3YxL2NyZWRlbnRpYWxzL3N0YXR1cy8xIn0sImNuZiI6eyJqd2siOnsia3R5IjoiRUMiLCJjcnYiOiJQLTI1NiIsIngiOiJ6eUR2TjRieWpyNldJRmN0UTB4UklzS2hLMmVTOE9qeHQwYm1pNml3YWRBIiwieSI6InNYWEtRVkNBMGg1NjNWdmtveW1IcTk4MUZnM3ZBRmh6MDlVVGU3cmNkQncifX0sInN1YiI6InVybjp1dWlkOjVjYTJkNGYyLTVhMTAtNDIyYS1iNDNhLWZiOTM4YTYwZGM2MyJ9.RaWC12rUPFEldKCalpnO-rekwLwi6HSdN5JX7Q43IcWSVdWS2R2fKSkAyefz4db6TyNdd42k1QHNfrUmRyW3tor36WAblkPyiEL2ixdDwfyD8kI-Fo6qq1RC_HunAafK1AoFN0zSa8WanR5V7sZyMlsMYawl6UhuBD55M9Stl8sZDMvqWAMK_X3G1JdX58CR1fgSENcK2ncc8WOnCi4Kw3kRxaQva30wIpEhnCZSXIBuL2I7NNd4Hoan2ngBMdeNf0uhHIdRJqWuhNf2s7Og7vdOCLvdRYNEnRZ6UzfBs4NyQLg6yaK7yafYUjZCO-E-_2QXnQQJoZA1nndQIBK46g";
    private static final String TENANT = "dome";
    // --- Token lifetime ---
    private static final long ONE_YEAR_SECONDS = 31_536_000L;
    private static final Path OUTPUT_DIR       = Path.of("target", "local-tokens");

    private CryptoComponent crypto;
    private JWTServiceImpl jwtService;
    private ObjectMapper objectMapper;

    @BeforeEach
    void setUp() throws IOException {
        BackendConfig backendConfig = mock(BackendConfig.class);
        when(backendConfig.hasIdentityConfigured()).thenReturn(true);
        when(backendConfig.getPrivateKey()).thenReturn(PRIVATE_KEY_HEX);
        when(backendConfig.getDidKey()).thenReturn(DID_KEY);
        when(backendConfig.getCertificate()).thenReturn(null);
        when(backendConfig.getUrl()).thenReturn(VERIFIER_URL);

        this.crypto = new CryptoComponent(backendConfig);
        this.objectMapper = new ObjectMapper();
        this.jwtService = new JWTServiceImpl(crypto, objectMapper);

        Files.createDirectories(OUTPUT_DIR);
    }

    /**
     * Builds an access token from a signed LEARCredentialMachine VC, mirroring the
     * client_credentials (M2M) flow: aud == iss == verifier URL.
     */
    @Test
    void buildAccessToken_forManualUse_machineVc_oneYear() throws Exception {
        JsonNode vc = extractVcFromJwt(MACHINE_VC_JWT);

        Instant iat = Instant.now();
        Instant exp = iat.plusSeconds(ONE_YEAR_SECONDS);

        // Profile learcredential.machine.w3c.3: subject_paths = [mandatee.ipAddress, mandatee.domain]
        String subject  = vc.at("/credentialSubject/mandate/mandatee/ipAddress").asText();
        String tenant   = TENANT;
        String credType = "learcredential.machine.w3c.3";

        JWTClaimsSet payload = new JWTClaimsSet.Builder()
                .issuer(VERIFIER_URL)
                .audience(VERIFIER_URL) // M2M: aud == iss
                .subject(subject)
                .jwtID(UUID.randomUUID().toString())
                .issueTime(Date.from(iat))
                .expirationTime(Date.from(exp))
                .claim(OAuth2ParameterNames.SCOPE, "machine learcredential")
                .claim("credential_type", credType)
                .claim("tenant", tenant)
                // access_token_embed from profile
                .claim("mandatee", objectMapper.convertValue(vc.at("/credentialSubject/mandate/mandatee"), Object.class))
                .claim("mandator", objectMapper.convertValue(vc.at("/credentialSubject/mandate/mandator"), Object.class))
                .claim("power",    objectMapper.convertValue(vc.at("/credentialSubject/mandate/power"),    Object.class))
                .build();

        String accessToken = jwtService.issueJWT(payload.toString());
        assertNotNull(accessToken);

        verifySignatureAndHeader(accessToken);
        SignedJWT parsed = SignedJWT.parse(accessToken);
        JWTClaimsSet claims = parsed.getJWTClaimsSet();
        assertEquals(VERIFIER_URL, claims.getIssuer());
        assertEquals(List.of(VERIFIER_URL), claims.getAudience());
        assertEquals(subject, claims.getSubject());
        assertEquals(tenant, claims.getStringClaim("tenant"));
        assertEquals("machine learcredential", claims.getStringClaim(OAuth2ParameterNames.SCOPE));
        assertEquals(credType, claims.getStringClaim("credential_type"));
        assertEquals(iat.getEpochSecond(), claims.getIssueTime().toInstant().getEpochSecond());
        assertEquals(exp.getEpochSecond(), claims.getExpirationTime().toInstant().getEpochSecond());
        assertTrue(claims.getExpirationTime().after(new Date()));

        writeToken("access_token_machine.txt", accessToken);
    }

    /**
     * Builds an id token from a signed LEARCredentialEmployee VC, mirroring the
     * authorization_code flow: aud == client_id (placeholder for local use).
     */
    @Test
    void buildIdToken_forManualUse_employeeVc_oneYear() throws Exception {
        JsonNode vc = extractVcFromJwt(EMPLOYEE_VC_JWT);

        // In auth_code, audience is the OIDC client_id. Placeholder for local testing.
        String clientId = "local-test-client";

        Instant iat = Instant.now();
        Instant exp = iat.plusSeconds(ONE_YEAR_SECONDS);

        // Profile learcredential.employee.w3c.4: subject_paths = [mandatee.email]
        String firstName    = vc.at("/credentialSubject/mandate/mandatee/firstName").asText();
        String lastName     = vc.at("/credentialSubject/mandate/mandatee/lastName").asText();
        String email        = vc.at("/credentialSubject/mandate/mandatee/email").asText();
        String subject      = email;
        String credType     = "learcredential.employee.w3c.4";
        String vcJsonString = objectMapper.writeValueAsString(vc);

        JWTClaimsSet idTokenClaims = new JWTClaimsSet.Builder()
                .subject(subject)
                .issuer(VERIFIER_URL)
                .audience(clientId)
                .issueTime(Date.from(iat))
                .expirationTime(Date.from(exp))
                .claim("auth_time", Date.from(iat))
                .claim("acr", "0")
                .claim("credential_type", credType)
                .claim("vc_json", vcJsonString)
                // id_token claim mappings from profile
                .claim("given_name", firstName)
                .claim("family_name", lastName)
                .claim("email", email)
                .claim("name", firstName + " " + lastName)
                .claim("email_verified", true)
                // id_token_embed mappings
                .claim("mandatee", objectMapper.convertValue(vc.at("/credentialSubject/mandate/mandatee"), Object.class))
                .claim("mandator", objectMapper.convertValue(vc.at("/credentialSubject/mandate/mandator"), Object.class))
                .claim("power",    objectMapper.convertValue(vc.at("/credentialSubject/mandate/power"),    Object.class))
                // nonce — set when the consumer needs to bind to an OIDC authentication request
                // .claim(IdTokenClaimNames.NONCE, "<client-nonce>")
                .build();

        String idToken = jwtService.issueJWT(idTokenClaims.toString());
        assertNotNull(idToken);

        verifySignatureAndHeader(idToken);
        SignedJWT parsed = SignedJWT.parse(idToken);
        JWTClaimsSet claims = parsed.getJWTClaimsSet();
        assertEquals(VERIFIER_URL, claims.getIssuer());
        assertEquals(List.of(clientId), claims.getAudience());
        assertEquals(subject, claims.getSubject());
        assertEquals("0", claims.getStringClaim("acr"));
        assertEquals(credType, claims.getStringClaim("credential_type"));
        assertEquals(email, claims.getStringClaim("email"));
        assertEquals(firstName, claims.getStringClaim("given_name"));
        assertEquals(lastName, claims.getStringClaim("family_name"));
        assertEquals(firstName + " " + lastName, claims.getStringClaim("name"));
        assertEquals(Boolean.TRUE, claims.getBooleanClaim("email_verified"));
        assertNotNull(claims.getStringClaim("vc_json"));
        assertEquals(iat.getEpochSecond(), claims.getIssueTime().toInstant().getEpochSecond());
        assertEquals(exp.getEpochSecond(), claims.getExpirationTime().toInstant().getEpochSecond());
        assertTrue(claims.getExpirationTime().after(new Date()));

        writeToken("id_token_employee.txt", idToken);
    }

    // --- helpers ---

    /**
     * Extracts the VC payload from a signed JWT VC. Mirrors JWTServiceImpl.extractVCFromPayload:
     * VCDM v1.1 wraps the credential under "vc"; v2.0 places the credential at the top level.
     * The JWT signature is intentionally NOT verified here — this test only consumes the payload.
     */
    private JsonNode extractVcFromJwt(String vcJwt) throws Exception {
        SignedJWT signed = SignedJWT.parse(vcJwt);
        Map<String, Object> claims = signed.getPayload().toJSONObject();
        Object vc = claims.getOrDefault("vc", claims);
        return objectMapper.convertValue(vc, JsonNode.class);
    }

    private void verifySignatureAndHeader(String jwt) throws Exception {
        SignedJWT parsed = SignedJWT.parse(jwt);
        ECKey ecKey = crypto.getECKey();
        assertTrue(parsed.verify(new ECDSAVerifier(ecKey.toECPublicKey())),
                "ES256 signature must verify with verifier's public key");
        assertEquals("ES256", parsed.getHeader().getAlgorithm().getName());
        assertEquals(ecKey.getKeyID(), parsed.getHeader().getKeyID());
    }

    private void writeToken(String fileName, String token) throws IOException {
        Path output = OUTPUT_DIR.resolve(fileName);
        Files.writeString(output, token);
        System.out.println("===");
        System.out.println(fileName + " -> " + output.toAbsolutePath());
        System.out.println(fileName.replace(".txt", "").toUpperCase() + "=" + token);
        System.out.println("===");
    }
}
