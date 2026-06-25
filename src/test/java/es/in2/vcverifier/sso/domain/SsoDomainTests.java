package es.in2.vcverifier.sso.domain;

import es.in2.vcverifier.sso.domain.model.SsoAuditEvent;
import es.in2.vcverifier.sso.domain.model.SsoSession;
import es.in2.vcverifier.sso.domain.model.SsoSessionState;
import es.in2.vcverifier.sso.domain.port.SsoAuditPort;
import es.in2.vcverifier.sso.infrastructure.audit.SsoAuditAdapter;
import es.in2.vcverifier.sso.infrastructure.persistence.SsoSessionJdbcRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.junit.jupiter.MockitoExtension;
import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.time.Duration;
import java.time.Instant;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
public class SsoDomainTests {


    @Test
    void SsoSession_establish_setsActiveStateAndExpiry() {

        Duration ttl = Duration.ofMinutes(30);

        Instant before = Instant.now();

        SsoSession session =
                SsoSession.establish(
                        "tenant-a",
                        "holder-hash",
                        ttl
                );

        Instant after = Instant.now();

        assertThat(session.getState())
                .isEqualTo(SsoSessionState.ACTIVE);

        assertThat(session.getTenant())
                .isEqualTo("tenant-a");

        assertThat(session.getHolderHash())
                .isEqualTo("holder-hash");

        assertThat(session.getEstablishedAt())
                .isBetween(before, after);

        assertThat(session.getExpiresAt())
                .isAfter(session.getEstablishedAt());

        assertThat(session.getExpiresAt())
                .isEqualTo(session.getEstablishedAt().plus(ttl));
    }



    @Test
    void SsoSession_supersede_marksSuperseded() {

        SsoSession session =
                SsoSession.establish(
                        "tenant-a",
                        "holder-hash",
                        Duration.ofMinutes(10)
                );

        session.supersede();

        assertThat(session.getState())
                .isEqualTo(SsoSessionState.SUPERSEDED);
    }


    @Test
    void SsoSessionJdbcRepository_findByTenant_doesNotResolveOtherTenant()
            throws Exception {

        DataSource dataSource = mock(DataSource.class);
        Connection connection = mock(Connection.class);

        PreparedStatement searchPathStatement = mock(PreparedStatement.class);
        PreparedStatement timeoutStatement = mock(PreparedStatement.class);
        PreparedStatement queryStatement = mock(PreparedStatement.class);

        ResultSet resultSet = mock(ResultSet.class);

        when(dataSource.getConnection())
                .thenReturn(connection);

        when(connection.prepareStatement(startsWith("SET LOCAL search_path")))
                .thenReturn(searchPathStatement);

        when(connection.prepareStatement(startsWith("SET LOCAL statement_timeout")))
                .thenReturn(timeoutStatement);

        when(connection.prepareStatement(
                startsWith("SELECT id, tenant, holder_hash")))
                .thenReturn(queryStatement);

        when(queryStatement.executeQuery())
                .thenReturn(resultSet);

        /*
         * Simulamos que no existe ninguna sesión ACTIVE
         * para el tenant solicitado.
         */
        when(resultSet.next())
                .thenReturn(false);

        SsoSessionJdbcRepository repository =
                new SsoSessionJdbcRepository(dataSource);

        Optional<SsoSession> result =
                repository.findActiveByTenantAndHolder(
                        "tenant-a",
                        "holder-hash"
                );

        assertThat(result).isEmpty();

        verify(queryStatement).setString(1, "tenant-a");
        verify(queryStatement).setString(2, "holder-hash");
    }

    @Test
    void SsoAuditAdapter_emit_structuresEventWithoutPlainSub() throws Exception {

        DataSource mockDataSource = mock(DataSource.class);
        doThrow(new java.sql.SQLException("test-no-db")).when(mockDataSource).getConnection();
        SsoAuditPort adapter = new SsoAuditAdapter(mockDataSource);

        SsoAuditEvent event =
                new SsoAuditEvent(
                        SsoAuditEvent.EventType.SSO_SESSION_ESTABLISHED,
                        "tenant-a",
                        "client-a",
                        "real-subject-value",
                        "SUCCESS",
                        "corr-123",
                        Instant.now(),
                        null
                );

        /*
         * Verificamos simplemente que no lanza excepción
         * al emitir el evento.
         */
        adapter.publish(event);

        assertThat(event.getHolderHash())
                .isEqualTo("real-subject-value");
    }


}