package es.in2.vcverifier.sso.infrastructure.persistence;

import es.in2.vcverifier.sso.domain.exception.SsoSessionRepositoryException;
import es.in2.vcverifier.sso.domain.model.SsoSession;
import es.in2.vcverifier.sso.domain.model.SsoSessionId;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Nested;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.InOrder;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.Optional;

import static org.assertj.core.api.Assertions.assertThat;
import static org.assertj.core.api.Assertions.assertThatThrownBy;
import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.contains;
import static org.mockito.Mockito.inOrder;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

/**
 * Verifica el fix de transaccionalidad de {@link SsoSessionJdbcRepository}: cada método debe
 * abrir una transacción real ({@code setAutoCommit(false)}) antes de aplicar
 * {@code SET LOCAL search_path}/{@code statement_timeout}, para que ambos ajustes sigan
 * vigentes cuando corre la sentencia de negocio, y hacer {@code commit()}/{@code rollback()}
 * explícito según el resultado.
 */
@ExtendWith(MockitoExtension.class)
class SsoSessionJdbcRepositoryTest {

    private static final String TENANT = "tenant-a";
    private static final String HOLDER_HASH = "holder-hash-1";
    private static final Clock FIXED_CLOCK = Clock.fixed(Instant.parse("2026-08-13T10:00:00Z"), ZoneOffset.UTC);

    @Mock private DataSource dataSource;
    @Mock private Connection connection;
    @Mock private PreparedStatement preparedStatement;
    @Mock private ResultSet resultSet;

    private SsoSessionJdbcRepository repository;

    @BeforeEach
    void setUp() throws SQLException {
        repository = new SsoSessionJdbcRepository(dataSource, FIXED_CLOCK);
        when(dataSource.getConnection()).thenReturn(connection);
        when(connection.prepareStatement(anyString())).thenReturn(preparedStatement);
    }

    private static SQLException uniqueViolation() {
        return new SQLException("duplicate key value violates unique constraint", "23505");
    }

    @Nested
    @DisplayName("save")
    class SaveTests {

        @Test
        void save_commitsWithinSameTransactionAsSearchPath_whenInsertSucceeds() throws SQLException {
            // Arrange
            SsoSession session = SsoSession.establish(TENANT, HOLDER_HASH, Duration.ofHours(1));
            when(preparedStatement.executeUpdate()).thenReturn(1);

            // Act
            SsoSession saved = repository.save(session);

            // Assert
            assertThat(saved).isEqualTo(session);
            verify(connection).prepareStatement(contains("SET LOCAL search_path"));
            verify(connection).prepareStatement(contains("\"" + TENANT + "\""));

            InOrder order = inOrder(connection, preparedStatement);
            order.verify(connection).setAutoCommit(false);
            order.verify(preparedStatement, times(2)).execute();
            order.verify(preparedStatement).executeUpdate();
            order.verify(connection).commit();
            order.verify(connection).setAutoCommit(true);
        }

        @Test
        void save_rollsBackAndThrowsRepositoryException_whenInsertFailsWithNonUniqueViolation() throws SQLException {
            // Arrange
            SsoSession session = SsoSession.establish(TENANT, HOLDER_HASH, Duration.ofHours(1));
            when(preparedStatement.executeUpdate()).thenThrow(new SQLException("connection reset", "08006"));

            // Act / Assert
            assertThatThrownBy(() -> repository.save(session))
                    .isInstanceOf(SsoSessionRepositoryException.class);

            verify(connection).rollback();
            verify(connection).setAutoCommit(true);
            verify(connection, never()).commit();
        }

        @Test
        void save_reusesSameConnectionForSupersedeAndRetry_whenUniqueViolationOccurs() throws SQLException {
            // Arrange: first insert violates the active-session-per-holder unique index,
            // supersede UPDATE and retry INSERT must run in the SAME connection/transaction.
            SsoSession session = SsoSession.establish(TENANT, HOLDER_HASH, Duration.ofHours(1));
            when(preparedStatement.executeUpdate())
                    .thenThrow(uniqueViolation())
                    .thenReturn(1)
                    .thenReturn(1);

            // Act
            SsoSession saved = repository.save(session);

            // Assert
            assertThat(saved).isEqualTo(session);
            verify(dataSource, times(1)).getConnection();
            verify(connection).commit();
            verify(connection, never()).rollback();
        }
    }

    @Nested
    @DisplayName("revokeAllByTenant")
    class RevokeAllByTenantTests {

        @Test
        void revokeAllByTenant_commitsAndReturnsDeletedCount_onSuccess() throws SQLException {
            // Arrange
            when(preparedStatement.executeUpdate()).thenReturn(3);

            // Act
            int revoked = repository.revokeAllByTenant(TENANT);

            // Assert
            assertThat(revoked).isEqualTo(3);
            verify(connection).commit();
            verify(connection, never()).rollback();
        }

        @Test
        void revokeAllByTenant_rollsBackAndThrowsRepositoryException_whenDeleteFails() throws SQLException {
            // Arrange
            when(preparedStatement.executeUpdate()).thenThrow(new SQLException("delete blocked", "40001"));

            // Act / Assert
            assertThatThrownBy(() -> repository.revokeAllByTenant(TENANT))
                    .isInstanceOf(SsoSessionRepositoryException.class);

            verify(connection).rollback();
            verify(connection, never()).commit();
            verify(connection).setAutoCommit(true);
        }
    }

    @Nested
    @DisplayName("findActiveById — fail-open on SQL errors")
    class FindActiveByIdTests {

        @Test
        void findActiveById_returnsEmptyAndRollsBack_whenSqlExceptionOccurs() throws SQLException {
            // Arrange
            when(connection.prepareStatement(anyString()))
                    .thenReturn(preparedStatement)
                    .thenReturn(preparedStatement)
                    .thenThrow(new SQLException("connection reset", "08006"));

            // Act
            Optional<SsoSession> result = repository.findActiveById(SsoSessionId.generate(), TENANT);

            // Assert
            assertThat(result).isEmpty();
            verify(connection).rollback();
            verify(connection).setAutoCommit(true);
        }
    }

    @Nested
    @DisplayName("findById — no tenant filter (AC-04)")
    class FindByIdTests {

        @Test
        void findById_skipsSearchPath_butStillAppliesStatementTimeoutAndCommits() throws SQLException {
            // Arrange
            when(preparedStatement.executeQuery()).thenReturn(resultSet);
            when(resultSet.next()).thenReturn(false);

            // Act
            Optional<SsoSession> result = repository.findById(SsoSessionId.generate());

            // Assert
            assertThat(result).isEmpty();
            verify(connection, never()).prepareStatement(contains("search_path"));
            verify(connection).prepareStatement(contains("SET LOCAL statement_timeout"));
            verify(connection).commit();
        }
    }

    @Nested
    @DisplayName("updateLastUsedAt")
    class UpdateLastUsedAtTests {

        @Test
        void updateLastUsedAt_rollsBackAndThrowsRepositoryException_onFailure() throws SQLException {
            // Arrange
            when(preparedStatement.executeUpdate()).thenThrow(new SQLException("timeout", "57014"));

            // Act / Assert
            assertThatThrownBy(() ->
                    repository.updateLastUsedAt(SsoSessionId.generate(), TENANT, Instant.now(FIXED_CLOCK)))
                    .isInstanceOf(SsoSessionRepositoryException.class);

            verify(connection).rollback();
            verify(connection).setAutoCommit(true);
        }
    }

    @Nested
    @DisplayName("recordClientActivity — best-effort (ADR-108)")
    class RecordClientActivityTests {

        @Test
        void recordClientActivity_swallowsExceptionWithoutThrowing_onFailure() throws SQLException {
            // Arrange
            when(preparedStatement.executeUpdate()).thenThrow(new SQLException("connection reset", "08006"));

            // Act / Assert — best-effort tracking must never break establish/reuse
            assertDoesNotThrow(() ->
                    repository.recordClientActivity(SsoSessionId.generate(), TENANT, "client-a"));

            verify(connection).rollback();
        }
    }

    @Nested
    @DisplayName("terminateActive")
    class TerminateActiveTests {

        @Test
        void terminateActive_commitsAndReturnsUpdatedRowCount_onSuccess() throws SQLException {
            // Arrange
            when(preparedStatement.executeUpdate()).thenReturn(1);

            // Act
            int updated = repository.terminateActive(SsoSessionId.generate(), TENANT);

            // Assert
            assertThat(updated).isEqualTo(1);
            verify(connection).commit();
            verify(connection, never()).rollback();
        }
    }
}
