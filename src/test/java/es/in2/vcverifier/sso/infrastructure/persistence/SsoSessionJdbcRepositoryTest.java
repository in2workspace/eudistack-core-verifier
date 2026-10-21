package es.in2.vcverifier.sso.infrastructure.persistence;

import ch.qos.logback.classic.Level;
import ch.qos.logback.classic.Logger;
import ch.qos.logback.classic.spi.ILoggingEvent;
import ch.qos.logback.core.read.ListAppender;
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
import org.slf4j.LoggerFactory;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.List;
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

    /** Runs {@code action} and returns the events the repository logged meanwhile (DEBUG included). */
    private static List<ILoggingEvent> captureLogs(Runnable action) {
        Logger logger = (Logger) LoggerFactory.getLogger(SsoSessionJdbcRepository.class);
        Level previousLevel = logger.getLevel();
        ListAppender<ILoggingEvent> appender = new ListAppender<>();
        appender.start();
        logger.addAppender(appender);
        logger.setLevel(Level.DEBUG);
        try {
            action.run();
            return List.copyOf(appender.list);
        } finally {
            logger.detachAppender(appender);
            logger.setLevel(previousLevel);
        }
    }

    @Nested
    @DisplayName("save")
    class SaveTests {

        @Test
        void save_commitsInSingleTransaction_whenInsertSucceeds() throws SQLException {
            // Arrange
            SsoSession session = SsoSession.establish(TENANT, HOLDER_HASH, Duration.ofHours(1));
            when(preparedStatement.executeUpdate()).thenReturn(1);

            // Act
            SsoSession saved = repository.save(session);

            // Assert
            assertThat(saved).isEqualTo(session);
            // No per-tenant search_path switch: isolation comes from the `tenant` column
            // filter already present in every query, not from a schema-per-tenant search_path.
            verify(connection, never()).prepareStatement(contains("search_path"));

            InOrder order = inOrder(connection, preparedStatement);
            order.verify(connection).setAutoCommit(false);
            order.verify(preparedStatement).execute();
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
        void save_insertFailure_logsClassNamesOnlyAtWarnAndThrowableAtDebug() throws SQLException {
            // Given: a driver error whose detail echoes the full session id
            SsoSession session = SsoSession.establish(TENANT, HOLDER_HASH, Duration.ofHours(1));
            String fullSessionId = session.getId().getValue();
            SQLException driverError = new SQLException("Key (id)=(" + fullSessionId + ") violates check", "23514");
            when(preparedStatement.executeUpdate()).thenThrow(driverError);

            // When
            List<ILoggingEvent> events = captureLogs(() -> assertThatThrownBy(() -> repository.save(session))
                    .isInstanceOf(SsoSessionRepositoryException.class));

            // Then
            ILoggingEvent warn = events.stream().filter(e -> e.getLevel() == Level.WARN).findFirst().orElseThrow();
            assertThat(warn.getFormattedMessage())
                    .endsWith("error=SQLException rootCause=SQLException")
                    .doesNotContain(fullSessionId);
            assertThat(warn.getThrowableProxy()).isNull();
            assertThat(events).anyMatch(e -> e.getLevel() == Level.DEBUG && e.getThrowableProxy() != null
                    && e.getThrowableProxy().getMessage().contains(fullSessionId));
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

        @Test
        void save_rollsBack_whenInsertThrowsUnexpectedRuntimeException() throws SQLException {
            // Arrange
            SsoSession session = SsoSession.establish(TENANT, HOLDER_HASH, Duration.ofHours(1));
            when(preparedStatement.executeUpdate()).thenThrow(new IllegalStateException("unexpected"));

            // Act / Assert
            assertThatThrownBy(() -> repository.save(session))
                    .isInstanceOf(IllegalStateException.class);

            verify(connection).rollback();
            verify(connection).setAutoCommit(true);
            verify(connection, never()).commit();
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
            // Arrange: 1st prepareStatement is the statement_timeout set_config, 2nd is the
            // business SELECT (no per-tenant search_path statement anymore — see NFR-S-149/H-10).
            when(connection.prepareStatement(anyString()))
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
        void findById_appliesStatementTimeoutAndCommits_withNoTenantFilter() throws SQLException {
            // Arrange
            when(preparedStatement.executeQuery()).thenReturn(resultSet);
            when(resultSet.next()).thenReturn(false);

            // Act
            Optional<SsoSession> result = repository.findById(SsoSessionId.generate());

            // Assert
            assertThat(result).isEmpty();
            verify(connection, never()).prepareStatement(contains("search_path"));
            verify(connection).prepareStatement(contains("set_config('statement_timeout'"));
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
            SsoSessionId sessionId = SsoSessionId.generate();
            Instant lastUsedAt = Instant.now(FIXED_CLOCK);

            // Act / Assert
            assertThatThrownBy(() -> repository.updateLastUsedAt(sessionId, TENANT, lastUsedAt))
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
            SsoSessionId sessionId = SsoSessionId.generate();

            // Act / Assert — best-effort tracking must never break establish/reuse
            assertDoesNotThrow(() -> repository.recordClientActivity(sessionId, TENANT, "client-a"));

            verify(connection).rollback();
        }

        @Test
        void recordClientActivity_failure_logsClassNamesOnlyAtWarnAndThrowableAtDebug() throws SQLException {
            // Given: an FK-violation detail echoing the full session id
            SsoSessionId sessionId = SsoSessionId.generate();
            String fullSessionId = sessionId.getValue();
            when(preparedStatement.executeUpdate()).thenThrow(new SQLException(
                    "Key (session_id)=(" + fullSessionId + ") is not present in table \"sso_session\"", "23503"));

            // When
            List<ILoggingEvent> events = captureLogs(
                    () -> repository.recordClientActivity(sessionId, TENANT, "client-a"));

            // Then
            ILoggingEvent warn = events.stream().filter(e -> e.getLevel() == Level.WARN).findFirst().orElseThrow();
            assertThat(warn.getFormattedMessage())
                    .endsWith("error=SQLException rootCause=SQLException")
                    .doesNotContain(fullSessionId);
            assertThat(warn.getThrowableProxy()).isNull();
            assertThat(events).anyMatch(e -> e.getLevel() == Level.DEBUG && e.getThrowableProxy() != null
                    && e.getThrowableProxy().getMessage().contains(fullSessionId));
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
