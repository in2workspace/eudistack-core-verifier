package es.in2.vcverifier.sso.domain.model;

import java.util.Objects;

/**
 * Resultado de la evaluación de reutilización de sesión SSO.
 * Representa el outcome final del flujo de decisión:
 * - ALLOWED (con sesión)
 * - LOGIN_REQUIRED
 * - INTERACTION_REQUIRED
 */
public sealed interface ReuseResult
        permits ReuseResult.Allowed,
                ReuseResult.LoginRequired,
                ReuseResult.InteractionRequired {

    // =========================
    // Factory methods
    // =========================

    static ReuseResult allowed(SsoSession session) {
        return new Allowed(session);
    }

    static ReuseResult loginRequired() {
        return LoginRequired.INSTANCE;
    }

    static ReuseResult interactionRequired() {
        return InteractionRequired.INSTANCE;
    }

    // =========================
    // Variants
    // =========================

    /**
     * Caso exitoso: reutilización permitida con sesión activa.
     */
    final class Allowed implements ReuseResult {

        private final SsoSession session;

        private Allowed(SsoSession session) {
            this.session = Objects.requireNonNull(session, "session must not be null");
        }

        public SsoSession session() {
            return session;
        }
    }

    /**
     * No se puede reutilizar sesión → requiere login completo.
     */
    final class LoginRequired implements ReuseResult {

        private static final LoginRequired INSTANCE = new LoginRequired();

        private LoginRequired() {
        }
    }

    /**
     * Existe sesión pero requiere interacción del usuario
     * (ej: consentimiento, step-up auth, MFA, etc.)
     */
    final class InteractionRequired implements ReuseResult {

        private static final InteractionRequired INSTANCE = new InteractionRequired();

        private InteractionRequired() {
        }
    }
}