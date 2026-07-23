package es.in2.vcverifier.sso.domain.model;

/**
 * Resultado de una notificación de Single Logout (US-06) a un callee concreto,
 * devuelto por {@code BackChannelLogoutNotifierPort#notifyLogout}.
 * <p>
 * Sellado para forzar pattern matching exhaustivo en el llamante (workflow) al decidir
 * entre emitir {@code backchannel_delivered} o {@code backchannel_failed} (AC-06).
 */
public sealed interface DeliveryOutcome permits DeliveryOutcome.Delivered, DeliveryOutcome.Failed {

    record Delivered(String clientId) implements DeliveryOutcome {}

    record Failed(String clientId, String reason) implements DeliveryOutcome {}
}