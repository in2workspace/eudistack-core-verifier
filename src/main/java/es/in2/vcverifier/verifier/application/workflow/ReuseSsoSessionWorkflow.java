package es.in2.vcverifier.verifier.application.workflow;

import es.in2.vcverifier.oauth2.domain.model.AuthorizationContext;

public interface ReuseSsoSessionWorkflow {

    Result reuse(String tenantSlug, String ssoCookieValue, AuthorizationContext ctx, String clientId);

    record Result(
            Status status,
            String redirectUrl
    ) {
        public enum Status {
            ALLOWED,
            LOGIN_REQUIRED,
            INTERACTION_REQUIRED
        }
    }
}
