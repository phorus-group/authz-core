package group.phorus.authz.core.model

import java.util.UUID

/**
 * The outcome of a single authorization evaluation step.
 *
 * Evaluators return one of three decisions:
 *
 * | Decision | Meaning |
 * |----------|---------|
 * | [PolicyDecision.ALLOW] | Access is explicitly granted. |
 * | [PolicyDecision.DENY] | Access is explicitly denied. |
 * | [PolicyDecision.ABSTAIN] | This evaluator has no opinion; defer to the next one in the chain. |
 *
 * @property decision The authorization decision.
 * @property source Which authorization layer produced this result, or `null` if the evaluator abstained.
 * @property matched A human-readable description of what matched (permission string, relationship, policy name).
 * @property grantId The grant identifier, populated when [source] is [AuthZSource.GRANT].
 * @property reason A human-readable explanation, especially useful for denials and audit logging.
 * @see AuthZSource
 * @see PolicyDecision
 */
data class AuthZResult(
    val decision: PolicyDecision,
    val source: AuthZSource? = null,
    val matched: String? = null,
    val grantId: UUID? = null,
    val reason: String? = null,
) {
    /** `true` when the decision is [PolicyDecision.ALLOW]. */
    val allowed: Boolean get() = decision == PolicyDecision.ALLOW

    /** `true` when the decision is [PolicyDecision.DENY]. */
    val denied: Boolean get() = decision == PolicyDecision.DENY

    /** `true` when the evaluator abstained (no opinion). */
    val abstained: Boolean get() = decision == PolicyDecision.ABSTAIN

    companion object {
        /**
         * Creates an [ALLOW][PolicyDecision.ALLOW] result.
         *
         * @param source The authorization layer that granted access.
         * @param matched Description of what permission, relationship, or policy matched.
         * @param grantId The grant ID, if this was a grant-based decision.
         */
        fun allowed(
            source: AuthZSource,
            matched: String,
            grantId: UUID? = null,
        ) = AuthZResult(
            decision = PolicyDecision.ALLOW,
            source = source,
            matched = matched,
            grantId = grantId,
        )

        /**
         * Creates a [DENY][PolicyDecision.DENY] result.
         *
         * @param reason A human-readable denial reason for audit logging.
         * @param source The authorization layer that denied access, if known.
         * @param matched Description of what triggered the denial (e.g., the ABAC policy name).
         */
        fun denied(
            reason: String,
            source: AuthZSource? = null,
            matched: String? = null,
        ) = AuthZResult(
            decision = PolicyDecision.DENY,
            source = source,
            matched = matched,
            reason = reason,
        )

        /**
         * Creates an [ABSTAIN][PolicyDecision.ABSTAIN] result, indicating this evaluator
         * has no opinion and the chain should continue to the next evaluator.
         */
        fun abstain() = AuthZResult(decision = PolicyDecision.ABSTAIN)
    }
}

/**
 * The three possible outcomes of a policy evaluation.
 *
 * Used by [AuthorizationEvaluator][group.phorus.authz.core.evaluation.AuthorizationEvaluator]
 * implementations to signal their decision.
 */
enum class PolicyDecision {
    /** Access is explicitly granted. */
    ALLOW,

    /** Access is explicitly denied. */
    DENY,

    /** No opinion; defer to the next evaluator in the chain. */
    ABSTAIN,
}

/**
 * Identifies which authorization layer produced an [AuthZResult].
 *
 * Recorded in audit logs so that operators can trace exactly *why* a request was allowed or denied.
 *
 * | Source | Layer | Example |
 * |--------|-------|---------|
 * | [IMPLICIT] | Baseline permissions | `user/self:read` granted to every authenticated user |
 * | [RBAC] | Role-Based Access Control | User's `Developer` role includes `bit:read` |
 * | [REBAC] | Relationship-Based Access Control | User is the owner of `organization/org_123` |
 * | [ABAC] | Attribute-Based Access Control | GDPR policy denies non-EU user access to tagged resource |
 * | [GRANT] | JIT Grants | One-time approval grant for `installation/inst_789:approve` |
 */
enum class AuthZSource {
    /** Baseline permissions granted to every authenticated user. */
    IMPLICIT,

    /** Role-Based Access Control: permissions derived from assigned roles. */
    RBAC,

    /** Relationship-Based Access Control: permissions derived from resource relationships. */
    REBAC,

    /** Attribute-Based Access Control: permissions derived from contextual attributes. */
    ABAC,

    /** JIT Grants: temporary, scoped permissions issued on demand. */
    GRANT,
}
