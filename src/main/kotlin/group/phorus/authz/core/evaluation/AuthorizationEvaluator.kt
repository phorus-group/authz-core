package group.phorus.authz.core.evaluation

import group.phorus.authz.core.model.AuthZResult
import group.phorus.authz.core.model.AuthZSource
import group.phorus.authz.core.model.EvaluationContext

/**
 * A single step in the authorization evaluation chain.
 *
 * Each authorization model (RBAC, ReBAC, ABAC, Grants) provides its own implementation
 * of this interface. The [AuthorizationChain] composes them into a sequential evaluation
 * that mirrors the flow described in the product plan:
 *
 * ```
 * RBAC → Implicit → ReBAC → ABAC → Grant → Deny
 * ```
 *
 * ### Contract
 *
 * - Return [AuthZResult.allowed] if this evaluator grants access.
 * - Return [AuthZResult.denied] if this evaluator explicitly denies access (e.g., ABAC constraint).
 * - Return [AuthZResult.abstain] if this evaluator has no opinion and the chain should continue.
 *
 * Evaluators must **never** throw exceptions for authorization decisions. Exceptions indicate
 * infrastructure failures (DB unreachable, invalid configuration), not access denials.
 *
 * ### Example implementation
 *
 * ```kotlin
 * class MyEvaluator : AuthorizationEvaluator {
 *     override val source = AuthZSource.RBAC
 *
 *     override suspend fun evaluate(context: EvaluationContext): AuthZResult {
 *         val matched = context.privileges.firstOrNull { privilege ->
 *             Permission.parse(privilege).covers(context.requiredPermission)
 *         }
 *         return if (matched != null) AuthZResult.allowed(source, matched)
 *         else AuthZResult.abstain()
 *     }
 * }
 * ```
 *
 * @see AuthorizationChain
 * @see AuthZResult
 */
interface AuthorizationEvaluator {
    /**
     * The authorization layer this evaluator represents.
     *
     * Recorded in [AuthZResult.source] for audit logging when this evaluator produces a decision.
     */
    val source: AuthZSource

    /**
     * Evaluates authorization for the given [context].
     *
     * @param context The evaluation context containing the user, required permission, attributes,
     *   and any grant tokens.
     * @return An [AuthZResult] with the evaluator's decision.
     */
    suspend fun evaluate(context: EvaluationContext): AuthZResult
}
