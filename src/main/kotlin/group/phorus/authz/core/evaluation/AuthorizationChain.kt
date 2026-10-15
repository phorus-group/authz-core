package group.phorus.authz.core.evaluation

import group.phorus.authz.core.model.AuthZResult
import group.phorus.authz.core.model.EvaluationContext
import group.phorus.authz.core.model.PolicyDecision

/**
 * Composes multiple [AuthorizationEvaluator]s into a sequential evaluation chain.
 *
 * The chain processes evaluators in order. For most evaluators, the first [ALLOW][PolicyDecision.ALLOW]
 * stops the chain and returns that result. However, **constraint evaluators** (like ABAC) can
 * [DENY][PolicyDecision.DENY] even after a previous evaluator allowed access.
 *
 * ### Evaluation flow
 *
 * The order the [standard] factory composes:
 *
 * ```
 * RBAC → Implicit → ReBAC → ABAC (constraint) → Grant → Deny
 * ```
 *
 * 1. **Granting evaluators** (RBAC, Implicit, ReBAC): First ALLOW wins.
 * 2. **Constraint evaluators** (ABAC): Run after a granting evaluator ALLOWs.
 *    If any constraint DENYs, the denial overrides the ALLOW.
 * 3. **Fallback evaluators** (Grant): Only checked if no granting evaluator allowed.
 * 4. **Default deny**: If no evaluator grants access, the chain returns DENY.
 *
 * ### Example
 *
 * ```kotlin
 * val chain = AuthorizationChain(
 *     grantingEvaluators = listOf(rbacEvaluator, implicitEvaluator, rebacEvaluator),
 *     constraintEvaluators = listOf(abacEvaluator),
 *     fallbackEvaluators = listOf(grantEvaluator),
 * )
 *
 * val result = chain.evaluate(context)
 * if (result.allowed) { // proceed }
 * ```
 *
 * @property grantingEvaluators Evaluators that can grant access (RBAC, Implicit, ReBAC).
 *   Evaluated in order; first ALLOW wins.
 * @property constraintEvaluators Evaluators that can deny access even after a grant (ABAC).
 *   Evaluated in order until one returns DENY, and that DENY overrides the grant.
 * @property fallbackEvaluators Evaluators checked only when no granting evaluator allowed (Grant).
 *   Evaluated in order; first ALLOW wins.
 */
class AuthorizationChain(
    private val grantingEvaluators: List<AuthorizationEvaluator> = emptyList(),
    private val constraintEvaluators: List<AuthorizationEvaluator> = emptyList(),
    private val fallbackEvaluators: List<AuthorizationEvaluator> = emptyList(),
) {
    /**
     * Evaluates the full authorization chain for the given [context].
     *
     * @return The final [AuthZResult]. If no evaluator produces a decision,
     *   returns a DENY with a descriptive reason.
     */
    suspend fun evaluate(context: EvaluationContext): AuthZResult {
        // Phase 1: Granting evaluators, first ALLOW wins
        var grantResult: AuthZResult? = null
        for (evaluator in grantingEvaluators) {
            val result = evaluator.evaluate(context)
            when (result.decision) {
                PolicyDecision.ALLOW -> { grantResult = result; break }
                PolicyDecision.DENY -> return result  // Explicit deny from granting evaluator
                PolicyDecision.ABSTAIN -> continue
            }
        }

        // Phase 2: Constraint evaluators, any DENY overrides the grant
        if (grantResult != null) {
            for (evaluator in constraintEvaluators) {
                val result = evaluator.evaluate(context)
                if (result.denied) return result  // Constraint denial overrides the grant
            }
            return grantResult  // Grant stands; no constraints denied
        }

        // Phase 3: Fallback evaluators, checked only when no granting evaluator allowed
        for (evaluator in fallbackEvaluators) {
            val result = evaluator.evaluate(context)
            when (result.decision) {
                PolicyDecision.ALLOW -> {
                    // Still check constraints on fallback grants
                    for (constraint in constraintEvaluators) {
                        val constraintResult = constraint.evaluate(context)
                        if (constraintResult.denied) return constraintResult
                    }
                    return result
                }
                PolicyDecision.DENY -> return result
                PolicyDecision.ABSTAIN -> continue
            }
        }

        // Phase 4: Default deny
        return AuthZResult.denied(
            reason = "Access denied to ${context.requiredPermission}. No evaluator granted access.",
        )
    }

    companion object {
        /**
         * Creates an [AuthorizationChain] with the standard evaluation order:
         * RBAC → Implicit → ReBAC (granting), ABAC (constraint), Grant (fallback).
         *
         * Pass `null` for any evaluator to skip that layer.
         */
        fun standard(
            rbac: AuthorizationEvaluator? = null,
            implicit: AuthorizationEvaluator? = null,
            rebac: AuthorizationEvaluator? = null,
            abac: AuthorizationEvaluator? = null,
            grant: AuthorizationEvaluator? = null,
        ) = AuthorizationChain(
            grantingEvaluators = listOfNotNull(rbac, implicit, rebac),
            constraintEvaluators = listOfNotNull(abac),
            fallbackEvaluators = listOfNotNull(grant),
        )
    }
}
