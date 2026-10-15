package group.phorus.authz.core.evaluation

import group.phorus.authz.core.model.AuthZResult
import group.phorus.authz.core.model.AuthZSource
import group.phorus.authz.core.model.EvaluationContext

/**
 * An [AuthorizationEvaluator] deciding from the scoped roles a subject holds.
 *
 * This is what puts the scoped-role model into an [AuthorizationChain], so a service deciding from
 * several sources together gets the same decision from roles that [Authorizer.permits] gives on its
 * own. It reads [EvaluationContext.principal] and [EvaluationContext.scopes], so one instance
 * serves every request.
 *
 * The required permission arrives parsed, and a catalogue holds the unparsed form, so the two
 * halves are joined back together: the leaf segment's type and the action, which is the spelling a
 * catalogue entry uses.
 *
 * ```kotlin
 * val chain = AuthorizationChain.standard(
 *     rbac = ScopedRoleEvaluator(authorizer),
 *     abac = businessHoursPolicy,
 * )
 * ```
 *
 * A grant reports [AuthZSource.RBAC] naming the permission that matched. Anything else abstains,
 * which leaves the decision to the rest of the chain rather than refusing on its own.
 *
 * @param authorizer The scoped-role check this delegates to.
 */
class ScopedRoleEvaluator(
    private val authorizer: Authorizer,
) : AuthorizationEvaluator {

    override val source: AuthZSource = AuthZSource.RBAC

    override suspend fun evaluate(context: EvaluationContext): AuthZResult {
        val required = context.requiredPermission
        val permission = "${required.resourcePath.leaf.type}:${required.action}"

        return if (authorizer.permits(context.principal, permission, context.scopes)) {
            AuthZResult.allowed(source = source, matched = permission)
        } else {
            AuthZResult.abstain()
        }
    }
}
