package group.phorus.authz.core.model


/**
 * All the information an [AuthorizationEvaluator][group.phorus.authz.core.evaluation.AuthorizationEvaluator]
 * needs to make a decision.
 *
 * The context is assembled once per authorization check and passed through the entire evaluator chain.
 * Each evaluator reads the fields it cares about and ignores the rest.
 *
 * ### Example
 *
 * Carrying the subject here is what lets one chain serve every request. An evaluator reads
 * [principal] off the context rather than holding one, so the chain can be built once at startup.
 *
 * ### Example
 *
 * ```kotlin
 * val context = EvaluationContext(
 *     principal = principal,
 *     requiredPermission = Permission.parse("organization/org_123/project/proj_456:read"),
 *     scopes = listOf(Scope("organization", "org_123"), Scope("project", "proj_456")),
 *     permissions = listOf("organization/org_123:*", "report:read"),
 *     attributes = mapOf(
 *         "user.region" to "EU",
 *         "resource.tags" to listOf("gdpr"),
 *         "env.business_hours" to true,
 *     ),
 * )
 * ```
 *
 * @property principal The subject the request acts for, its scoped roles, and the delegated scope.
 * @property requiredPermission The permission needed to perform the requested action.
 * @property scopes The chain the target object sits in, outermost first, which a scoped-role
 *   evaluator reads. Empty where the check runs before the object is known.
 * @property permissions The permission strings the subject holds, in the
 *   `<resource-path>:<action>` form [Permission] parses.
 * @property attributes A flat map of contextual attributes for ABAC evaluation. Keys follow the
 *   convention `category.name` (e.g., `"user.region"`, `"resource.tags"`, `"env.time"`).
 * @property grantToken The raw grant token string from the `X-Grant-Token` header, if present.
 * @property properties Additional key-value pairs that evaluators may use (e.g., role assignments,
 *   custom JWT claims).
 */
data class EvaluationContext(
    val principal: Principal,
    val requiredPermission: Permission,
    val scopes: List<Scope> = emptyList(),
    val permissions: List<String> = emptyList(),
    val attributes: Map<String, Any?> = emptyMap(),
    val grantToken: String? = null,
    val properties: Map<String, String> = emptyMap(),
)
