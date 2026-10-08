package group.phorus.authz.core.model

import java.util.UUID

/**
 * All the information an [AuthorizationEvaluator][group.phorus.authz.core.evaluation.AuthorizationEvaluator]
 * needs to make a decision.
 *
 * The context is assembled once per authorization check and passed through the entire evaluator chain.
 * Each evaluator reads the fields it cares about and ignores the rest.
 *
 * ### Example
 *
 * ```kotlin
 * val context = EvaluationContext(
 *     userId = UUID.fromString("7f3a9c1e-0b4d-4e26-91a8-2c5f6d0a7b31"),
 *     privileges = listOf("organization/org_123:manage", "report:read"),
 *     requiredPermission = Permission.parse("organization/org_123/project/proj_456:read"),
 *     attributes = mapOf(
 *         "user.region" to "EU",
 *         "resource.tags" to listOf("gdpr"),
 *         "env.business_hours" to true,
 *     ),
 * )
 * ```
 *
 * @property userId The authenticated user's identifier.
 * @property privileges The permission strings the subject holds, in the
 *   `<resource-path>:<action>` form [Permission] parses.
 * @property requiredPermission The permission needed to perform the requested action.
 * @property attributes A flat map of contextual attributes for ABAC evaluation. Keys follow the
 *   convention `category.name` (e.g., `"user.region"`, `"resource.tags"`, `"env.time"`).
 * @property grantToken The raw grant token string from the `X-Grant-Token` header, if present.
 * @property properties Additional key-value pairs that evaluators may use (e.g., role assignments,
 *   custom JWT claims).
 */
data class EvaluationContext(
    val userId: UUID,
    val privileges: List<String> = emptyList(),
    val requiredPermission: Permission,
    val attributes: Map<String, Any?> = emptyMap(),
    val grantToken: String? = null,
    val properties: Map<String, String> = emptyMap(),
)
