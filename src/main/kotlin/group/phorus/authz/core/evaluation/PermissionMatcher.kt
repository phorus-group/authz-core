package group.phorus.authz.core.evaluation

import group.phorus.authz.core.model.Permission

/**
 * Utility for matching permission strings with support for wildcards and hierarchy inheritance.
 *
 * This is the core matching engine used by RBAC, ReBAC, and other evaluators to determine
 * whether a granted permission covers a required permission.
 *
 * ### Matching rules
 *
 * 1. **Exact match**: `report:read` covers `report:read`.
 * 2. **Wildcard action**: `report:*` covers `report:read`, `report:update`, etc.
 * 3. **Wildcard instance**: an instance id of `*` covers every instance of that type.
 * 4. **Hierarchy inheritance**: `organization/org_123:read` covers
 *    `organization/org_123/project/proj_456:read` (parent cascades to children).
 * 5. **Superadmin**: `*:*` covers everything, and the bare `*` reads as `*:*`.
 *
 * ### Examples
 *
 * ```kotlin
 * val matcher = PermissionMatcher
 *
 * // Exact match
 * matcher.covers("report:read", "report:read")  // true
 *
 * // Wildcard type
 * matcher.covers("*:read", "organization/org_123:read")  // true
 *
 * // Hierarchy inheritance
 * matcher.covers("organization/org_123:read", "organization/org_123/project/proj_456:read")  // true
 *
 * // Superadmin
 * matcher.covers("*:*", "document/doc_789:delete")  // true
 * ```
 */
object PermissionMatcher {

    /**
     * Returns `true` if [granted] covers [required].
     *
     * @param granted The permission the user holds.
     * @param required The permission needed for the requested action.
     */
    fun covers(granted: Permission, required: Permission): Boolean = granted.covers(required)

    /**
     * Returns `true` if [granted] covers [required], parsing both from raw strings.
     *
     * @param granted The raw permission string the user holds.
     * @param required The raw permission string needed for the requested action.
     */
    fun covers(granted: String, required: String): Boolean =
        Permission.parse(granted).covers(Permission.parse(required))

    /**
     * Finds the first permission in [granted] that covers [required], or `null` if none match.
     *
     * @param granted The list of raw permission strings the user holds.
     * @param required The permission needed for the requested action.
     * @return The raw string of the first matching permission, or `null`.
     */
    fun findMatch(granted: List<String>, required: Permission): String? =
        granted.firstOrNull { Permission.parse(it).covers(required) }

    /**
     * Finds the first permission in [granted] that covers [required], or `null` if none match.
     *
     * @param granted The list of raw permission strings the user holds.
     * @param required The raw permission string needed for the requested action.
     * @return The raw string of the first matching permission, or `null`.
     */
    fun findMatch(granted: List<String>, required: String): String? =
        findMatch(granted, Permission.parse(required))

    /**
     * Returns `true` if any permission in [granted] covers [required].
     *
     * @param granted The list of raw permission strings the user holds.
     * @param required The permission needed for the requested action.
     */
    fun anyCovers(granted: List<String>, required: Permission): Boolean =
        findMatch(granted, required) != null

    /**
     * Returns `true` if any permission in [granted] covers [required].
     *
     * @param granted The list of raw permission strings the user holds.
     * @param required The raw permission string needed for the requested action.
     */
    fun anyCovers(granted: List<String>, required: String): Boolean =
        findMatch(granted, required) != null
}
