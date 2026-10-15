package group.phorus.authz.core.evaluation

import group.phorus.authz.core.model.RoleName

/**
 * Maps a role name to the permissions that role grants.
 *
 * An implementation is static application code: one definition per role for the whole deployment,
 * held in memory and read on every check.
 *
 * A permission names a resource type and an action, `"report:read"` or `"document:approve"`. The
 * object it applies to comes from the scope chain passed to [Authorizer.permits]. The entry `"*"`
 * grants everything.
 *
 * ```kotlin
 * object ApplicationRoles : RoleCatalog {
 *
 *     private val definitions = mapOf(
 *         "OWNER" to setOf("*"),
 *         "APPROVER" to setOf("document:approve", "document:read"),
 *         "VIEWER" to setOf("report:read", "project:read", "document:read"),
 *     )
 *
 *     override fun permissions(role: RoleName): Set<String> = definitions[role.value].orEmpty()
 * }
 * ```
 *
 * Where a senior role absorbs a junior one, which is hierarchical RBAC as standardised in
 * ANSI INCITS 359-2004, compute the transitive closure once at startup inside the implementation so
 * callers read a flat set.
 */
interface RoleCatalog {
    /**
     * Returns the actions [role] grants.
     *
     * An implementation has to return the empty set for an unknown name, which the `orEmpty()`
     * above is doing. [Authorizer] calls this for the names a principal holds at the scopes it is
     * checking, and those names arrived from outside the process, so it is called with unknown,
     * misspelled and withdrawn names too. The empty set grants no action, which is what makes such a name safe.
     *
     * @param role The role name taken from a role entry.
     */
    fun permissions(role: RoleName): Set<String>
}
