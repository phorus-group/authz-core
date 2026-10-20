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

    companion object {

        /**
         * Returns the [entries] holding a `*` that [Authorizer] reads as an ordinary character,
         * sorted.
         *
         * An entry is `type:action`, and a `*` standing alone as the whole entry, as the type or
         * as the action is read as every value of that part. A `*` anywhere else belongs to a
         * name, so `doc*:read` grants the action `read` on a type called `doc*` and `report:re*d`
         * grants an action called `re*d`. A path carrying an instance wildcard reads the same way,
         * because the whole path is the type half. Each reads as breadth and grants the one
         * permission it spells.
         *
         * Call this wherever definitions enter the process and refuse what it returns, so an
         * entry meaning less than it reads is reported where somebody can correct it:
         *
         * ```kotlin
         * val unreadable = RoleCatalog.unreadableWildcards(definitions.values.flatten())
         * require(unreadable.isEmpty()) { "These role entries grant one permission each: $unreadable" }
         * ```
         *
         * @param entries The permissions the definitions grant, from every role together or one
         *   role at a time.
         */
        fun unreadableWildcards(entries: Iterable<String>): List<String> =
            entries.filter { entry ->
                val colon = entry.lastIndexOf(':')
                if (colon <= 0 || colon == entry.length - 1) {
                    entry != Authorizer.UNRESTRICTED && entry.contains('*')
                } else {
                    partIsName(entry.substring(0, colon)) || partIsName(entry.substring(colon + 1))
                }
            }.distinct().sorted()

        /** Whether a type or an action holds a `*` that belongs to a name rather than standing for one. */
        private fun partIsName(part: String): Boolean =
            part.contains('*') && part != Authorizer.UNRESTRICTED
    }
}
