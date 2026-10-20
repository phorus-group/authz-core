package group.phorus.authz.core.model

/**
 * A parsed permission string consisting of a [resourcePath] and an [action].
 *
 * Permission strings follow the format `<resource-path>:<action>`, where the resource path
 * encodes the hierarchical location of the resource and the action describes what operation
 * is being performed.
 *
 * ### Format
 *
 * ```
 * <resource-path>:<action>
 * ```
 *
 * ### Standard actions
 *
 * | Written | Meaning |
 * |---------|---------|
 * | `create` | Create a new resource |
 * | `read` | Read a single resource |
 * | `list` | List resources |
 * | `update` | Modify an existing resource |
 * | `delete` | Remove a resource |
 * | `:*` | Full control over the resource the permission names, as in `report:*` |
 * | `*` | Full control over every path, the whole string, equal to `*:*` |
 *
 * ### Examples
 *
 * ```kotlin
 * Permission.parse("organization:create")                                     // type-level
 * Permission.parse("organization/org_123:read")                               // instance-level
 * Permission.parse("organization/org_123/project/proj_456:update")            // nested
 * // Wildcard: Permission(resourcePath=["organization","*"], action="read")
 * Permission.parse("*:*")                                                     // superadmin
 * Permission.parse("*")                                                       // the same, as a role spells it
 * ```
 *
 * ### Matching rules
 *
 * A permission **covers** another when:
 * 1. Its [resourcePath] covers the other's resource path (exact match, wildcard, or ancestor), **and**
 * 2. Its [action] covers the other's action (`*` covers every action, exact match otherwise).
 *
 * @property resourcePath The hierarchical resource location.
 * @property action The operation being performed or permitted.
 * @see ResourcePath
 */
data class Permission(
    val resourcePath: ResourcePath,
    val action: String,
) {
    /** The raw string representation of this permission. */
    val raw: String get() = "$resourcePath:$action"

    /**
     * Checks whether this permission covers [other].
     *
     * Coverage means this permission is equal to or broader than [other]. A broader permission
     * grants access to everything the narrower one does, and possibly more.
     *
     * ```kotlin
     * val broad = Permission.parse("organization/org_123:*")
     * val narrow = Permission.parse("organization/org_123/project/proj_456:read")
     * broad.covers(narrow)  // true: every action on the parent covers read on the child
     * narrow.covers(broad)  // false
     * ```
     */
    fun covers(other: Permission): Boolean {
        if (!resourcePath.covers(other.resourcePath)) return false
        return actionCovers(action, other.action)
    }

    override fun toString(): String = raw

    companion object {
        /** The wildcard token that matches any action. */
        const val WILDCARD_ACTION = "*"

        /**
         * Parses a raw permission string into a [Permission].
         *
         * The string carries a `:` separating the resource path from the action, or is the bare
         * `*` that a role catalogue spells full control with, which reads as `*:*`.
         *
         * @param raw The permission string, e.g. `"organization/org_123:read"`.
         * @throws IllegalArgumentException if the format is invalid.
         */
        fun parse(raw: String): Permission {
            require(raw.isNotBlank()) { "Permission string must not be blank" }

            // A role catalogue spells full control `*`, so the same string reads here as `*:*`.
            if (raw == WILDCARD_ACTION) {
                return Permission(
                    resourcePath = ResourcePath.parse(WILDCARD_ACTION),
                    action = WILDCARD_ACTION,
                )
            }

            val colonIndex = raw.lastIndexOf(':')
            require(colonIndex > 0 && colonIndex < raw.length - 1) {
                "Permission string must contain ':' separating resource path and action: \"$raw\""
            }

            val resourceRaw = raw.substring(0, colonIndex)
            val action = raw.substring(colonIndex + 1)

            return Permission(
                resourcePath = ResourcePath.parse(resourceRaw),
                action = action,
            )
        }

        /**
         * Returns `true` if [granted] action covers [required] action.
         *
         * - `*` covers every action.
         * - Otherwise, exact string match.
         */
        fun actionCovers(granted: String, required: String): Boolean = when (granted) {
            WILDCARD_ACTION -> true
            else -> granted == required
        }
    }
}
