package group.phorus.authz.core.model

import java.util.UUID

/**
 * A role name, such as `ADMIN` or `REPORT_PUBLISHER`.
 *
 * @property value The name.
 */
@JvmInline
value class RoleName(val value: String)

/**
 * The place a role is held at: a resource type and one instance of that type.
 *
 * A role entry carries the scope it is held at, in two shapes:
 *
 * ```
 * ADMIN@organization:org_123     Scope("organization", "org_123")
 * OWNER                          PLATFORM
 * ```
 *
 * @property type The resource type the role is held at, e.g. `"organization"` or `"project"`.
 * @property id The identifier of the one resource of that type.
 */
data class Scope(val type: String, val id: String) {
    override fun toString() = "$type:$id"

    companion object {
        /** Where an unqualified role entry is held. */
        val PLATFORM = Scope("platform", "*")

        /**
         * Parses a raw `type:id` scope, or returns `null` when [raw] holds no `:` or either half is
         * blank.
         *
         * The first `:` separates the two, so an id may itself contain `:`.
         *
         * A role entry reaching this function came from outside the process, so a value that is not
         * `type:id` is answered with `null` and the caller drops the entry. That makes a malformed
         * entry grant nothing.
         *
         * @param raw The raw scope, e.g. `"organization:org_123"`.
         */
        fun parseOrNull(raw: String): Scope? =
            raw.split(':', limit = 2).takeIf { it.size == 2 && it.none(String::isBlank) }
                ?.let { Scope(it[0], it[1]) }
    }
}

/**
 * The subject a request acts for, and the authority carried on its behalf.
 *
 * @property subjectId The subject's identifier.
 * @property roles The roles the subject holds, keyed by the scope each is held at. A subject can
 *   hold several roles at one scope and roles at several scopes at once.
 * @property scope The delegated authority of the calling application, as the OAuth `scope` claim
 *   carried it. This is a separate thing from [Scope] above, which names a container a role is
 *   held at, and the two are independent. An `Authorizer` constructed with `narrowByScope = true`
 *   reads this claim; one left at the default decides from roles alone.
 */
data class Principal(
    val subjectId: UUID,
    val roles: Map<Scope, Set<RoleName>>,
    val scope: List<String> = emptyList(),
) {
    companion object {
        /**
         * Builds a [Principal] from the raw values of a `roles` claim.
         *
         * An entry carries the scope it is held at after an `@`, as in
         * `ADMIN@organization:org_123`, and an entry naming no scope is held at [Scope.PLATFORM].
         *
         * Entries arrive from outside the process, so one that is not in either shape grants
         * nothing rather than failing the request: a blank role name, or a scope half that
         * [Scope.parseOrNull] reads as `null`, is dropped and passed to [onDropped]. Log what
         * arrives there.
         *
         * @param subjectId The subject's identifier.
         * @param roleEntries The raw values of the `roles` claim.
         * @param scope The delegated authority of the calling application, as the OAuth `scope` claim
         *   carried it.
         * @param onDropped Called once per entry that parsed to nothing. Pass an empty lambda to
         *     accept the loss, which states the choice where a reader of the call can see it.
         */
        fun fromRoleEntries(
            subjectId: UUID,
            roleEntries: List<String>,
            scope: List<String> = emptyList(),
            onDropped: (String) -> Unit,
        ): Principal {
            val roles = roleEntries
                .mapNotNull { entry ->
                    val name = entry.substringBefore('@')
                    val entryScope =
                        if ('@' in entry) Scope.parseOrNull(entry.substringAfter('@')) else Scope.PLATFORM

                    if (name.isBlank() || entryScope == null) {
                        onDropped(entry)
                        null
                    } else {
                        entryScope to RoleName(name)
                    }
                }
                .groupBy({ it.first }, { it.second })
                .mapValues { (_, names) -> names.toSet() }

            return Principal(subjectId = subjectId, roles = roles, scope = scope)
        }
    }
}
