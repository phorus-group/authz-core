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
 * @property scope The delegated scope of the calling application, as the `scope` claim carried it.
 *   An `Authorizer` constructed with `narrowByScope = true` reads it; one left at the default
 *   ignores it.
 */
data class Principal(
    val subjectId: UUID,
    val roles: Map<Scope, Set<RoleName>>,
    val scope: List<String> = emptyList(),
)
