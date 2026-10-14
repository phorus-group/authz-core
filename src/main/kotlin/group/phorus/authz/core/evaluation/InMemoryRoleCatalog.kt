package group.phorus.authz.core.evaluation

import group.phorus.authz.core.model.RoleName

/**
 * A [RoleCatalog] answering from definitions already in memory.
 *
 * [permissions] reads the map this was built with, so a check stays synchronous and costs a lookup.
 * Role definitions change far less often than requests arrive, which is what makes one snapshot
 * workable for the life of a deployment.
 *
 * ```kotlin
 * val roles = InMemoryRoleCatalog(
 *     mapOf(
 *         RoleName("OWNER") to setOf("*"),
 *         RoleName("APPROVER") to setOf("document:approve", "document:read"),
 *     ),
 * )
 *
 * val authorizer = Authorizer(roles)
 * ```
 *
 * Where the definitions live in storage, read them once at startup and build a catalogue from what
 * you read. When they change, build another and swap the reference, so each check still reads a
 * complete snapshot:
 *
 * ```kotlin
 * @Volatile
 * private var catalog: RoleCatalog = InMemoryRoleCatalog(loadDefinitions())
 *
 * fun onDefinitionsChanged() {
 *     catalog = InMemoryRoleCatalog(loadDefinitions())
 * }
 * ```
 *
 * Reading storage inside [permissions] would put a round trip in front of every authorization, and
 * the signature forbids awaiting one.
 *
 * Where a senior role absorbs a junior one, compute the transitive closure before constructing
 * this, so [permissions] answers the union as one flat set.
 *
 * @param definitions The permissions each role grants. The map is copied, so changes to the
 *   argument after construction leave this catalogue as it was.
 */
class InMemoryRoleCatalog(definitions: Map<RoleName, Set<String>>) : RoleCatalog {

    private val definitions: Map<RoleName, Set<String>> = definitions.toMap()

    override fun permissions(role: RoleName): Set<String> = definitions[role].orEmpty()
}
