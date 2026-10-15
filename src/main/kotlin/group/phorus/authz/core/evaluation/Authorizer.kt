package group.phorus.authz.core.evaluation

import group.phorus.authz.core.model.Principal
import group.phorus.authz.core.model.Scope

/**
 * Decides whether a principal may perform an action on an object, reading the principal alone.
 *
 * The roles the subject holds have to grant the action somewhere in the object's scope chain. A
 * subject may act when any held role grants the action, which is core RBAC as standardised in
 * ANSI INCITS 359-2004, where a session's permissions are the union over its activated roles.
 *
 * ```kotlin
 * val authorizer = Authorizer(ApplicationRoles)
 *
 * val chain = listOf(
 *     Scope("organization", organizationId.toString()),
 *     Scope("project", projectId.toString()),
 * )
 *
 * authorizer.permits(principal, "document:approve", chain)
 * ```
 *
 * A second condition reads [Principal.scope], the OAuth `scope` claim carrying what the calling
 * application was granted consent to do under
 * [RFC 6749 §3.3](https://datatracker.ietf.org/doc/html/rfc6749#section-3.3). That claim is a
 * separate thing from [Scope], the container a role is held at. Effective authority is the
 * intersection of the two, so an application never exceeds the subject it acts for. The claim can
 * only subtract, since the roles have to grant the permission either way.
 *
 * A token issued to the subject directly, with no application in between, carries
 * [UNRESTRICTED] as its only scope value and the second condition passes. A token issued to an
 * application carries the permissions that application was consented, in the catalogue's
 * vocabulary. Which kind a token is therefore travels in the token, where the claim already is,
 * rather than in a deployment-wide setting.
 *
 * ```kotlin
 * Principal(subjectId, roles, scope = listOf(Authorizer.UNRESTRICTED))   // a direct login
 * Principal(subjectId, roles, scope = listOf("document:read"))           // consented to one thing
 * ```
 *
 * An empty claim grants nothing, so a token carrying no scope is refused rather than treated as
 * unrestricted.
 *
 * @param catalog The role definitions for this deployment.
 */
class Authorizer(
    private val catalog: RoleCatalog,
) {

    /**
     * Returns `true` when [principal] may exercise [permission] on an object sitting in [scopes].
     *
     * @param principal The subject, its roles, and the delegated scope of the application acting
     *   for it.
     * @param permission A permission from the catalogue's vocabulary, e.g. `"document:approve"`.
     * @param scopes The chain the target object sits in, outermost first, for example
     *   `[Scope("organization", organizationId), Scope("project", projectId)]`. A role held at any
     *   link in the chain grants it, and [Scope.PLATFORM] is consulted on every call. The
     *   caller supplies the chain because the object's place in the hierarchy is known where the
     *   object is.
     */
    fun permits(principal: Principal, permission: String, scopes: List<Scope>): Boolean =
        rolesGrant(principal, permission, scopes) && scopeAllows(principal, permission)

    /**
     * Returns `true` when [principal] holds [permission] at any scope it holds a role at.
     *
     * A check that runs before the object is loaded has no scope chain to pass, and
     * [permits] with an empty chain consults [Scope.PLATFORM] alone. This covers the wider case a
     * route gate needs, whether the subject holds the permission anywhere. A gate using it still
     * needs the narrower [permits] once the object is loaded, because holding a permission
     * somewhere leaves open whether it holds over that object.
     *
     * @param principal The subject, its roles, and the delegated scope of the application acting
     *   for it.
     * @param permission A permission from the catalogue's vocabulary, e.g. `"document:approve"`.
     */
    fun permitsAnywhere(principal: Principal, permission: String): Boolean =
        principal.roles.keys.any { permits(principal, permission, listOf(it)) }

    private fun rolesGrant(principal: Principal, permission: String, scopes: List<Scope>): Boolean =
        (scopes + Scope.PLATFORM).any { scope ->
            principal.roles[scope].orEmpty().any { role ->
                catalog.permissions(role).let { "*" in it || permission in it }
            }
        }

    private fun scopeAllows(principal: Principal, permission: String): Boolean =
        UNRESTRICTED in principal.scope || permission in principal.scope

    companion object {

        /**
         * The `scope` value a token carries when no application stands between the subject and the
         * request, so the roles alone decide. One value rather than the subject's whole permission
         * set, which keeps a token holding roles at several containers inside the 4096 bytes
         * [RFC 6265 §6.1](https://datatracker.ietf.org/doc/html/rfc6265#section-6.1) requires a
         * cookie to support.
         */
        const val UNRESTRICTED = "*"
    }
}
