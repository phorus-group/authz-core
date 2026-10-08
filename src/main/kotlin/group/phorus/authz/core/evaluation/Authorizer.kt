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
 * [narrowByScope] adds a second condition for a deployment that issues tokens to third-party
 * integrations: the action also has to appear in [Principal.scope], which carries what the calling
 * application was granted consent to do under
 * [RFC 6749 §3.3](https://datatracker.ietf.org/doc/html/rfc6749#section-3.3). Turning it on makes
 * effective authority the intersection of the two, so an application never exceeds the subject it
 * acts for.
 *
 * ```kotlin
 * val authorizer = Authorizer(ApplicationRoles, narrowByScope = true)
 * ```
 *
 * @param catalog The role definitions for this deployment.
 * @param narrowByScope Whether [Principal.scope] is read as a second condition. The `scope` claim
 *   carries two kinds of value, and which kind a token holds is a property of the authorization
 *   server rather than something a library can read off the list. OpenID Connect identity scopes
 *   such as `openid profile email` grant access to identity claims, and API scopes name actions.
 *   Matching an action against a list holding `openid` answers nothing, so a deployment states which
 *   kind it issues by setting this. Leave it at `false` where the `scope` claim carries identity
 *   scopes or nothing; set it to `true` once the authorization server issues API scopes drawn from
 *   the same action vocabulary as [RoleCatalog], such as `"report:read document:approve"`.
 */
class Authorizer(
    private val catalog: RoleCatalog,
    private val narrowByScope: Boolean = false,
) {

    /**
     * Returns `true` when [principal] may perform [action] on an object sitting in [scopes].
     *
     * @param principal The subject, its roles, and the delegated scope of the application acting
     *   for it.
     * @param action An action from the catalogue's vocabulary, e.g. `"document:approve"`.
     * @param scopes The chain the target object sits in, outermost first, for example
     *   `[Scope("organization", organizationId), Scope("project", projectId)]`. A role held at any
     *   link in the chain grants the action, and [Scope.PLATFORM] is consulted on every call. The
     *   caller supplies the chain because the object's place in the hierarchy is known where the
     *   object is.
     */
    fun permits(principal: Principal, action: String, scopes: List<Scope>): Boolean =
        rolesGrant(principal, action, scopes) && scopeAllows(principal, action)

    private fun rolesGrant(principal: Principal, action: String, scopes: List<Scope>): Boolean =
        (scopes + Scope.PLATFORM).any { scope ->
            principal.roles[scope].orEmpty().any { role ->
                catalog.permissions(role).let { "*" in it || action in it }
            }
        }

    private fun scopeAllows(principal: Principal, action: String): Boolean =
        !narrowByScope || action in principal.scope
}
