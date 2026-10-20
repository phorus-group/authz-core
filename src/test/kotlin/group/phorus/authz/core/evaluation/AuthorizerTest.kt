package group.phorus.authz.core.evaluation

import group.phorus.authz.core.model.Principal
import group.phorus.authz.core.model.RoleName
import group.phorus.authz.core.model.Scope
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.util.UUID
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AuthorizerTest {

    private val catalog = object : RoleCatalog {
        private val definitions = mapOf(
            OWNER to setOf("*"),
            ADMIN to setOf("project:manage", "report:manage", "document:approve"),
            DEVELOPER to setOf("report:read", "document:create", "document:publish"),
            APPROVER to setOf("document:approve", "document:read"),
            EDITOR to setOf("document:*"),
        )

        override fun permissions(role: RoleName): Set<String> = definitions[role].orEmpty()
    }

    private val authorizer = Authorizer(catalog)

    private val organization = Scope("organization", ORGANIZATION_ID)
    private val project = Scope("project", PROJECT_ID)
    private val otherProject = Scope("project", OTHER_PROJECT_ID)

    private fun principal(
        roles: Map<Scope, Set<RoleName>>,
        scope: List<String> = listOf(Authorizer.UNRESTRICTED),
    ) = Principal(
        subjectId = UUID.fromString(SUBJECT_ID),
        roles = roles,
        scope = scope,
    )

    @Nested
    @DisplayName("Roles and the scope chain")
    inner class RolesAndTheScopeChain {
        @Test
        fun `role held at a scope in the chain grants the action`() {
            val subject = principal(mapOf(organization to setOf(ADMIN)))
            assertTrue(authorizer.permits(subject, "report:manage", listOf(organization)))
        }

        @Test
        fun `role held at an outer link grants at an inner one`() {
            val subject = principal(mapOf(organization to setOf(ADMIN)))
            assertTrue(
                authorizer.permits(subject, "document:approve", listOf(organization, project))
            )
        }

        @Test
        fun `role held at an inner link grants when the chain reaches it`() {
            val subject = principal(mapOf(project to setOf(APPROVER)))
            assertTrue(
                authorizer.permits(subject, "document:approve", listOf(organization, project))
            )
        }

        @Test
        fun `role held at a scope the chain omits grants nothing`() {
            val subject = principal(mapOf(organization to setOf(ADMIN)))
            assertFalse(authorizer.permits(subject, "report:manage", listOf(project)))
        }

        @Test
        fun `role held at another instance of the same type grants nothing`() {
            val subject = principal(mapOf(otherProject to setOf(APPROVER)))
            assertFalse(
                authorizer.permits(subject, "document:approve", listOf(organization, project))
            )
        }

        @Test
        fun `action no held role lists is refused`() {
            val subject = principal(mapOf(project to setOf(DEVELOPER)))
            assertFalse(
                authorizer.permits(subject, "document:approve", listOf(organization, project))
            )
        }

        @Test
        fun `role the catalogue holds no definition for grants nothing`() {
            val subject = principal(mapOf(organization to setOf(RoleName("UNDEFINED"))))
            assertFalse(authorizer.permits(subject, "report:read", listOf(organization)))
        }
    }

    @Nested
    @DisplayName("Platform scope")
    inner class PlatformScope {
        @Test
        fun `entry held at the platform scope grants inside a chain`() {
            val subject = principal(mapOf(Scope.PLATFORM to setOf(OWNER)))
            assertTrue(
                authorizer.permits(subject, "report:manage", listOf(organization, project))
            )
        }

        @Test
        fun `entry held at the platform scope grants with an empty chain`() {
            val subject = principal(mapOf(Scope.PLATFORM to setOf(OWNER)))
            assertTrue(authorizer.permits(subject, "report:manage", emptyList()))
        }

        @Test
        fun `empty chain refuses a subject holding only scoped roles`() {
            val subject = principal(mapOf(organization to setOf(ADMIN)))
            assertFalse(authorizer.permits(subject, "report:manage", emptyList()))
        }
    }

    @Nested
    @DisplayName("Wildcard catalogue entry")
    inner class WildcardCatalogueEntry {
        @Test
        fun `star grants an action the definition does not list`() {
            val subject = principal(mapOf(organization to setOf(OWNER)))
            assertTrue(authorizer.permits(subject, "document:approve", listOf(organization)))
        }

        @Test
        fun `star grants the star action`() {
            val subject = principal(mapOf(organization to setOf(OWNER)))
            assertTrue(authorizer.permits(subject, "*", listOf(organization)))
        }

        @Test
        fun `definition without star refuses the star action`() {
            val subject = principal(mapOf(organization to setOf(ADMIN)))
            assertFalse(authorizer.permits(subject, "*", listOf(organization)))
        }
    }

    @Nested
    @DisplayName("Catalogue entry ending in a star")
    inner class TypeWildcardCatalogueEntry {
        private val editor = principal(mapOf(organization to setOf(EDITOR)))

        @Test
        fun `an entry ending in a wildcard grants every action on that type`() {
            assertTrue(authorizer.permits(editor, "document:read", listOf(organization)))
            assertTrue(authorizer.permits(editor, "document:approve", listOf(organization)))
            assertTrue(authorizer.permits(editor, "document:anything-added-later", listOf(organization)))
        }

        @Test
        fun `it grants the star action on the type it names`() {
            assertTrue(authorizer.permits(editor, "document:*", listOf(organization)))
        }

        @Test
        fun `a wildcard reaches its own type and no other`() {
            assertFalse(authorizer.permits(editor, "report:read", listOf(organization)))
            assertFalse(authorizer.permits(editor, "documentary:read", listOf(organization)))
            assertFalse(authorizer.permits(editor, "document:", listOf(organization)))
        }

        @Test
        fun `the scope chain still decides where it applies`() {
            val elsewhere = principal(mapOf(otherProject to setOf(EDITOR)))
            assertFalse(authorizer.permits(elsewhere, "document:approve", listOf(organization)))
        }

        @Test
        fun `an entry spelling an action grants that action alone`() {
            val admin = principal(mapOf(organization to setOf(ADMIN)))
            assertTrue(authorizer.permits(admin, "project:manage", listOf(organization)))
            assertFalse(authorizer.permits(admin, "project:read", listOf(organization)))
        }
    }

    @Nested
    @DisplayName("Delegated scope")
    inner class DelegatedScope {

        @Test
        fun `the unrestricted value lets the roles decide`() {
            val subject = principal(
                mapOf(organization to setOf(ADMIN)),
                scope = listOf(Authorizer.UNRESTRICTED),
            )

            assertTrue(authorizer.permits(subject, "report:manage", listOf(organization)))
            assertFalse(authorizer.permits(subject, "document:publish", listOf(organization)))
        }

        @Test
        fun `a consented permission the roles grant is permitted`() {
            val subject = principal(
                mapOf(organization to setOf(ADMIN)),
                scope = listOf("report:manage", "document:approve"),
            )

            assertTrue(authorizer.permits(subject, "report:manage", listOf(organization)))
        }

        @Test
        fun `a permission the roles grant and the consent omits is refused`() {
            val subject = principal(
                mapOf(organization to setOf(ADMIN)),
                scope = listOf("report:read"),
            )

            assertFalse(authorizer.permits(subject, "report:manage", listOf(organization)))
        }

        @Test
        fun `a consented permission no role grants is refused`() {
            val subject = principal(
                mapOf(organization to setOf(DEVELOPER)),
                scope = listOf("document:approve"),
            )

            assertFalse(authorizer.permits(subject, "document:approve", listOf(organization)))
        }

        @Test
        fun `an empty claim refuses every permission`() {
            val subject = principal(mapOf(organization to setOf(OWNER)), scope = emptyList())

            assertFalse(authorizer.permits(subject, "report:manage", listOf(organization)))
        }
    }

    @Nested
    @DisplayName("Several roles at one scope")
    inner class SeveralRolesAtOneScope {
        private val subject = principal(mapOf(organization to setOf(DEVELOPER, APPROVER)))

        @Test
        fun `union grants an action from either role`() {
            assertTrue(authorizer.permits(subject, "document:publish", listOf(organization)))
            assertTrue(authorizer.permits(subject, "document:approve", listOf(organization)))
        }

        @Test
        fun `union refuses an action neither role lists`() {
            assertFalse(authorizer.permits(subject, "project:manage", listOf(organization)))
        }
    }

    @Nested
    @DisplayName("A permission held anywhere")
    inner class HeldAnywhere {
        @Test
        fun `grants where the subject holds the permission at some scope`() {
            val subject = principal(mapOf(organization to setOf(ADMIN)))

            assertTrue(authorizer.permitsAnywhere(subject, "document:approve"))
        }

        @Test
        fun `refuses where no role the subject holds grants it`() {
            val subject = principal(mapOf(organization to setOf(DEVELOPER)))

            assertFalse(authorizer.permitsAnywhere(subject, "document:approve"))
        }

        @Test
        fun `refuses a subject holding no roles`() {
            assertFalse(authorizer.permitsAnywhere(principal(emptyMap()), "document:approve"))
        }

        @Test
        fun `finds it at a scope that is not the first one held`() {
            val subject = principal(
                mapOf(organization to setOf(DEVELOPER), project to setOf(APPROVER)),
            )

            assertTrue(authorizer.permitsAnywhere(subject, "document:approve"))
        }

        @Test
        fun `grants where permits with an empty chain refuses, which is why it exists`() {
            val subject = principal(mapOf(organization to setOf(ADMIN)))

            assertFalse(authorizer.permits(subject, "document:approve", emptyList()))
            assertTrue(authorizer.permitsAnywhere(subject, "document:approve"))
        }

        @Test
        fun `a platform role grants anywhere, as it does through permits`() {
            val subject = principal(mapOf(Scope.PLATFORM to setOf(ADMIN)))

            assertTrue(authorizer.permitsAnywhere(subject, "document:approve"))
        }
    }

    companion object {
        private const val SUBJECT_ID = "00000000-0000-0000-0000-000000000001"
        private const val ORGANIZATION_ID = "org_123"
        private const val PROJECT_ID = "44de0a17"
        private const val OTHER_PROJECT_ID = "7a2155cb"

        private val OWNER = RoleName("OWNER")
        private val ADMIN = RoleName("ADMIN")
        private val EDITOR = RoleName("EDITOR")
        private val DEVELOPER = RoleName("DEVELOPER")
        private val APPROVER = RoleName("APPROVER")
    }
}
