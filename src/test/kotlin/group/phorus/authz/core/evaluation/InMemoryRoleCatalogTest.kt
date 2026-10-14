package group.phorus.authz.core.evaluation

import group.phorus.authz.core.model.Principal
import group.phorus.authz.core.model.RoleName
import group.phorus.authz.core.model.Scope
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals

class InMemoryRoleCatalogTest {

    private val owner = RoleName("OWNER")
    private val approver = RoleName("APPROVER")

    @Test
    fun `answers the permissions a role was given`() {
        val catalog = InMemoryRoleCatalog(
            mapOf(approver to setOf("document:approve", "document:read")),
        )

        assertEquals(setOf("document:approve", "document:read"), catalog.permissions(approver))
    }

    @Test
    fun `answers the empty set for a name it holds no definition for`() {
        val catalog = InMemoryRoleCatalog(mapOf(approver to setOf("document:read")))

        assertEquals(emptySet(), catalog.permissions(owner))
    }

    @Test
    fun `answers the empty set when it was built with no definitions`() {
        assertEquals(emptySet(), InMemoryRoleCatalog(emptyMap()).permissions(owner))
    }

    @Test
    fun `copies the definitions, so a later change to the argument leaves it as it was`() {
        val source = mutableMapOf(approver to setOf("document:read"))
        val catalog = InMemoryRoleCatalog(source)

        source[owner] = setOf("*")
        source[approver] = setOf("document:approve")

        assertEquals(setOf("document:read"), catalog.permissions(approver))
        assertEquals(emptySet(), catalog.permissions(owner))
    }

    @Test
    fun `serves an Authorizer without a hand written implementation`() {
        val authorizer = Authorizer(InMemoryRoleCatalog(mapOf(owner to setOf("*"))))
        val principal = Principal(
            subjectId = UUID.randomUUID(),
            roles = mapOf(Scope.PLATFORM to setOf(owner)),
        )

        assertEquals(true, authorizer.permits(principal, "document:approve", emptyList()))
    }
}
