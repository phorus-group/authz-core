package group.phorus.authz.core.evaluation

import group.phorus.authz.core.model.Principal
import group.phorus.authz.core.model.RoleName
import group.phorus.authz.core.model.Scope
import java.util.UUID
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

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
            scope = listOf(Authorizer.UNRESTRICTED),
        )

        assertEquals(true, authorizer.permits(principal, "document:approve", emptyList()))
    }

    @Test
    fun `refuses an entry whose star belongs to a name`() {
        val error = assertFailsWith<IllegalArgumentException> {
            InMemoryRoleCatalog(mapOf(owner to setOf("organization/*:read", "doc*:read")))
        }

        assertTrue(error.message.orEmpty().contains("organization/*:read"), error.message.orEmpty())
        assertTrue(error.message.orEmpty().contains("doc*:read"), error.message.orEmpty())
    }

    @Test
    fun `accepts the three places a star stands for every value`() {
        val catalog = InMemoryRoleCatalog(
            mapOf(owner to setOf("*", "document:*", "*:read", "*:*", "document:read")),
        )

        assertEquals(5, catalog.permissions(owner).size)
    }

    @Test
    fun `names every entry a catalogue reads as a name rather than as breadth`() {
        val reported = RoleCatalog.unreadableWildcards(
            listOf(
                "*", "*:*", "*:read", "document:*", "document:read", "backoffice",
                "organization/*:read", "doc*:read", "document:re*d", "*report:read", "doc*",
            ),
        )

        assertEquals(
            listOf("*report:read", "doc*", "doc*:read", "document:re*d", "organization/*:read"),
            reported,
        )
    }

    @Test
    fun `reports one entry once however many roles hold it`() {
        assertEquals(
            listOf("doc*:read"),
            RoleCatalog.unreadableWildcards(listOf("doc*:read", "doc*:read", "document:read")),
        )
    }
}
