package group.phorus.authz.core.model

import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PrincipalTest {

    @Nested
    @DisplayName("Scope")
    inner class ScopeFormatting {
        @Test
        fun `formats as type and id`() {
            assertEquals("organization:$ORGANIZATION_ID", Scope("organization", ORGANIZATION_ID).toString())
        }

        @Test
        fun `platform scope formats as platform and star`() {
            assertEquals("platform:*", Scope.PLATFORM.toString())
        }
    }

    @Nested
    @DisplayName("Scope parsing")
    inner class ScopeParsing {
        @Test
        fun `reads type and id`() {
            assertEquals(
                Scope("organization", ORGANIZATION_ID),
                Scope.parseOrNull("organization:$ORGANIZATION_ID"),
            )
        }

        @Test
        fun `keeps a colon inside the id`() {
            assertEquals(Scope("organization", "a:b"), Scope.parseOrNull("organization:a:b"))
        }

        @Test
        fun `round-trips the platform scope`() {
            assertEquals(Scope.PLATFORM, Scope.parseOrNull(Scope.PLATFORM.toString()))
        }

        @Test
        fun `returns null without a separator`() {
            assertNull(Scope.parseOrNull("organization"))
        }

        @Test
        fun `returns null on a blank type`() {
            assertNull(Scope.parseOrNull(":$ORGANIZATION_ID"))
        }

        @Test
        fun `returns null on a blank id`() {
            assertNull(Scope.parseOrNull("organization:"))
            assertNull(Scope.parseOrNull("organization:   "))
        }

        @Test
        fun `returns null on a blank value`() {
            assertNull(Scope.parseOrNull(""))
            assertNull(Scope.parseOrNull("   "))
        }
    }

    @Nested
    @DisplayName("RoleName")
    inner class Names {
        @Test
        fun `holds the name`() {
            assertEquals("ADMIN", RoleName("ADMIN").value)
        }
    }

    @Nested
    @DisplayName("Principal")
    inner class Subjects {
        @Test
        fun `delegated scope defaults to empty`() {
            val subject = Principal(
                subjectId = UUID.fromString(SUBJECT_ID),
                roles = mapOf(Scope("organization", ORGANIZATION_ID) to setOf(RoleName("ADMIN"))),
            )
            assertTrue(subject.scope.isEmpty())
        }

        @Test
        fun `holds several roles at one scope and roles at several scopes`() {
            val organization = Scope("organization", ORGANIZATION_ID)
            val project = Scope("project", PROJECT_ID)
            val subject = Principal(
                subjectId = UUID.fromString(SUBJECT_ID),
                roles = mapOf(
                    organization to setOf(RoleName("ADMIN"), RoleName("REPORT_PUBLISHER")),
                    project to setOf(RoleName("APPROVER")),
                ),
            )
            assertEquals(2, subject.roles[organization]?.size)
            assertEquals(setOf(RoleName("APPROVER")), subject.roles[project])
        }
    }

    @Nested
    @DisplayName("Reading role entries")
    inner class RoleEntries {
        private val subject = UUID.fromString(SUBJECT_ID)
        private val organization = Scope("organization", ORGANIZATION_ID)

        @Test
        fun `reads a qualified entry into the scope it names`() {
            val principal = Principal.fromRoleEntries(
                subject,
                listOf("ADMIN@organization:$ORGANIZATION_ID"),
                onDropped = {},
            )

            assertEquals(mapOf(organization to setOf(RoleName("ADMIN"))), principal.roles)
        }

        @Test
        fun `holds an unqualified entry at the platform scope`() {
            val principal = Principal.fromRoleEntries(subject, listOf("OWNER"), onDropped = {})

            assertEquals(mapOf(Scope.PLATFORM to setOf(RoleName("OWNER"))), principal.roles)
        }

        @Test
        fun `groups several roles held at one scope`() {
            val principal = Principal.fromRoleEntries(
                subject,
                listOf("ADMIN@organization:$ORGANIZATION_ID", "VIEWER@organization:$ORGANIZATION_ID"),
                onDropped = {},
            )

            assertEquals(setOf(RoleName("ADMIN"), RoleName("VIEWER")), principal.roles[organization])
        }

        @Test
        fun `carries the subject and the delegated scope across`() {
            val principal = Principal.fromRoleEntries(
                subject,
                listOf("OWNER"),
                listOf("report:read"),
                onDropped = {},
            )

            assertEquals(subject, principal.subjectId)
            assertEquals(listOf("report:read"), principal.scope)
        }

        @Test
        fun `drops every malformed shape and reports each one`() {
            val dropped = mutableListOf<String>()
            val malformed = listOf(
                "ADMIN@",
                "@organization:$ORGANIZATION_ID",
                "@",
                "ADMIN@organization",
                "ADMIN@:$ORGANIZATION_ID",
                "ADMIN@organization:",
                "",
            )

            val principal = Principal.fromRoleEntries(subject, malformed, onDropped = dropped::add)

            assertTrue(principal.roles.isEmpty())
            assertEquals(malformed, dropped)
        }

        @Test
        fun `keeps the entries that parse when one beside them is malformed`() {
            val dropped = mutableListOf<String>()

            val principal = Principal.fromRoleEntries(
                subject,
                listOf("ADMIN@", "VIEWER@organization:$ORGANIZATION_ID"),
                onDropped = dropped::add,
            )

            assertEquals(mapOf(organization to setOf(RoleName("VIEWER"))), principal.roles)
            assertEquals(listOf("ADMIN@"), dropped)
        }

        @Test
        fun `an id may itself contain a colon`() {
            val principal = Principal.fromRoleEntries(
                subject,
                listOf("ADMIN@organization:a:b"),
                onDropped = {},
            )

            assertEquals(mapOf(Scope("organization", "a:b") to setOf(RoleName("ADMIN"))), principal.roles)
        }
    }

    companion object {
        private const val SUBJECT_ID = "00000000-0000-0000-0000-000000000001"
        private const val ORGANIZATION_ID = "org_123"
        private const val PROJECT_ID = "44de0a17"
    }
}
