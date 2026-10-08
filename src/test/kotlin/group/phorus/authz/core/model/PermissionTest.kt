package group.phorus.authz.core.model

import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class PermissionTest {

    @Nested
    @DisplayName("Parsing")
    inner class Parsing {
        @Test
        fun `parses type-level permission`() {
            val perm = Permission.parse("organization:create")
            assertEquals("organization", perm.resourcePath.toString())
            assertEquals("create", perm.action)
        }

        @Test
        fun `parses instance-level permission`() {
            val perm = Permission.parse("organization/org_123:read")
            assertEquals("organization/org_123", perm.resourcePath.toString())
            assertEquals("read", perm.action)
        }

        @Test
        fun `parses nested permission`() {
            val perm = Permission.parse("organization/org_123/project/proj_456:update")
            assertEquals("organization/org_123/project/proj_456", perm.resourcePath.toString())
            assertEquals("update", perm.action)
        }

        @Test
        fun `parses wildcard permission`() {
            val perm = Permission.parse("*:*")
            assertEquals("*", perm.action)
        }

        @Test
        fun `parses manage permission`() {
            val perm = Permission.parse("organization/org_123:manage")
            assertEquals("manage", perm.action)
        }

        @Test
        fun `raw string round-trips`() {
            val raw = "organization/org_123/project/proj_456:read"
            assertEquals(raw, Permission.parse(raw).raw)
        }

        @Test
        fun `throws on blank string`() {
            assertThrows<IllegalArgumentException> { Permission.parse("") }
        }

        @Test
        fun `throws on missing colon`() {
            assertThrows<IllegalArgumentException> { Permission.parse("organization") }
        }

        @Test
        fun `throws on trailing colon`() {
            assertThrows<IllegalArgumentException> { Permission.parse("organization:") }
        }
    }

    @Nested
    @DisplayName("Covers: action matching")
    inner class ActionMatching {
        @Test
        fun `exact action match`() {
            assertTrue(Permission.parse("bit:read").covers(Permission.parse("bit:read")))
        }

        @Test
        fun `different actions do not match`() {
            assertFalse(Permission.parse("bit:read").covers(Permission.parse("bit:update")))
        }

        @Test
        fun `wildcard action covers any action`() {
            assertTrue(Permission.parse("bit:*").covers(Permission.parse("bit:read")))
            assertTrue(Permission.parse("bit:*").covers(Permission.parse("bit:delete")))
            assertTrue(Permission.parse("bit:*").covers(Permission.parse("bit:manage")))
        }

        @Test
        fun `manage action covers any action`() {
            assertTrue(Permission.parse("bit:manage").covers(Permission.parse("bit:read")))
            assertTrue(Permission.parse("bit:manage").covers(Permission.parse("bit:delete")))
            assertTrue(Permission.parse("bit:manage").covers(Permission.parse("bit:create")))
        }

        @Test
        fun `regular action does not cover wildcard`() {
            assertFalse(Permission.parse("bit:read").covers(Permission.parse("bit:*")))
        }

        @Test
        fun `regular action does not cover manage`() {
            assertFalse(Permission.parse("bit:read").covers(Permission.parse("bit:manage")))
        }
    }

    @Nested
    @DisplayName("Covers: resource matching")
    inner class ResourceMatching {
        @Test
        fun `exact resource match`() {
            assertTrue(
                Permission.parse("organization/org_123:read")
                    .covers(Permission.parse("organization/org_123:read"))
            )
        }

        @Test
        fun `different instances do not match`() {
            assertFalse(
                Permission.parse("organization/org_123:read")
                    .covers(Permission.parse("organization/org_456:read"))
            )
        }

        @Test
        fun `wildcard resource covers specific instance`() {
            assertTrue(
                Permission.parse("organization/*:read")
                    .covers(Permission.parse("organization/org_123:read"))
            )
        }
    }

    @Nested
    @DisplayName("Covers: hierarchy inheritance")
    inner class HierarchyInheritance {
        @Test
        fun `parent manage covers child read`() {
            assertTrue(
                Permission.parse("organization/org_123:manage")
                    .covers(Permission.parse("organization/org_123/project/proj_456:read"))
            )
        }

        @Test
        fun `parent read covers child read`() {
            assertTrue(
                Permission.parse("organization/org_123:read")
                    .covers(Permission.parse("organization/org_123/project/proj_456:read"))
            )
        }

        @Test
        fun `child does not cover parent`() {
            assertFalse(
                Permission.parse("organization/org_123/project/proj_456:manage")
                    .covers(Permission.parse("organization/org_123:read"))
            )
        }

        @Test
        fun `grandparent covers grandchild`() {
            assertTrue(
                Permission.parse("organization/org_123:manage")
                    .covers(Permission.parse("organization/org_123/project/proj_456/installation/inst_789:read"))
            )
        }
    }

    @Nested
    @DisplayName("Covers: superadmin")
    inner class Superadmin {
        @Test
        fun `star-star covers everything`() {
            val superadmin = Permission.parse("*:*")
            assertTrue(superadmin.covers(Permission.parse("organization:create")))
            assertTrue(superadmin.covers(Permission.parse("organization/org_123:read")))
            assertTrue(superadmin.covers(Permission.parse("organization/org_123/project/proj_456:delete")))
            assertTrue(superadmin.covers(Permission.parse("bit:upload")))
        }
    }

    @Nested
    @DisplayName("toString")
    inner class ToString {
        @Test
        fun `formats correctly`() {
            assertEquals(
                "organization/org_123:read",
                Permission.parse("organization/org_123:read").toString()
            )
        }
    }
}
