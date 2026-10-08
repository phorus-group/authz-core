package group.phorus.authz.core.evaluation

import group.phorus.authz.core.model.Permission
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PermissionMatcherTest {

    @Nested
    @DisplayName("covers (strings)")
    inner class CoversStrings {
        @Test
        fun `exact match`() {
            assertTrue(PermissionMatcher.covers("report:read", "report:read"))
        }

        @Test
        fun `wildcard action`() {
            assertTrue(PermissionMatcher.covers("report:*", "report:read"))
        }

        @Test
        fun `manage action`() {
            assertTrue(PermissionMatcher.covers("organization/org_123:manage", "organization/org_123:read"))
        }

        @Test
        fun `hierarchy inheritance`() {
            assertTrue(PermissionMatcher.covers(
                "organization/org_123:manage",
                "organization/org_123/project/proj_456:read"
            ))
        }

        @Test
        fun `no match`() {
            assertFalse(PermissionMatcher.covers("report:read", "report:update"))
        }
    }

    @Nested
    @DisplayName("covers (Permission objects)")
    inner class CoversPermissions {
        @Test
        fun `delegates to Permission covers`() {
            val granted = Permission.parse("organization/*:read")
            val required = Permission.parse("organization/org_123:read")
            assertTrue(PermissionMatcher.covers(granted, required))
        }
    }

    @Nested
    @DisplayName("findMatch")
    inner class FindMatch {
        private val userPermissions = listOf(
            "organization/org_123:manage",
            "report:read",
            "report:list",
        )

        @Test
        fun `finds exact match`() {
            assertEquals("report:read", PermissionMatcher.findMatch(userPermissions, "report:read"))
        }

        @Test
        fun `finds via hierarchy`() {
            assertEquals(
                "organization/org_123:manage",
                PermissionMatcher.findMatch(userPermissions, "organization/org_123/project/proj_456:read")
            )
        }

        @Test
        fun `returns null when no match`() {
            assertNull(PermissionMatcher.findMatch(userPermissions, "user:delete"))
        }

        @Test
        fun `returns first match when multiple apply`() {
            val perms = listOf("*:*", "report:read")
            assertEquals("*:*", PermissionMatcher.findMatch(perms, "report:read"))
        }
    }

    @Nested
    @DisplayName("anyCovers")
    inner class AnyCovers {
        @Test
        fun `returns true when at least one covers`() {
            assertTrue(PermissionMatcher.anyCovers(listOf("report:read", "report:update"), "report:read"))
        }

        @Test
        fun `returns false when none cover`() {
            assertFalse(PermissionMatcher.anyCovers(listOf("report:read"), "user:delete"))
        }

        @Test
        fun `returns false for empty list`() {
            assertFalse(PermissionMatcher.anyCovers(emptyList(), "report:read"))
        }
    }
}
