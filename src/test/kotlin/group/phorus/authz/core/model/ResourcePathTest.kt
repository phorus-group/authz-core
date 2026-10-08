package group.phorus.authz.core.model

import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import org.junit.jupiter.api.assertThrows
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class ResourcePathTest {

    @Nested
    @DisplayName("Parsing")
    inner class Parsing {
        @Test
        fun `parses type-level path`() {
            val path = ResourcePath.parse("organization")
            assertEquals(1, path.segments.size)
            assertEquals("organization", path.segments[0].type)
            assertEquals(null, path.segments[0].instanceId)
        }

        @Test
        fun `parses instance-level path`() {
            val path = ResourcePath.parse("organization/org_123")
            assertEquals(1, path.segments.size)
            assertEquals("organization", path.segments[0].type)
            assertEquals("org_123", path.segments[0].instanceId)
        }

        @Test
        fun `parses nested path`() {
            val path = ResourcePath.parse("organization/org_123/project/proj_456")
            assertEquals(2, path.segments.size)
            assertEquals(ResourceSegment("organization", "org_123"), path.segments[0])
            assertEquals(ResourceSegment("project", "proj_456"), path.segments[1])
        }

        @Test
        fun `parses deeply nested path`() {
            val path = ResourcePath.parse("organization/org_123/project/proj_456/installation/inst_789")
            assertEquals(3, path.segments.size)
            assertEquals(ResourceSegment("installation", "inst_789"), path.leaf)
            assertEquals(ResourceSegment("organization", "org_123"), path.root)
        }

        @Test
        fun `parses wildcard path`() {
            val path = ResourcePath.parse("organization/*/project/*")
            assertEquals(2, path.segments.size)
            assertTrue(path.segments[0].isWildcard)
            assertTrue(path.segments[1].isWildcard)
        }

        @Test
        fun `parses path ending with type only`() {
            val path = ResourcePath.parse("organization/org_123/project")
            assertEquals(2, path.segments.size)
            assertEquals(ResourceSegment("organization", "org_123"), path.segments[0])
            assertEquals(ResourceSegment("project"), path.segments[1])
        }

        @Test
        fun `throws on blank path`() {
            assertThrows<IllegalArgumentException> { ResourcePath.parse("") }
            assertThrows<IllegalArgumentException> { ResourcePath.parse("  ") }
        }
    }

    @Nested
    @DisplayName("Ancestors")
    inner class Ancestors {
        @Test
        fun `single segment has no ancestors`() {
            val path = ResourcePath.parse("organization")
            assertEquals(0, path.ancestors().toList().size)
        }

        @Test
        fun `two segments has one ancestor`() {
            val path = ResourcePath.parse("organization/org_123/project/proj_456")
            val ancestors = path.ancestors().toList()
            assertEquals(1, ancestors.size)
            assertEquals("organization/org_123", ancestors[0].toString())
        }

        @Test
        fun `three segments has two ancestors`() {
            val path = ResourcePath.parse("organization/org_123/project/proj_456/installation/inst_789")
            val ancestors = path.ancestors().toList()
            assertEquals(2, ancestors.size)
            assertEquals("organization/org_123/project/proj_456", ancestors[0].toString())
            assertEquals("organization/org_123", ancestors[1].toString())
        }
    }

    @Nested
    @DisplayName("isAncestorOf")
    inner class IsAncestorOf {
        @Test
        fun `parent is ancestor of child`() {
            val parent = ResourcePath.parse("organization/org_123")
            val child = ResourcePath.parse("organization/org_123/project/proj_456")
            assertTrue(parent.isAncestorOf(child))
        }

        @Test
        fun `child is not ancestor of parent`() {
            val parent = ResourcePath.parse("organization/org_123")
            val child = ResourcePath.parse("organization/org_123/project/proj_456")
            assertFalse(child.isAncestorOf(parent))
        }

        @Test
        fun `path is not ancestor of itself`() {
            val path = ResourcePath.parse("organization/org_123")
            assertFalse(path.isAncestorOf(path))
        }

        @Test
        fun `wildcard parent is ancestor of specific child`() {
            val parent = ResourcePath.parse("organization/*")
            val child = ResourcePath.parse("organization/org_123/project/proj_456")
            assertTrue(parent.isAncestorOf(child))
        }

        @Test
        fun `different type is not ancestor`() {
            val a = ResourcePath.parse("organization/org_123")
            val b = ResourcePath.parse("project/proj_456/installation/inst_789")
            assertFalse(a.isAncestorOf(b))
        }
    }

    @Nested
    @DisplayName("Covers")
    inner class Covers {
        @Test
        fun `exact match covers`() {
            val a = ResourcePath.parse("organization/org_123")
            val b = ResourcePath.parse("organization/org_123")
            assertTrue(a.covers(b))
        }

        @Test
        fun `wildcard covers specific instance`() {
            val wildcard = ResourcePath.parse("organization/*")
            val specific = ResourcePath.parse("organization/org_123")
            assertTrue(wildcard.covers(specific))
        }

        @Test
        fun `parent covers child (hierarchy inheritance)`() {
            val parent = ResourcePath.parse("organization/org_123")
            val child = ResourcePath.parse("organization/org_123/project/proj_456")
            assertTrue(parent.covers(child))
        }

        @Test
        fun `child does not cover parent`() {
            val parent = ResourcePath.parse("organization/org_123")
            val child = ResourcePath.parse("organization/org_123/project/proj_456")
            assertFalse(child.covers(parent))
        }

        @Test
        fun `different instances do not cover each other`() {
            val a = ResourcePath.parse("organization/org_123")
            val b = ResourcePath.parse("organization/org_456")
            assertFalse(a.covers(b))
        }

        @Test
        fun `type-level covers type-level`() {
            val a = ResourcePath.parse("organization")
            val b = ResourcePath.parse("organization")
            assertTrue(a.covers(b))
        }

        @Test
        fun `type-level covers instance-level of same type`() {
            val typeLevel = ResourcePath.parse("organization")
            val instance = ResourcePath.parse("organization/org_123")
            // type-level covers any instance of the same type
            assertTrue(typeLevel.covers(instance))
        }
    }

    @Nested
    @DisplayName("toString")
    inner class ToString {
        @Test
        fun `formats type-level path`() {
            assertEquals("organization", ResourcePath.parse("organization").toString())
        }

        @Test
        fun `formats instance-level path`() {
            assertEquals("organization/org_123", ResourcePath.parse("organization/org_123").toString())
        }

        @Test
        fun `formats nested path`() {
            assertEquals(
                "organization/org_123/project/proj_456",
                ResourcePath.parse("organization/org_123/project/proj_456").toString()
            )
        }
    }
}
