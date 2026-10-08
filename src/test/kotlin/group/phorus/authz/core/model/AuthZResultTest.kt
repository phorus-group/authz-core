package group.phorus.authz.core.model

import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

class AuthZResultTest {

    @Nested
    @DisplayName("allowed")
    inner class Allowed {
        @Test
        fun `carries the source and what matched`() {
            val result = AuthZResult.allowed(AuthZSource.RBAC, "report:read")
            assertEquals(PolicyDecision.ALLOW, result.decision)
            assertEquals(AuthZSource.RBAC, result.source)
            assertEquals("report:read", result.matched)
            assertTrue(result.allowed)
            assertFalse(result.denied)
            assertFalse(result.abstained)
        }

        @Test
        fun `carries a grant id`() {
            val grantId = UUID.fromString(GRANT_ID)
            val result = AuthZResult.allowed(AuthZSource.GRANT, "document:approve", grantId)
            assertEquals(grantId, result.grantId)
        }
    }

    @Nested
    @DisplayName("denied")
    inner class Denied {
        @Test
        fun `carries the reason, the source and what matched`() {
            val result = AuthZResult.denied("outside business hours", AuthZSource.ABAC, "production-hours")
            assertEquals(PolicyDecision.DENY, result.decision)
            assertEquals("outside business hours", result.reason)
            assertEquals(AuthZSource.ABAC, result.source)
            assertEquals("production-hours", result.matched)
            assertTrue(result.denied)
            assertFalse(result.allowed)
            assertFalse(result.abstained)
        }

        @Test
        fun `reason alone leaves the source and the match null`() {
            val result = AuthZResult.denied("no evaluator granted access")
            assertNull(result.source)
            assertNull(result.matched)
        }
    }

    @Nested
    @DisplayName("abstain")
    inner class Abstain {
        @Test
        fun `reports abstained alone`() {
            val result = AuthZResult.abstain()
            assertEquals(PolicyDecision.ABSTAIN, result.decision)
            assertTrue(result.abstained)
            assertFalse(result.allowed)
            assertFalse(result.denied)
            assertNull(result.source)
            assertNull(result.reason)
        }
    }

    companion object {
        private const val GRANT_ID = "3f0c1d8a-5e47-4b92-8a16-7c2d9e4f0b35"
    }
}
