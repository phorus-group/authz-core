package group.phorus.authz.core.evaluation

import group.phorus.authz.core.model.*
import kotlinx.coroutines.runBlocking
import org.junit.jupiter.api.DisplayName
import org.junit.jupiter.api.Nested
import org.junit.jupiter.api.Test
import java.util.UUID
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

class AuthorizationChainTest {

    private val testContext = EvaluationContext(
        userId = UUID.fromString("00000000-0000-0000-0000-000000000001"),
        permissions = listOf("report:read"),
        requiredPermission = Permission.parse("report:read"),
    )

    /** Creates a stub evaluator that always returns the given result. */
    private fun stubEvaluator(source: AuthZSource, result: AuthZResult) = object : AuthorizationEvaluator {
        override val source = source
        override suspend fun evaluate(context: EvaluationContext) = result
    }

    private fun allowingEvaluator(source: AuthZSource, matched: String = "test") =
        stubEvaluator(source, AuthZResult.allowed(source, matched))

    private fun denyingEvaluator(source: AuthZSource, reason: String = "denied") =
        stubEvaluator(source, AuthZResult.denied(reason, source))

    private fun abstainingEvaluator(source: AuthZSource) =
        stubEvaluator(source, AuthZResult.abstain())

    @Nested
    @DisplayName("Granting evaluators")
    inner class GrantingEvaluators {
        @Test
        fun `first ALLOW wins`() = runBlocking {
            val chain = AuthorizationChain(
                grantingEvaluators = listOf(
                    allowingEvaluator(AuthZSource.RBAC, "rbac-match"),
                    allowingEvaluator(AuthZSource.REBAC, "rebac-match"),
                ),
            )
            val result = chain.evaluate(testContext)
            assertTrue(result.allowed)
            assertEquals(AuthZSource.RBAC, result.source)
            assertEquals("rbac-match", result.matched)
        }

        @Test
        fun `skips ABSTAIN and uses next ALLOW`() = runBlocking {
            val chain = AuthorizationChain(
                grantingEvaluators = listOf(
                    abstainingEvaluator(AuthZSource.RBAC),
                    allowingEvaluator(AuthZSource.REBAC, "rebac-match"),
                ),
            )
            val result = chain.evaluate(testContext)
            assertTrue(result.allowed)
            assertEquals(AuthZSource.REBAC, result.source)
        }

        @Test
        fun `explicit DENY from granting evaluator stops chain`() = runBlocking {
            val chain = AuthorizationChain(
                grantingEvaluators = listOf(
                    denyingEvaluator(AuthZSource.RBAC, "explicitly denied"),
                    allowingEvaluator(AuthZSource.REBAC),
                ),
            )
            val result = chain.evaluate(testContext)
            assertTrue(result.denied)
            assertEquals(AuthZSource.RBAC, result.source)
        }
    }

    @Nested
    @DisplayName("Constraint evaluators (ABAC)")
    inner class ConstraintEvaluators {
        @Test
        fun `constraint DENY overrides granting ALLOW`() = runBlocking {
            val chain = AuthorizationChain(
                grantingEvaluators = listOf(allowingEvaluator(AuthZSource.RBAC)),
                constraintEvaluators = listOf(denyingEvaluator(AuthZSource.ABAC, "GDPR restriction")),
            )
            val result = chain.evaluate(testContext)
            assertTrue(result.denied)
            assertEquals(AuthZSource.ABAC, result.source)
            assertEquals("GDPR restriction", result.reason)
        }

        @Test
        fun `constraint ABSTAIN does not block granting ALLOW`() = runBlocking {
            val chain = AuthorizationChain(
                grantingEvaluators = listOf(allowingEvaluator(AuthZSource.RBAC, "rbac-match")),
                constraintEvaluators = listOf(abstainingEvaluator(AuthZSource.ABAC)),
            )
            val result = chain.evaluate(testContext)
            assertTrue(result.allowed)
            assertEquals(AuthZSource.RBAC, result.source)
        }

        @Test
        fun `multiple constraints all checked`() = runBlocking {
            val chain = AuthorizationChain(
                grantingEvaluators = listOf(allowingEvaluator(AuthZSource.RBAC)),
                constraintEvaluators = listOf(
                    abstainingEvaluator(AuthZSource.ABAC),
                    denyingEvaluator(AuthZSource.ABAC, "second constraint"),
                ),
            )
            val result = chain.evaluate(testContext)
            assertTrue(result.denied)
            assertEquals("second constraint", result.reason)
        }
    }

    @Nested
    @DisplayName("Fallback evaluators (Grant)")
    inner class FallbackEvaluators {
        @Test
        fun `fallback ALLOW when no granting evaluator matches`() = runBlocking {
            val chain = AuthorizationChain(
                grantingEvaluators = listOf(abstainingEvaluator(AuthZSource.RBAC)),
                fallbackEvaluators = listOf(allowingEvaluator(AuthZSource.GRANT, "grant-match")),
            )
            val result = chain.evaluate(testContext)
            assertTrue(result.allowed)
            assertEquals(AuthZSource.GRANT, result.source)
        }

        @Test
        fun `fallback not checked when granting evaluator already allowed`() = runBlocking {
            var fallbackCalled = false
            val trackingFallback = object : AuthorizationEvaluator {
                override val source = AuthZSource.GRANT
                override suspend fun evaluate(context: EvaluationContext): AuthZResult {
                    fallbackCalled = true
                    return AuthZResult.allowed(AuthZSource.GRANT, "grant")
                }
            }
            val chain = AuthorizationChain(
                grantingEvaluators = listOf(allowingEvaluator(AuthZSource.RBAC)),
                fallbackEvaluators = listOf(trackingFallback),
            )
            chain.evaluate(testContext)
            assertFalse(fallbackCalled)
        }

        @Test
        fun `constraint DENY overrides fallback ALLOW`() = runBlocking {
            val chain = AuthorizationChain(
                grantingEvaluators = listOf(abstainingEvaluator(AuthZSource.RBAC)),
                constraintEvaluators = listOf(denyingEvaluator(AuthZSource.ABAC, "constraint denied")),
                fallbackEvaluators = listOf(allowingEvaluator(AuthZSource.GRANT)),
            )
            val result = chain.evaluate(testContext)
            assertTrue(result.denied)
            assertEquals(AuthZSource.ABAC, result.source)
        }
    }

    @Nested
    @DisplayName("Default deny")
    inner class DefaultDeny {
        @Test
        fun `denies when all evaluators abstain`() = runBlocking {
            val chain = AuthorizationChain(
                grantingEvaluators = listOf(abstainingEvaluator(AuthZSource.RBAC)),
                fallbackEvaluators = listOf(abstainingEvaluator(AuthZSource.GRANT)),
            )
            val result = chain.evaluate(testContext)
            assertTrue(result.denied)
            assertTrue(result.reason!!.contains("No evaluator granted access"))
        }

        @Test
        fun `denies when no evaluators configured`() = runBlocking {
            val chain = AuthorizationChain()
            val result = chain.evaluate(testContext)
            assertTrue(result.denied)
        }
    }

    @Nested
    @DisplayName("standard factory")
    inner class StandardFactory {
        @Test
        fun `creates chain with standard order`() = runBlocking {
            val chain = AuthorizationChain.standard(
                rbac = allowingEvaluator(AuthZSource.RBAC, "rbac"),
            )
            val result = chain.evaluate(testContext)
            assertTrue(result.allowed)
            assertEquals(AuthZSource.RBAC, result.source)
        }

        @Test
        fun `null evaluators are skipped`() = runBlocking {
            val chain = AuthorizationChain.standard(
                rbac = null,
                implicit = null,
                rebac = allowingEvaluator(AuthZSource.REBAC, "rebac"),
            )
            val result = chain.evaluate(testContext)
            assertTrue(result.allowed)
            assertEquals(AuthZSource.REBAC, result.source)
        }
    }
}
