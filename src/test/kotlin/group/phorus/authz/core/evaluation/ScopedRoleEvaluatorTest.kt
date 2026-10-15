package group.phorus.authz.core.evaluation

import group.phorus.authz.core.model.AuthZSource
import group.phorus.authz.core.model.EvaluationContext
import group.phorus.authz.core.model.Permission
import group.phorus.authz.core.model.Principal
import group.phorus.authz.core.model.RoleName
import group.phorus.authz.core.model.Scope
import java.util.UUID
import kotlinx.coroutines.runBlocking
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

class ScopedRoleEvaluatorTest {

    private val organization = Scope("organization", "org_123")
    private val project = Scope("project", "proj_456")

    private val authorizer = Authorizer(
        InMemoryRoleCatalog(
            mapOf(
                RoleName("ADMIN") to setOf("document:approve"),
                RoleName("VIEWER") to setOf("document:read"),
            ),
        ),
    )

    private val evaluator = ScopedRoleEvaluator(authorizer)

    private fun contextFor(principal: Principal, required: String, scopes: List<Scope>) =
        EvaluationContext(
            principal = principal,
            requiredPermission = Permission.parse(required),
            scopes = scopes,
        )

    private fun principalHolding(role: String, at: Scope) = Principal(
        subjectId = UUID.randomUUID(),
        roles = mapOf(at to setOf(RoleName(role))),
    )

    @Test
    fun `allows when the role grants the permission in the chain`() = runBlocking {
        val context = contextFor(
            principalHolding("ADMIN", organization),
            "organization/org_123/project/proj_456/document/doc_789:approve",
            listOf(organization, project),
        )

        val result = evaluator.evaluate(context)

        assertTrue(result.allowed)
        assertEquals(AuthZSource.RBAC, result.source)
        assertEquals("document:approve", result.matched)
    }

    @Test
    fun `abstains rather than denying when the role falls short`() = runBlocking {
        val context = contextFor(
            principalHolding("VIEWER", organization),
            "document/doc_789:approve",
            listOf(organization),
        )

        val result = evaluator.evaluate(context)

        assertTrue(result.abstained)
    }

    @Test
    fun `abstains when the chain omits the scope the role is held at`() = runBlocking {
        val context = contextFor(
            principalHolding("ADMIN", organization),
            "document/doc_789:approve",
            listOf(project),
        )

        assertTrue(evaluator.evaluate(context).abstained)
    }

    @Test
    fun `joins the leaf type and the action into the catalogue spelling`() = runBlocking {
        val context = contextFor(
            principalHolding("ADMIN", organization),
            "organization/org_123/document/doc_789:approve",
            listOf(organization),
        )

        assertEquals("document:approve", evaluator.evaluate(context).matched)
    }

    @Test
    fun `one instance answers two subjects correctly`() = runBlocking {
        val granted = contextFor(
            principalHolding("ADMIN", organization),
            "document/doc_789:approve",
            listOf(organization),
        )
        val refused = contextFor(
            principalHolding("VIEWER", organization),
            "document/doc_789:approve",
            listOf(organization),
        )

        assertTrue(evaluator.evaluate(granted).allowed)
        assertTrue(evaluator.evaluate(refused).abstained)
        assertTrue(evaluator.evaluate(granted).allowed)
    }
}
