# authz-core

[![GitHub license](https://img.shields.io/badge/license-Apache%20License%202.0-blue.svg?style=flat)](https://www.apache.org/licenses/LICENSE-2.0)
[![Maven Central](https://img.shields.io/maven-central/v/group.phorus/authz-core)](https://mvnrepository.com/artifact/group.phorus/authz-core)
[![codecov](https://codecov.io/gh/phorus-group/authz-core/branch/main/graph/badge.svg)](https://codecov.io/gh/phorus-group/authz-core)

Authorization library for Kotlin/JVM services. Provides framework-agnostic scoped RBAC,
permission-string matching with wildcards and hierarchy inheritance, and a composable evaluator
chain, so you can decide what a caller may do from state the process already holds.

For the JWT creation and validation behind the claims a check reads, see
[authn-core](https://github.com/phorus-group/authn-core).

### Notes

> The project runs a vulnerability analysis pipeline regularly,
> any found vulnerabilities will be fixed as soon as possible.

> The project dependencies are being regularly updated by [Renovate](https://github.com/phorus-group/renovate).

## Table of contents

- [What an authorization check decides](#what-an-authorization-check-decides)
  - [Two ways to carry authority](#two-ways-to-carry-authority)
- [Getting started](#getting-started)
  - [Installation](#installation)
  - [Quick start](#quick-start)
- [How it works](#how-it-works)
- [Using it in an endpoint](#using-it-in-an-endpoint)
  - [Acting on one existing resource](#acting-on-one-existing-resource)
  - [Creating a resource under a parent](#creating-a-resource-under-a-parent)
  - [Listing what sits in a container](#listing-what-sits-in-a-container)
  - [Refusing before the database is touched](#refusing-before-the-database-is-touched)
  - [Authority granted on one named object](#authority-granted-on-one-named-object)
  - [Handing out a role](#handing-out-a-role)
  - [Deciding from more than one source](#deciding-from-more-than-one-source)
- [Core concepts](#core-concepts)
  - [Scoped roles](#scoped-roles)
    - [The role catalogue](#the-role-catalogue)
    - [The scope chain](#the-scope-chain)
    - [The platform scope](#the-platform-scope)
    - [Delegated scope](#delegated-scope)
  - [Permission strings](#permission-strings)
    - [Format](#format)
    - [Standard actions](#standard-actions)
    - [Matching rules](#matching-rules)
    - [Hierarchy inheritance](#hierarchy-inheritance)
  - [Resource paths](#resource-paths)
    - [Segments](#segments)
    - [Ancestors](#ancestors)
    - [Wildcards](#wildcards)
- [The evaluation chain](#the-evaluation-chain)
  - [What the chain is for](#what-the-chain-is-for)
  - [The three decisions](#the-three-decisions)
  - [Phases and precedence](#phases-and-precedence)
  - [Writing an evaluator](#writing-an-evaluator)
  - [Composing a chain](#composing-a-chain)
- [Core types reference](#core-types-reference)
- [Security considerations](#security-considerations)
- [Standards references](#standards-references)
- [Building and contributing](#building-and-contributing)
- [Authors and acknowledgment](#authors-and-acknowledgment)

***

## What an authorization check decides

If you are already familiar with scoped roles and permission strings, feel free to skip to
[Getting started](#getting-started).

A check decides whether one subject may perform one action on one object.

- The **subject** is whoever a check is about, which is usually the user or service account a call
  is being made on behalf of.
- The **action** is the operation the subject wants to perform, such as `read` or `approve`.
- The **object** is the one resource the action applies to.
- A **permission** names a resource and an action joined by a colon, as in `document:approve`. The
  two ways below differ in how its resource half names the object, and each section says how.

Which one a service picks decides what a check takes as arguments.

### Two ways to carry authority

A **role** is a named set of permissions. A **scoped role** is a role held at one **scope**, which is a
resource type together with one instance of that type, such as the organization `org_123`. With
scoped roles the subject carries a set of them, where the role name says what the subject is and the
scope says where it holds that role. The object arrives separately, as the **scope chain**, the list
of scopes the object sits inside, outermost first. A role held at an outer scope grants at the inner
ones, so an administrator of `org_123` reaches a document in a project inside it when the chain
passed for that document names the organization. Each permission a role grants names a resource
type rather than one object, as in `document:approve`, and the chain names which document.

With **permission strings** the subject carries strings that already name their object, each one a
**resource path** and an action joined by a colon, as in `organization/org_123:read`. A resource
path is a chain of types and ids separated by `/`, and it names the object, so the action here is
the bare verb `read`. What a check requires is another string of the same shape, so the two strings
are all it compares.

Either one works on its own, and a service can compose both.

| What differs | Scoped roles | Permission strings |
|---|---|---|
| What a check reads | a [`Principal`](#core-types-reference), a permission and a scope chain | the permission strings held and the one required |
| Where the object is named | the scope chain the caller passes in | inside the permission string itself |
| What the subject carries | one scoped role per role and scope | one string per object per action |
| How that set grows | with the number of places it holds a role | with the number of objects reachable |
| When removing authority takes effect | when a service next builds the principal | when the strings are next supplied |
| How breadth works | a role at an outer scope grants at inner ones, and an entry ending in `:*` grants every action on a type | a path prefix covers everything under it |
| What the calling code has to know | where the object sits | the required permission alone |
| Entry point | `Authorizer.permits` | `PermissionMatcher.covers` |

**When to use each:**

- **Scoped roles** fit authority held over a container, such as administrator of an organization or
  approver on a project. The cost is that the scope chain has to be known before the check runs,
  because the chain carries where the object sits.
- **Permission strings** fit authority granted on one named object, such as a share, a one-off grant
  or a relationship recorded against a single resource. The requirement names its own object, so the
  string is all a check reads. The cost is the number of strings a subject carries, which grows with
  the objects they enumerate, so hold them in storage the service reads on each check rather than
  inside a token.
- **Both together** suits a design that needs both. A role reaches everything inside the scopes it
  is held at, and a permission string records authority over one named object. See
  [the evaluation chain](#the-evaluation-chain) for composing the two into one decision.

## Getting started

### Installation

Make sure that `mavenCentral` (or any of its mirrors) is added to the repository list of the project.

Binaries and dependency information for Maven and Gradle can be found at [http://search.maven.org](https://search.maven.org/search?q=g:group.phorus%20AND%20a:authz-core).

<details open>
<summary>Gradle</summary>

```groovy
implementation 'group.phorus:authz-core:x.y.z'
```
</details>

<details open>
<summary>Gradle / Kotlin DSL</summary>

```kotlin
implementation("group.phorus:authz-core:x.y.z")
```
</details>

<details open>
<summary>Maven</summary>

```xml
<dependency>
    <groupId>group.phorus</groupId>
    <artifactId>authz-core</artifactId>
    <version>x.y.z</version>
</dependency>
```
</details>

### Quick start

Steps 1 to 3 get a scoped-role check running in your service, and you need three things: role
definitions, a principal, and the scope chain the target object sits in. Step 4 is the
permission-string model, which works on the permission strings alone.

**1. Declare the roles and the permissions each one grants.**

A **role catalogue** maps a role name to the permissions that role grants. `InMemoryRoleCatalog`
reads a map you hand it, which is one definition per role for the whole deployment.

```kotlin
import group.phorus.authz.core.evaluation.InMemoryRoleCatalog
import group.phorus.authz.core.model.RoleName

val applicationRoles = InMemoryRoleCatalog(
    mapOf(
        RoleName("OWNER") to setOf("*"),   // everything
        RoleName("ADMIN") to setOf("project:manage", "report:manage", "document:approve"),
        RoleName("APPROVER") to setOf("document:approve", "document:read"),
        RoleName("VIEWER") to setOf("report:read", "project:read", "document:read"),
    ),
)
```

A catalogue permission matches a requested one when the two are equal, and the colon in
`document:approve` is convention here. A name of your own works as well as these. `"*"` instead
grants every permission, and an entry ending in `:*` grants every action on the type before the
colon, so `project:*` grants `project:read` and `project:archive` alike. Every other entry grants
the action it spells. See [Wildcards](#wildcards) for what `*` means in each place it appears.

**2. Build a principal for the subject the request acts for.**

A `Principal` belongs to one request. Build one per request, from that request's claims, since one
held past its request leaves every later check reading the first request's subject.

Each role is keyed by the scope it is held at. So one principal can hold several roles at one scope,
and roles at several scopes. See [Scoped roles](#scoped-roles) for building the same map
from a token's `roles` claim.

```kotlin
import group.phorus.authz.core.model.Principal
import group.phorus.authz.core.model.Scope

val principal = Principal(
    subjectId = subjectId,          // a java.util.UUID from this request's claims
    roles = mapOf(
        Scope("organization", "org_123") to setOf(RoleName("ADMIN")),
        Scope("project", "proj_456") to setOf(RoleName("APPROVER")),
    ),
)
```

`Principal` takes a third argument, `scope`, which holds the OAuth `scope` claim as a list of
strings. A subject signing in directly carries `Authorizer.UNRESTRICTED` there and the roles alone
decide. The `Scope` type keying the roles map is a different type, a resource type with one
instance of it. See [Delegated scope](#delegated-scope) for what the claim does.

**3. Check a permission against the scope chain the object sits in.**

This step hands the catalogue from step 1 to an `Authorizer`, which runs a scoped-role check against
it. `Authorizer` holds the catalogue, which outlives a request, so one instance serves every
request. Build it at startup.

The scope chain is the list of scopes the target object sits inside, outermost first. The caller
builds it, and `permits` tries each link on its own, so the order is for the reader rather than for
the library.

```kotlin
import group.phorus.authz.core.evaluation.Authorizer

val authorizer = Authorizer(applicationRoles)

val chain = listOf(
    Scope("organization", "org_123"),
    Scope("project", "proj_456"),
)

authorizer.permits(principal, "document:approve", chain)   // true
```

Where the stored record names the containers an object sits in, read the chain from that record,
which [acting on one existing resource](#acting-on-one-existing-resource) shows.

**4. Match permission strings where authority was granted on one named object.**

A permission string is a resource path and an action joined by `:`. `covers` returns `true` when
the permission a subject was granted is broad enough for the one a check requires.

```kotlin
import group.phorus.authz.core.evaluation.PermissionMatcher

PermissionMatcher.covers(
    granted = "organization/org_123:read",
    required = "organization/org_123/project/proj_456:read",
)   // true: the organization path covers the project inside it
```

**What you get:**

- **From `permits`**: `true` here. The `ADMIN` role above is held at the organization, the chain
  names that organization, and `document:approve` is in that role's set.
- **From `covers`**: `true` when the granted path covers the required path and the granted action
  covers the required action. `read` on the organization covers `read` on a project inside it, as
  described in [Hierarchy inheritance](#hierarchy-inheritance).
- **In both cases**: the decision reads state the process already holds, so both are plain
  functions that return on the calling thread and do no I/O.

**An action means the same thing to both**, using the `principal` from step 2 and the `authorizer`
and `chain` from step 3.

```kotlin
authorizer.permits(principal, "report:read", chain)   // false, ADMIN holds report:manage
PermissionMatcher.covers(granted = "report:manage", required = "report:read")   // false
```

An action matches by name in each, so `report:manage` grants and covers `report:manage`. `*` is the
one action that matches every other, granting every action on the type in a catalogue and covering
every action on the path in a permission string. The resource half still differs between the two: a
catalogue entry names a type and the scope chain says which object, while a permission string names
the object itself and therefore covers the paths under it.

## How it works

The `permits` call in step 3 took three arguments, and each one came from somewhere different:

| Argument | What supplies it |
|---|---|
| the principal | the claims of the validated token, read once per request |
| the permission | the endpoint's own source, since it is what that endpoint does |
| the scope chain | the containers of the object, read from the service's own storage |

**The principal arrives with the request.** Whatever validated the token leaves a subject id, a
`roles` claim and a `scope` claim, and `Principal.fromRoleEntries` turns those into a `Principal`.
See [Scoped roles](#scoped-roles) for that step.

**The permission is a constant in the endpoint.** The route that approves a document requires
`document:approve` whoever calls it, so the string is written in the source rather than read from
the request. A request choosing its own permission would be choosing its own authority.

**The scope chain comes out of storage.** A request names the object by its id, and where that
object sits is recorded against it, so the service loads that record and reads the containers
from it.

The sections below are the shapes your endpoints take, and each one says where all three came from.

## Using it in an endpoint

Each section below is one such shape, written as the function behind one route. The library is
framework-agnostic, so the route sits in a comment rather than in an annotation. Each function uses
the `authorizer` you built at startup in step 3 and the `principal` you build per request in step 2.

### Acting on one existing resource

Where a request carries only an id, the loaded object supplies the scope chain, and `NotFound`
below is the service's own exception type:

```kotlin
// POST /documents/{id}/approve
suspend fun approve(principal: Principal, id: UUID) {
    val document = documentRepository.findById(id)
        ?: throw NotFound("Document $id not found")

    val chain = listOf(
        Scope("organization", document.project.organization.id.toString()),
        Scope("project", document.project.id.toString()),
    )

    if (!authorizer.permits(principal, "document:approve", chain)) {
        if (authorizer.permits(principal, "document:read", chain)) throw Forbidden()
        throw NotFound("Document $id not found")
    }
}
```

| Argument | Where this route got it |
|---|---|
| `principal` | built from the request's token before the function ran |
| `"document:approve"` | written here, because approving is what the route does |
| `chain` | read from the loaded record, which names the project and the organization above it |

**Where the service speaks HTTP, pick the status from what the subject can already see.** The check
runs once the object is loaded, so a 403 to a subject with no sight of the object confirms that the
id exists. A subject who may read it already knows, and 403 is honest there, naming the
one permission they lack. The second check above is how the route tells those two apart.

### Creating a resource under a parent

Nothing is stored yet, so there is no record to read a chain from. The parent is named in the path
instead, and the chain is that parent together with its own containers:

```kotlin
// POST /projects/{projectId}/documents
suspend fun createDocument(principal: Principal, projectId: UUID, body: NewDocument): Document {
    val project = projectRepository.findById(projectId)
        ?: throw NotFound("Project $projectId not found")

    val chain = listOf(
        Scope("organization", project.organization.id.toString()),
        Scope("project", project.id.toString()),
    )

    if (!authorizer.permits(principal, "document:create", chain)) {
        if (authorizer.permits(principal, "project:read", chain)) throw Forbidden()
        throw NotFound("Project $projectId not found")
    }

    return documentRepository.save(body.toDocument(project))
}
```

| Argument | Where this route got it |
|---|---|
| `principal` | the request's token |
| `"document:create"` | written here, naming the type being created |
| `chain` | the parent named in the path, plus the containers that parent records |

The object is still to be created, so authority over it is authority over the place it is going. The parent
is loaded all the same, because it carries the organization above it, and because a project the
subject cannot see at all is then refused with the same 404 as a missing project, while a subject
who may read the project gets a 403 naming the permission they lack.

### Listing what sits in a container

The container's id is already in the path, so the chain is one link and the check runs straight
away:

```kotlin
// GET /projects/{projectId}/documents
suspend fun listDocuments(principal: Principal, projectId: UUID): List<Document> {
    val chain = listOf(Scope("project", projectId.toString()))

    if (!authorizer.permits(principal, "document:list", chain)) {
        throw NotFound("Project $projectId not found")
    }

    return documentRepository.findByProjectId(projectId)
}
```

| Argument | Where this route got it |
|---|---|
| `principal` | the request's token |
| `"document:list"` | written here, naming the type being listed |
| `chain` | the project id in the path, with no load in front of it |

**A chain of one link reaches the roles held at that link, and those held at the
[platform scope](#the-platform-scope).** A role held at the organization above the project stays out
of it, because the chain names only the project. Where you want that role to reach this list too,
load the project, read the organization from it, and pass both links as the two sections above do.

### Refusing before the database is touched

Where a check runs before the object is loaded, the permission is all it has to go on.
`Authorizer.permitsAnywhere` returns `true` where the subject holds that permission at any scope it
holds a role at:

```kotlin
// POST /documents/{id}/approve
suspend fun approve(principal: Principal, id: UUID) {
    if (!authorizer.permitsAnywhere(principal, "document:approve")) {
        throw NotFound("Document $id not found")
    }

    // the load and the instance check from the first section follow here
}
```

Passing an empty chain to `permits` behaves differently. That call reads the platform scope
alone, so it refuses a subject whose only grant is over one organization, which is the subject this
check exists to let through.

**`permitsAnywhere` is a pre-filter, and the instance check follows it.** It says the subject holds
the permission somewhere, and the instance check then settles whether it holds on this object,
because that check has the object's scope chain. A route that stops here lets somebody who
administers one organization act on another's.

| Argument | Where this route got it |
|---|---|
| `principal` | the request's token |
| `"document:approve"` | written here, the same constant the instance check uses |
| the chain | every scope the principal holds a role at, so the principal supplies it |

**The pre-filter only refuses.** It passes a subject holding the permission somewhere else entirely,
so the instance check still has to run after it. What it saves is the query for a subject who holds
the permission nowhere.

### Authority granted on one named object

Where authority was recorded against one object rather than over a container, the strings the
subject holds already name their object, so the check compares two strings and takes no chain.
`PermissionMatcher.anyCovers` returns `true` when any string in the list the subject holds covers
the one string the route requires:

```kotlin
// GET /documents/{id}
suspend fun readDocument(principal: Principal, id: UUID): Document {
    val document = documentRepository.findById(id)
        ?: throw NotFound("Document $id not found")

    val held = grantRepository.permissionsFor(principal.subjectId)
    val required = "organization/${document.project.organization.id}" +
        "/project/${document.project.id}/document/${document.id}:read"

    if (!PermissionMatcher.anyCovers(held, required)) {
        throw NotFound("Document $id not found")
    }

    return document
}
```

| Argument | Where this route got it |
|---|---|
| `principal` | the request's token, for its `subjectId` alone |
| the `read` action in `required` | written here, naming what the route performs |
| the path in `required` | the loaded record, which names the containers the document sits in |

The resource path carries where the object sits, which is the job the scope chain does in the
sections above. A grant recorded on the organization reaches this document through
[hierarchy inheritance](#hierarchy-inheritance). Read the held strings from storage on each check
rather than out of a token, since their number grows with the objects your subject can reach.

### Handing out a role

A service that lets one subject grant a role to another needs the rule that nobody hands out more
than they hold. Ask `permits` for each permission the role grants, against the chain the grant is
being made on:

```kotlin
// PUT /organizations/{organizationId}/members/{userId}/role
suspend fun setMemberRole(principal: Principal, organizationId: UUID, userId: UUID, role: RoleName) {
    val chain = listOf(Scope("organization", organizationId.toString()))

    val missing = applicationRoles.permissions(role)
        .filterNot { authorizer.permits(principal, it, chain) }

    if (missing.isNotEmpty()) throw Forbidden("Granting $role would hand out $missing")

    memberRepository.setRole(organizationId, userId, role)
}
```

| Argument | Where this route got it |
|---|---|
| `principal` | the request's token |
| `chain` | the organization named in the path, which is where the grant is being made |
| the role's permissions | the same catalogue the checks read |

**Read the granter's authority at the chain the grant is made on.** Building the set out of
`permitsAnywhere` instead asks whether they hold each permission at *any* scope they hold a role
at, so somebody who owns organization A passes the guard for a grant they are making in
organization B.

### Deciding from more than one source

Once your service decides from roles, granted strings and a policy together, a route passes all
three to a chain rather than calling each in turn. `AuthorizationEvaluator` is one source of authority,
`AuthorizationChain` holds those evaluators and runs them in a fixed order, `EvaluationContext`
carries one check's inputs, and `evaluate` returns an `AuthZResult` whose `allowed` is the decision.
[The evaluation chain](#the-evaluation-chain) builds the evaluators named here and sets out the
order they run in.

```kotlin
// POST /documents/{id}/approve
suspend fun approve(principal: Principal, id: UUID) {
    val document = documentRepository.findById(id)
        ?: throw NotFound("Document $id not found")

    val chain = listOf(
        Scope("organization", document.project.organization.id.toString()),
        Scope("project", document.project.id.toString()),
    )

    val context = EvaluationContext(
        principal = principal,
        scopes = chain,
        permissions = grantRepository.permissionsFor(principal.subjectId),
        requiredPermission = Permission.parse(
            "organization/${document.project.organization.id}" +
                "/project/${document.project.id}/document/${document.id}:approve",
        ),
        attributes = mapOf("env.business_hours" to true),
    )

    val result = authorizationChain.evaluate(context)

    if (!result.allowed) throw NotFound("Document $id not found")

    auditLog.record(principal.subjectId, result.source, result.matched, result.grantId)
}
```

| Argument | Where this route got it |
|---|---|
| `principal` | the request's token, for its `subjectId` and for the roles the role evaluator reads |
| the `approve` action | written here, in the required permission the whole chain decides against |
| the chain and the path | the loaded record, which names the containers once and fills both |

`authorizationChain` is built once, in [Composing a chain](#composing-a-chain). The context is
assembled once per check and each evaluator the chain reaches reads the fields it cares about, so
the record is loaded once however many sources decide from it.

A rule that reads the object belongs in this position too, such as an approval having to come from
somebody other than the person who requested it. A constraint-phase evaluator carries the same rule
when the service puts the loaded object in `EvaluationContext.attributes`, whose values are typed
`Any?`.

## Core concepts

### Scoped roles

A role name says what the subject is. A [`Scope`](#core-types-reference) says where the subject is
that thing. The two together are one scoped role, which Azure RBAC calls a role assignment and GCP
IAM a role binding. A role definition carries permissions alone, a scoped role adds the scope, and a
`Principal` holds those scoped roles for one subject.

```kotlin
RoleName("ADMIN")                  // what
Scope("organization", "org_123")   // where
```

`Scope` formats as `type:id`, and `parseOrNull` reads that form back. The split takes the first `:`,
so an id may itself contain one:

```kotlin
Scope("organization", "org_123").toString()   // "organization:org_123"
Scope.parseOrNull("organization:org_123")     // Scope("organization", "org_123")
Scope.parseOrNull("organization:a:b")         // Scope("organization", "a:b")
```

A **role entry** is one value of the `roles` claim, which a service reads into a role name and the
`Scope` it is held at. The issuer of the claim decides its shape, under
[RFC 7643 §4.1.2](https://datatracker.ietf.org/doc/html/rfc7643#section-4.1.2), which defines `roles`
and specifies no vocabulary or syntax for its values. These two shapes are the ones this library
documents, with the raw entry on the left and what a service reads it as on the right. An entry
naming no scope is held at `Scope.PLATFORM`, which is `Scope("platform", "*")` and is consulted on
every check:

```
ADMIN@organization:org_123     RoleName("ADMIN") at Scope("organization", "org_123")
OWNER                          RoleName("OWNER") at Scope.PLATFORM
```

`Scope.parseOrNull` reads the scope half of such an entry. Splitting the entry at `@` is the
service's own step, as the snippet below does.

**A role entry arrives from outside the process, even when it arrives signed.** A signature
identifies the issuer, and leaves the value's shape unchecked. So `parseOrNull` returns `null` for a
value that is not `type:id`:

```kotlin
Scope.parseOrNull("organization")    // null, no separator
Scope.parseOrNull(":org_123")        // null, blank type
Scope.parseOrNull("organization:")   // null, blank id
Scope.parseOrNull("")                // null
```

`Principal.fromRoleEntries` does that reading. Given `rolesClaim` and `scopeClaim` read from the
validated token as `List<String>`, it splits each entry at its `@`, parses the half after it as a
scope, and treats a bare entry as a role held at `Scope.PLATFORM`. A malformed entry goes to
`onDropped` and the rest are kept, so the subject holds the roles that parsed and a check needing a
dropped role returns `false`. The handler has no default, so a caller content to lose the entry
writes an empty lambda and states that where a reader of the call can see it:

```kotlin
val principal = Principal.fromRoleEntries(
    subjectId = subjectId,
    roleEntries = rolesClaim,
    scope = scopeClaim,
    onDropped = { entry -> log.warn("Dropping role entry \"{}\"", entry) },
)
```

An entry is dropped when its role name is blank, when the half after the `@` fails to parse as a
`type:id` pair, or when either side of that pair is blank. `ADMIN@` is dropped, since the `@` says
a scope was meant while an empty string arrived.

Reach for `Scope.parseOrNull` directly where the roles come from somewhere other than a claim in
this shape, such as a role assignment table:

```kotlin
val roles: Map<Scope, Set<RoleName>> = assignments
    .mapNotNull { assignment ->
        Scope.parseOrNull(assignment.scope)?.let { it to RoleName(assignment.role) }
    }
    .groupBy({ it.first }, { it.second })
    .mapValues { (_, names) -> names.toSet() }

val principal = Principal(
    subjectId = subjectId,
    roles = roles,
    scope = scopeClaim,
)
```

#### The role catalogue

`InMemoryRoleCatalog` reads a map, which covers a deployment whose role definitions live in
its own source. Behind it is `RoleCatalog`, a one-method interface, so a service that keeps
definitions elsewhere writes its own:

```kotlin
interface RoleCatalog {
    fun permissions(role: RoleName): Set<String>
}
```

The strings in the set are permissions naming a resource type, and `Authorizer` compares each one to
the requested permission whole. The entry `"*"` is the exception, and it grants everything. A
catalogue permission names a resource type by convention, while a permission string names an
instance, so each string belongs to the model it was written for.

**Where definitions live in storage, read them once and keep the result.** The method is
synchronous, so reading storage inside it means blocking, which puts a round trip in front of
every authorization. Load at startup, build a catalogue from what you read, and when the
definitions change build another and swap the reference, so each check reads a complete snapshot:

```kotlin
@Volatile
private var catalog: RoleCatalog = InMemoryRoleCatalog(loadDefinitions())

fun onDefinitionsChanged() {
    catalog = InMemoryRoleCatalog(loadDefinitions())
}
```

A subject's own roles are a separate matter, and those are read per request into a
[`Principal`](#core-types-reference). Swapping the catalogue changes what a role means, not who
holds it.

| What the catalogue returns for a name | What a subject holding that role may do |
|---|---|
| `setOf("report:read", "project:read")` | exactly those two permissions |
| `setOf("*")` | every permission |
| the empty set | nothing |

**Return the empty set for an unknown name.** `Authorizer` reads the catalogue for the names a
principal holds at the scopes being checked, and those names arrived from outside the process, so
unknown, misspelled and withdrawn names reach it too. `InMemoryRoleCatalog` returns the empty set
for a name it holds no definition for, and the empty set grants nothing, so such a name is safe. A
catalogue of your own has to return the same.

By convention a catalogue permission names a type and a verb, as `document:approve` does, and a
permission string's action is the bare verb instead. The catalogue permission names the type and the
scope chain names the object, so one definition serves every organization.
[Writing an evaluator](#writing-an-evaluator) builds a catalogue permission in that spelling, so an
evaluator that reads both models depends on it.

**Role inheritance, where a senior role absorbs a junior one, belongs inside your catalogue.** The
set `permissions` returns is flat and `Authorizer` reads it as it comes. So compute the transitive
closure once at startup and return the union, and a catalogue where `ADMIN` absorbs `APPROVER`
returns both sets of permissions under the `ADMIN` name. Role inheritance is hierarchical RBAC,
standardised in ANSI INCITS 359-2004, and it is a separate mechanism from the
[hierarchy inheritance](#hierarchy-inheritance) between resource paths.

#### The scope chain

`Authorizer.permits` takes the scope chain the target object sits in, outermost first. A role grants
the requested permission when its catalogue set holds that permission or `"*"`, and the role is held
at any link of the chain, so an organization administrator reaches every project inside the
organization through that one role. Where the subject holds several roles, any one of them granting
it is enough. Taking a `document:approve` check against the step 1 catalogue:

| Roles held | Chain passed | Result |
|---|---|---|
| `ADMIN` at `organization:o1` | `[organization:o1]` | granted, held at the scope checked |
| `ADMIN` at `organization:o1` | `[organization:o1, project:p1]` | granted, an outer link grants at an inner one |
| `APPROVER` at `project:p1` | `[organization:o1, project:p1]` | granted, the chain reaches the scope held |
| `ADMIN` at `organization:o1` | `[project:p1]` | refused, the chain omits the scope held |
| `APPROVER` at `project:p2` | `[organization:o1, project:p1]` | refused, another instance of the same type |
| `OWNER` at [`Scope.PLATFORM`](#the-platform-scope) | `[organization:o1]` | granted, the platform scope is consulted on every call |

**You pass the chain, because it is the only hierarchy a scoped-role check carries.** So a request
can carry the object's id alone. The service loads the object, reads the containers from the stored
record, and passes those as the chain. See
[acting on one existing resource](#acting-on-one-existing-resource) for that code.

#### The platform scope

`Scope.PLATFORM` is `Scope("platform", "*")`, where the `*` is a literal id, and `Authorizer`
consults it on every call, whatever the chain holds. So a role held there grants everywhere.

```kotlin
val operator = Principal(
    subjectId = subjectId,
    roles = mapOf(Scope.PLATFORM to setOf(RoleName("OWNER"))),
)

authorizer.permits(operator, "report:manage", emptyList())   // true
```

With an empty chain, a role held at `Scope.PLATFORM` is the only one consulted.

#### Delegated scope

A token can be issued to an application acting for the subject, and the `scope` claim records how
much of the subject's authority that application was granted consent to use. `Principal.scope` holds
the claim as it arrived, which
[RFC 6749 §3.3](https://datatracker.ietf.org/doc/html/rfc6749#section-3.3) defines as the authority
delegated to the client application. It is a list of strings. The `Scope` type above is its own
type: a resource type with one instance of it.

`Authorizer` applies the claim as a second condition alongside the roles. Effective authority is
the intersection of what the subject holds and what the application was granted consent to do, so
the claim can only subtract: the roles have to grant the permission either way.

**Which kind of token this is travels in the token.** A request the subject makes directly, with no
application in between, carries `Authorizer.UNRESTRICTED` as its only scope value, and the second
condition passes. A request an application makes on the subject's behalf carries the permissions
that application was consented, written in the catalogue's vocabulary.

```kotlin
Principal(subjectId, roles, scope = listOf(Authorizer.UNRESTRICTED))   // signed in directly
Principal(subjectId, roles, scope = listOf("report:read"))             // consented to one thing
```

One value rather than the subject's whole permission set is what keeps a token holding roles at
several containers inside the 4096 bytes
[RFC 6265 §6.1](https://datatracker.ietf.org/doc/html/rfc6265#section-6.1) requires a cookie to
support.

A value in the claim matches the requested permission by equality, so a delegated claim has to
carry the permission itself. Take `permits(principal, "report:manage", chain)` where the subject's
roles already grant `report:manage`:

| What `Principal.scope` holds | Outcome |
|---|---|
| `listOf(Authorizer.UNRESTRICTED)` | granted, no application stands in between |
| `listOf("report:manage", "report:read")` | granted, the permission is listed |
| `listOf("report:read")` | refused, the permission is outside the delegated set |
| `listOf("openid", "profile", "email")` | refused, identity scopes name no permission |
| `emptyList()` | refused, a claim listing nothing grants nothing |

An issuer that writes identity scopes such as `openid profile email` into the claim therefore needs
`Authorizer.UNRESTRICTED` added for a direct login, since those values name no permission.

### Permission strings

#### Format

A permission string is `<resource-path>:<action>`.

```
organization/org_123:read                       one organization, one action
organization/org_123/project/proj_456:*         one project, every action on it and under it
report:create                                   the report type, so every report, one action
*:*                                             any path, any action
*                                               the same, written the way a role spells it
```

The last `:` separates the path from the action, so a colon anywhere inside a permission string
belongs to the resource path. `Permission.parse` reads that form and the bare `*`, and it throws
`IllegalArgumentException` for a blank string, for any other string with no `:`, and for one whose
last `:` sits at either end. Where a string reached the process from outside, catch it.

`Permission.parse` is the only reader and it throws, so that exception is how a malformed string
arrives. `anyCovers` and `findMatch`, the two [matcher](#matching-rules) calls that search a list of
permission strings the subject holds, parse those strings in list order and stop at the first one
that covers. So a malformed entry ahead of the match throws from the matcher call, and one behind it
is never read. Validate held strings where they enter the process. `Scope.parseOrNull` returns
`null` and the caller skips the entry, while `Permission.parse` throws, so each model needs its own
guard at the boundary.

A catalogue permission, a permission string and a `Scope` all read alike, and the colon does a different
job in each. `report:read` in your catalogue is one permission, and `Authorizer` compares it to the
requested permission whole, so the colon there is convention. `report:read` as a permission string is
the resource path `report` and the action `read`, and `covers` compares the two halves separately.
`organization:org_123` as a `Scope` is a resource type and one instance id. `Scope.parseOrNull`
splits at the first colon and `Permission.parse` at the last, so `organization:a:b` is the id `a:b`
to one and the action `b` to the other. Each value is read by the call belonging to its own model.

#### Standard actions

Only `*` carries matching behaviour in code. Every other action name matches by exact string, so a
name of your own works like `create`, `read`, `list`, `update` and `delete`, which are the names
the library documents. Write `:*` as the action where one entry should reach every action.

| Written | What it means | How it matches |
|---|---|---|
| `create` | create a new resource | by exact string |
| `read` | read a single resource | by exact string |
| `list` | list resources | by exact string |
| `update` | modify an existing resource | by exact string |
| `delete` | remove a resource | by exact string |
| `:*` | full control over the resource the permission names | covers every required action on a path it covers |
| `*` | full control over every path, the whole string | reads as `*:*` and covers every permission |

**`*` is the only action that reaches another.** `report:*` grants every action on the type in a
catalogue and covers every action on the path in a permission string. Every other action, whether
one of the five above or one of your own, matches the action it spells. The
[quick start](#quick-start) shows both sides of that after step 4.

#### Matching rules

| Rule | Granted | Required | Result |
|------|---------|----------|--------|
| Exact match | `report:read` | `report:read` | covers |
| Wildcard action | `report:*` | `report:delete` | covers |
| Wildcard instance | `organization/*:read` | `organization/org_123:read` | covers |
| Type level | `organization:read` | `organization/org_123:read` | covers |
| Superadmin | `*:*` | `document/doc_789:delete` | covers |
| Superadmin, bare | `*` | `document/doc_789:delete` | covers |
| Hierarchy | `organization/org_123:read` | `organization/org_123/project/proj_456:read` | covers |
| Narrower action | `report:read` | `report:delete` | does not cover |
| Narrower path | `organization/org_123/project/proj_456:*` | `organization/org_123:read` | does not cover |

**`PermissionMatcher` holds the matching calls**, and it takes either raw strings or parsed
`Permission` objects. `anyCovers` and `findMatch` search a list the subject holds:

```kotlin
val held = listOf("organization/org_123:*", "report:read", "report:list")

PermissionMatcher.anyCovers(held, "organization/org_123/project/proj_456:read")   // true
PermissionMatcher.findMatch(held, "report:read")                                 // "report:read"
PermissionMatcher.findMatch(held, "user:delete")                                 // null
```

`findMatch` returns the first held string that covers the requirement, in list order. Keep that string
and an audit record can name what granted access.

#### Hierarchy inheritance

A granted path covers a required path when the granted segments cover the leading segments of the
required one, so a permission at a broader path covers everything under it. The cascade is modelled
on the resource hierarchies of GCP IAM and Azure RBAC:

```
organization/org_123:*
  covers  organization/org_123/project/proj_456:read
  covers  organization/org_123/project/proj_456:update
  covers  organization/org_123/project/proj_456/document/doc_789:approve
```

Inheritance applies to every action, so `organization/org_123:read` covers
`organization/org_123/project/proj_456:read`. It runs downward, from the granted path toward the
paths under it.

### Resource paths

A resource path is the path half of a permission string. Where a service builds its paths only
through `Permission.parse`, read [Wildcards](#wildcards) below and skip the rest of this section.

#### Segments

A `ResourcePath` is an ordered list of `ResourceSegment`s, each one a type with an optional instance
id, and a raw path writes them separated by `/`. A `ResourceSegment` pairs a type with an instance
id as a `Scope` does, and writes it `organization/org_123` where a `Scope` writes
`organization:org_123`. The two belong to different ways of carrying authority: a segment is part of
a resource path, while a `Scope` keys a role and sits in a scope chain.

**How `parse` reads a raw path:** it splits on `/` and pairs the tokens. Tokens at even indices
become types, and tokens at odd indices become the instance id of the type before them. So the four
tokens below give two segments rather than four.

```kotlin
val path = ResourcePath.parse("organization/org_123/project/proj_456")

path.segments[0]   // ResourceSegment("organization", "org_123")
path.root          // ResourceSegment("organization", "org_123")
path.leaf          // ResourceSegment("project", "proj_456")
path.depth         // 2
```

A type token with no id after it becomes a type-level segment, so an odd number of tokens parses too:

```kotlin
ResourcePath.parse("organization/org_123/project").leaf   // ResourceSegment("project")
```

A segment reports which of three shapes it holds. Two of them are broad: a `*` instance id and a
type-level segment both cover any instance of the type.

| Segment | What it targets | `isInstance` | `isWildcard` | `isTypeLevel` |
|---|---|---|---|---|
| `ResourceSegment("organization", "org_123")` | that one organization | true | false | false |
| `ResourceSegment("organization", "*")` | any organization | false | true | false |
| `ResourceSegment("organization")` | any organization | false | false | true |

A `*` instance id is written into the string. `parse` leaves a type-level segment for a type token
standing alone. `covers` reads the two the same way, so either spelling works in a stored
permission string, and a `*` in the type position covers any type.

#### Ancestors

`ancestors()` returns a `Sequence`, walking up the hierarchy and yielding one path per segment above
the leaf. It starts at the direct parent and ends at the path holding the root segment alone. A
single-segment path yields an empty sequence. Walk it to look for a grant recorded on a container
above the object.

```kotlin
val path = ResourcePath.parse("organization/org_123/project/proj_456/document/doc_789")

path.ancestors().toList()
// [organization/org_123/project/proj_456, organization/org_123]
```

`isAncestorOf` returns `true` when one path you already hold sits above another. A path is never
its own ancestor:

```kotlin
val organization = ResourcePath.parse("organization/org_123")
val project = ResourcePath.parse("organization/org_123/project/proj_456")

organization.isAncestorOf(project)        // true
project.isAncestorOf(organization)        // false
organization.isAncestorOf(organization)   // false
```

#### Wildcards

`*` stands in for an instance id, for a type, or for both. Its meaning follows from where it
appears, so a string carrying one changes meaning when it is copied between a `RoleCatalog` set, a
`scope` claim and a permission string:

| Where `*` appears | What it means there |
|---|---|
| the instance in a path, as `organization/*:read` | any instance of that type |
| the type in a path, as `*:read` | any type |
| the action, as `report:*` | any action on a path it covers |
| a whole permission string, as `*` | every permission, read as `*:*` |
| a `RoleCatalog` set, as `setOf("*")` | every permission |
| a permission inside a `RoleCatalog` set, as `project:*` | every action on `project` |
| the `scope` claim, as `listOf("*")` | the permission `"*"` alone |
| `Scope.PLATFORM`, which is `Scope("platform", "*")` | a literal id, compared by equality like any other |

```kotlin
ResourcePath.parse("organization/*").covers(ResourcePath.parse("organization/org_123"))   // true
ResourceSegment("*", "proj_456").covers(ResourceSegment("project", "proj_456"))           // true
```

`covers` works at three levels. `PermissionMatcher` compares two permissions,
`ResourcePath.covers` compares two paths, and `ResourceSegment.covers` compares two segments.

## The evaluation chain

### What the chain is for

`Authorizer` and `PermissionMatcher` each read one source. Once your service decides from
more than one source, you need an order between them and a rule for which decision wins.
`AuthorizationEvaluator` and `AuthorizationChain` supply both. The library ships the interface and the
composition, and you write one evaluator per source of authority.

The chain in this section holds evaluators. The scope chain a `permits` call takes holds scopes.

Each evaluator names the source it reads, as an `AuthZSource`, and the result carries that name:

| `AuthZSource` | Stands for | What the evaluator reads | Example |
|---|---|---|---|
| `IMPLICIT` | a baseline every authenticated subject holds | the subject's own identity | `user/self:read` |
| `RBAC` | role-based access control | the roles the subject holds | a `VIEWER` role granting `report:read` |
| `REBAC` | relationship-based access control | a relationship recorded between the subject and the object | the subject owns `organization/org_123` |
| `ABAC` | attribute-based access control | attributes of the subject, the object or the moment | a policy refusing a subject outside the EU on a resource tagged `gdpr` |
| `GRANT` | a grant issued on demand for one object | a grant record | a one-time approval of `document/doc_789:approve` |

These five names are what `AuthZResult.source` carries into an audit record, and an evaluator of
your own picks whichever one describes where its decision came from. The library reads an instance
id as opaque, so `self` in `user/self:read` is an instance id a service writes from the subject's
own id.

### The three decisions

An evaluator picks a `PolicyDecision`, which `AuthZResult.decision` carries:

| Decision | What it means |
|---|---|
| `ALLOW` | this source grants access |
| `DENY` | this source refuses access, and the chain returns that refusal |
| `ABSTAIN` | this source has nothing to say, so the chain carries on |

`AuthZResult` has one factory per decision, and one property reads each decision back:

| Factory | What it fills | Reads back as |
|---|---|---|
| `AuthZResult.allowed(source, matched, grantId = null)` | `source`, `matched`, `grantId` | `allowed` |
| `AuthZResult.denied(reason, source = null, matched = null)` | `reason`, `source`, `matched` | `denied` |
| `AuthZResult.abstain()` | the decision alone | `abstained` |

`matched` holds what granted access or what triggered the refusal, as a permission string, a
catalogue permission, a relationship or a policy name. `grantId` is a `UUID` and it is filled where
`source` is `GRANT`, so a grant-based allow names the record it came from. `reason` carries the
refusal text for an audit record. `source`, `matched`, `grantId` and `reason` are each nullable, so
one log line records the grounds the deciding evaluator supplied, and the chain's own default `DENY`
carries a reason alone.

### Phases and precedence

`AuthorizationChain` holds three lists of evaluators, one per phase, and each phase runs under its
own rule:

| Phase | What its evaluators are for | The rule it runs under |
|---|---|---|
| Granting | sources that confer authority | the first `ALLOW` or `DENY` ends it, an `ALLOW` running the constraint phase next and a `DENY` returning immediately |
| Constraint | cross-cutting policies that restrict | they run in order until one returns a `DENY` result, that `DENY` replaces the `ALLOW`, and the rest never run |
| Fallback | sources consulted when the granting phase abstained | the first `ALLOW` or `DENY` ends it, an `ALLOW` running the constraint phase for the first time and a `DENY` returning immediately |
| Default | every granting and fallback evaluator abstained | `DENY`, naming the required permission |

**One consequence matters:** a policy in the constraint phase can refuse an `ALLOW` that a granting
evaluator produced. That makes the constraint phase the place for a rule that has to hold however
access was granted.

### Writing an evaluator

`AuthorizationEvaluator` requires a `source` property and one `evaluate` function. `evaluate` is a
`suspend` function, so your evaluator can read storage or call a service directly, while `Authorizer.permits` and `PermissionMatcher.covers` stay plain calls on the calling
thread.

This one decides from the permission strings the subject holds, which it reads from
`context.permissions`. Those strings record a relationship with one named object, so it names `REBAC`
as the source its decision came from:

```kotlin
import group.phorus.authz.core.evaluation.AuthorizationEvaluator
import group.phorus.authz.core.evaluation.PermissionMatcher
import group.phorus.authz.core.model.AuthZResult
import group.phorus.authz.core.model.AuthZSource
import group.phorus.authz.core.model.EvaluationContext

class HeldPermissionEvaluator : AuthorizationEvaluator {   // built once

    override val source = AuthZSource.REBAC

    override suspend fun evaluate(context: EvaluationContext): AuthZResult {
        val matched = PermissionMatcher.findMatch(context.permissions, context.requiredPermission)

        return if (matched != null) AuthZResult.allowed(source, matched)
        else AuthZResult.abstain()
    }
}
```

A service assembles an `EvaluationContext` once per check and hands it to the chain, which passes it
to each evaluator it reaches. Your evaluator reads the fields it cares about and ignores the rest:

| Field | What it holds |
|---|---|
| `principal` | the subject, with the roles it holds keyed by scope and the delegated scope |
| `scopes` | the containers the target object sits inside, outermost first, which is the chain `Authorizer.permits` reads |
| `permissions` | the permission strings the subject holds, as raw strings in the `<resource-path>:<action>` form, which is what `findMatch` searches |
| `requiredPermission` | what the check requires, already parsed as a `Permission` |
| `attributes` | contextual values typed `Map<String, Any?>`, keyed by a dotted name whose first part groups related values, such as `"user.region"` to `"EU"` or `"env.business_hours"` to `true` |
| `grantToken` | a grant token as it arrived, as a `String?`, for a fallback evaluator to look up |
| `properties` | extra pairs of strings the service puts there for evaluators of its own |

An `attributes` value arrives as `Any?`, so the evaluator reading one compares or casts it as its own
policy needs. A grant token is the string a request carries to name a grant record, and the
fallback-phase evaluator holding the `GRANT` source looks that record up. An evaluator or an audit
record wanting the subject's identifier alone reads `principal.subjectId`.

Everything a check varies by travels in the context, so one instance of an evaluator serves every
request the service handles.

`ScopedRoleEvaluator` is the role model written as an evaluator, and the library ships it. It takes
an `Authorizer` and reads the subject and the scope chain from the context it is handed. A catalogue
permission is `"${required.resourcePath.leaf.type}:${required.action}"`, since the leaf segment of
the required permission's path carries the type and the action carries the verb:

```kotlin
class ScopedRoleEvaluator(
    private val authorizer: Authorizer,
) : AuthorizationEvaluator {

    override val source: AuthZSource = AuthZSource.RBAC

    override suspend fun evaluate(context: EvaluationContext): AuthZResult {
        val required = context.requiredPermission
        val permission = "${required.resourcePath.leaf.type}:${required.action}"

        return if (authorizer.permits(context.principal, permission, context.scopes)) {
            AuthZResult.allowed(source = source, matched = permission)
        } else {
            AuthZResult.abstain()
        }
    }
}
```

It abstains where the roles fall short, so a later phase can still grant.

The constraint phase reads a `DENY` and carries on past any other result, so a constraint-phase
evaluator returns a result whose decision is `DENY` or `ABSTAIN`:

```kotlin
class BusinessHoursPolicy : AuthorizationEvaluator {   // built once

    override val source = AuthZSource.ABAC

    override suspend fun evaluate(context: EvaluationContext): AuthZResult =
        if (context.attributes["env.business_hours"] == true) AuthZResult.abstain()
        else AuthZResult.denied(reason = "Outside business hours", source = source)
}
```

**Signal an authorization outcome through the return value, never by throwing.** An exception out of
`evaluate` means infrastructure failed, such as a database that timed out or configuration that
broke on load. Returning `DENY` is how you refuse.

An exception out of `evaluate` reaches the caller of `AuthorizationChain.evaluate` and ends the check
there, so handle it where the chain is called.

### Composing a chain

`AuthorizationChain.standard` takes one evaluator per source and fills the three phases. It puts
`rbac`, `implicit` and `rebac` in the granting phase, `abac` in the constraint phase and `grant` in
the fallback phase. Every parameter accepts `null` and a `null` is skipped, so a service with one
source passes one argument.

A chain is built once and serves every request. In the two chain snippets `heldPermissionEvaluator`
and `businessHoursPolicy` are instances of the two classes above, while `baselineEvaluator` and
`oneTimeGrantEvaluator` stand for evaluators of your own, one per source you decide from.

```kotlin
import group.phorus.authz.core.evaluation.AuthorizationChain
import group.phorus.authz.core.evaluation.ScopedRoleEvaluator

val authorizationChain = AuthorizationChain.standard(
    rbac = ScopedRoleEvaluator(authorizer),
    implicit = baselineEvaluator,
    rebac = heldPermissionEvaluator,
    abac = businessHoursPolicy,
    grant = oneTimeGrantEvaluator,
)
```

`AuthorizationChain.evaluate` is a `suspend` function, and it takes an `EvaluationContext`.
`principal` and `requiredPermission` are the two required arguments, `scopes`, `permissions`,
`attributes` and `properties` default to empty, and `grantToken` defaults to `null`:

```kotlin
import group.phorus.authz.core.model.EvaluationContext
import group.phorus.authz.core.model.Permission

val context = EvaluationContext(        // one per check
    principal = principal,
    scopes = listOf(Scope("organization", "org_123"), Scope("project", "proj_456")),
    permissions = listOf("organization/org_123:*", "report:read"),
    requiredPermission = Permission.parse("organization/org_123/project/proj_456:read"),
    attributes = mapOf("env.business_hours" to true),
)

suspend fun decide(): Boolean {
    val result = authorizationChain.evaluate(context)

    result.source    // which layer decided, for an audit record
    result.matched   // what granted access, or what triggered the refusal
    result.grantId   // the grant record a grant-based allow came from
    result.reason    // why access was refused

    return result.allowed
}
```

For any other order, construct `AuthorizationChain` directly and fill the three phase lists in the
order you want.

```kotlin
val customChain = AuthorizationChain(
    grantingEvaluators = listOf(
        ScopedRoleEvaluator(authorizer),
        heldPermissionEvaluator,
    ),
    constraintEvaluators = listOf(businessHoursPolicy),
    fallbackEvaluators = listOf(oneTimeGrantEvaluator),
)
```

A phase list may hold more than one evaluator, and the phase runs them in the order given.

## Core types reference

| Type | Package, under `group.phorus.authz.core` | What it holds |
|------|---------|---------------|
| `RoleName` | `model` | a role name, as an inline value class over `String` |
| `Scope` | `model` | a resource type and one instance of it, formatted `type:id` |
| `Principal` | `model` | a subject id as a `UUID`, its roles keyed by scope, and the delegated scope |
| `Permission` | `model` | a parsed permission string: a resource path and an action |
| `ResourcePath` | `model` | an ordered list of resource segments |
| `ResourceSegment` | `model` | one segment: a type and an optional instance id |
| `AuthZResult` | `model` | a decision with its source, what matched, a grant id and a reason |
| `PolicyDecision` | `model` | `ALLOW`, `DENY`, `ABSTAIN` |
| `AuthZSource` | `model` | which layer decided: `IMPLICIT`, `RBAC`, `REBAC`, `ABAC`, `GRANT` |
| `EvaluationContext` | `model` | one check's inputs: the subject, the scope chain, held permissions, required permission, attributes, grant token and extra properties |
| `RoleCatalog` | `evaluation` | the role definitions a check reads, with one method |
| `InMemoryRoleCatalog` | `evaluation` | a `RoleCatalog` reading a map handed to it |
| `Authorizer` | `evaluation` | the scoped-role decision over a `Principal` and a scope chain |
| `ScopedRoleEvaluator` | `evaluation` | the role model as an `AuthorizationEvaluator`, over an `Authorizer` |
| `PermissionMatcher` | `evaluation` | permission-string matching with wildcards and hierarchy |
| `AuthorizationEvaluator` | `evaluation` | one source of authority, implemented by a service |
| `AuthorizationChain` | `evaluation` | a chain of evaluators with granting, constraint and fallback phases |

## Security considerations

- **`Authorizer` grants only the permissions a role's set lists.** It grants when the requested
  permission appears in the set the catalogue returns, or when `"*"` does. So a set that omits a
  permission makes `permits` return `false` for it, while a catalogue returning `"*"` for an unknown
  name turns the same omission into open access.
- **Return 404 where a 403 would confirm an id.** An instance check runs once the object is loaded,
  so the status code carries information on its own. Reserve it for a subject with no sight of the
  object, since one who may already read it learns nothing from a 403 and is better told which
  permission they lack.
- **A direct login needs `Authorizer.UNRESTRICTED` in its `scope` claim.** A value in the claim
  matches the requested permission by equality, so a claim holding identity scopes or nothing
  refuses every check. Minting that value from the path that issues a delegated token would give an
  integration the subject's full authority instead of its consented share.
- **Check a granter's authority with `permits` at the chain the grant is made on.** A rule that
  refuses to hand out a role carrying more than the granter holds is the standard guard against
  escalation through delegated administration, and writing it with `permitsAnywhere` passes
  authority held at one container for a grant made at another.
- **Follow every `permitsAnywhere` with a scoped check.** It returns `true` where a subject holds a
  permission at some scope it holds a role at, which is what a route can check before the object is
  loaded. A caller holding `EDITOR@organization:A` passes it and then reaches an object in
  organization B, so a route where it is the last check is broken access control.
- **Drop a malformed role entry and keep the rest.** `Principal.fromRoleEntries` sends each one to
  `onDropped`, and `Scope.parseOrNull` returns `null` for a reader of its own. A role entry arrives
  from outside the process, even when it arrives signed.
- **A catalogue edit reaches every holder of the role.** Changing which permissions a role
  grants applies to everybody holding that role, because the catalogue is keyed by the name alone.
- **Removing a role from a subject takes effect when the principal is next built.** So whatever
  carries the roles bounds how long that removal takes to apply.
- **Put scoped roles in what a subject carries and permission strings in storage.** A token carrying
  permission strings grows with the objects the subject can reach.

## Standards references

- [RFC 7643 §4.1.2](https://datatracker.ietf.org/doc/html/rfc7643#section-4.1.2) SCIM core schema,
  which defines `roles` and states that no vocabulary or syntax is specified for its values.
- [RFC 6749 §3.3](https://datatracker.ietf.org/doc/html/rfc6749#section-3.3) OAuth 2.0, which defines
  `scope` as the authority delegated to a client.
- [RFC 9068 §7.2](https://datatracker.ietf.org/doc/html/rfc9068#section-7.2) JWT profile for OAuth 2.0
  access tokens, which registers `roles` as a claim name.
- ANSI INCITS 359-2004, NIST RBAC. Core RBAC makes the permissions in force the union over the
  roles activated, which here is the union over the roles a `Principal` holds at the scopes checked.
  Hierarchical RBAC adds inheritance between roles.

## Building and contributing

See [Contributing Guidelines](CONTRIBUTING.md).

## Authors and acknowledgment

Developed and maintained by the [Phorus Group](https://phorus.group) team.
