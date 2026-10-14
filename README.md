# authz-core

[![GitHub license](https://img.shields.io/badge/license-Apache%20License%202.0-blue.svg?style=flat)](https://www.apache.org/licenses/LICENSE-2.0)
[![Maven Central](https://img.shields.io/maven-central/v/group.phorus/authz-core)](https://mvnrepository.com/artifact/group.phorus/authz-core)
[![codecov](https://codecov.io/gh/phorus-group/authz-core/branch/main/graph/badge.svg)](https://codecov.io/gh/phorus-group/authz-core)

Authorization library for Kotlin/JVM services. Provides framework-agnostic scoped-role checking,
permission-string matching with wildcards and hierarchy inheritance, and a composable evaluator
chain, so you can decide what a caller may do from role definitions written as ordinary Kotlin code.

For the JWT creation and validation that issues the claims a decision is built from, see
[authn-core](https://github.com/phorus-group/authn-core).

### Notes

> The project runs a vulnerability analysis pipeline regularly,
> any found vulnerabilities will be fixed as soon as possible.

> The project dependencies are being regularly updated by [Renovate](https://github.com/phorus-group/renovate).

## Table of contents

- [What an authorization check asks](#what-an-authorization-check-asks)
  - [Two ways to carry authority](#two-ways-to-carry-authority)
- [Getting started](#getting-started)
  - [Installation](#installation)
  - [Quick start](#quick-start)
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
- [Enforcement patterns](#enforcement-patterns)
  - [Checks before the object is loaded](#checks-before-the-object-is-loaded)
  - [Instance checks once the object is loaded](#instance-checks-once-the-object-is-loaded)
- [Security considerations](#security-considerations)
- [Standards references](#standards-references)
- [Building and contributing](#building-and-contributing)
- [Authors and acknowledgment](#authors-and-acknowledgment)

***

## What an authorization check asks

If you are already familiar with scoped roles and permission strings, feel free to skip to
[Getting started](#getting-started).

A check asks whether one subject may perform one action on one object.

- The **subject** is whoever a check is about, which is usually the user or service account a call
  is being made on behalf of.
- The **action** is what the subject wants to do, such as reading or approving. Each of the two
  ways below writes it a little differently, and each section says how.
- The **object** is the one resource the action lands on, named by its type and its id joined by
  `/`, as in `document/doc_789`.

Each of the two ways below names the object in its own way. Which one a service picks decides what
a check takes as arguments.

### Two ways to carry authority

A **role** is a named set of actions. A **scoped role** is a role held at one **scope**, which is a
resource type together with one instance of that type, such as the organization `org_123`. With
scoped roles the subject carries a set of them, where the role name says what the subject is and the
scope says where it holds that role. The object arrives separately, as the **scope chain**, the list
of scopes the object sits inside, outermost first. A role held at an outer scope grants at the inner
ones, so an administrator of `org_123` reaches a document in a project inside it when the chain
passed for that document names the organization. Here an action is written as a resource type and a
verb joined by `:`, as in `document:approve`, and the chain is what says which document.

With **permission strings** the subject carries strings that already name their object, each one a
**resource path** and an action joined by a colon, as in `organization/org_123:read`. A resource
path is a chain of types and ids separated by `/`, and it names the object, so the action here is
the bare verb `read`. What a check requires is another string of the same shape, so the two strings
are all it compares.

Either one answers on its own, and a service can compose both.

| What differs | Scoped roles | Permission strings |
|---|---|---|
| What a check reads | a [`Principal`](#core-types-reference), an action and a scope chain | the permission strings held and the one required |
| Where the object is named | the scope chain the caller passes in | inside the permission string itself |
| What the subject carries | one scoped role per role and scope | one string per object per action |
| How that set grows | with the number of places it holds a role | with the number of objects reachable |
| When removing authority takes effect | when a service next builds the principal | when the strings are next supplied |
| How breadth works | a role at an outer scope grants at inner ones | a path prefix covers everything under it |
| What the calling code has to know | where the object sits | the required permission alone |
| Entry point | `Authorizer.permits` | `PermissionMatcher.covers` |

**When to use each:**

- **Scoped roles** fit authority held over a container, such as administrator of an organization or
  approver on a project. The cost is that the scope chain has to be known before the check runs,
  because the chain is what names where the object sits.
- **Permission strings** fit authority granted on one named object, such as a share, a one-off grant
  or a relationship recorded against a single resource. The requirement names its own object, so the
  string is all a check reads. The cost is size. The permission strings a subject holds enumerate the
  objects it can reach, so hold them in storage the service reads on each check rather than inside a
  token.
- **Both together** suits a design that needs both answers. Roles answer whether this kind of member
  may do this at all. Permission strings answer whether this particular object was shared with this
  subject. See [the evaluation chain](#the-evaluation-chain) for composing the two answers into one.

## Getting started

### Installation

Make sure that `mavenCentral` (or any of its mirrors) is added to the repository list of the project.

Binaries and dependency information for Maven and Gradle can be found at [http://search.maven.org](https://search.maven.org/search?q=g:group.phorus%20AND%20a:authz-core).

<details open>
<summary>Gradle / Kotlin DSL</summary>

```kotlin
implementation("group.phorus:authz-core:x.y.z")
```
</details>

<details open>
<summary>Gradle</summary>

```groovy
implementation 'group.phorus:authz-core:x.y.z'
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

The library requires only the Kotlin standard library, and compiles against Java 17.

### Quick start

Steps 1 to 3 get a scoped-role check running in your service, and you need three things: role
definitions, a principal, and the scope chain the target object sits in. Step 4 is the
permission-string model, which answers on its own and needs none of the three.

**1. Declare the roles and the actions each one grants.**

A **role catalogue** maps a role name to the actions that role grants. A `RoleCatalog` implementation
is static application code: one definition per role for the whole deployment, held in memory and
read on every check.

```kotlin
import group.phorus.authz.core.evaluation.RoleCatalog
import group.phorus.authz.core.model.RoleName

object ApplicationRoles : RoleCatalog {

    private val definitions = mapOf(
        RoleName("OWNER") to setOf("*"),   // every action
        RoleName("ADMIN") to setOf("project:manage", "report:manage", "document:approve"),
        RoleName("APPROVER") to setOf("document:approve", "document:read"),
        RoleName("VIEWER") to setOf("report:read", "project:read", "document:read"),
    )

    override fun actions(role: RoleName): Set<String> = definitions[role].orEmpty()
}
```

`Authorizer` is what answers a scoped-role check. It compares a catalogue action to the requested
action as one whole string, so the two match only when they are equal, and the colon in
`document:approve` is convention here. A name of your own works as well as these. The action `"*"`
is the one exception, and a role whose set holds it grants every action. The action `project:*`
grants nothing unless a check requests the literal action `project:*`, because it is compared whole
like any other action. See [Wildcards](#wildcards) for what `*` means in each place it appears.

Whole comparison bounds what one action grants. `report:manage` in this catalogue is the action
`report:manage`, so a subject whose only role is `ADMIN` is refused a `report:read` check, and a
role that grants both lists both.

**`manage` is matched differently in the two models, and both lines below are true.**

```kotlin
// principal and chain are the ones built in steps 2 and 3
authorizer.permits(principal, "report:read", chain)   // false, ADMIN holds report:manage
PermissionMatcher.covers(granted = "report:manage", required = "report:read")   // true
```

A catalogue action is compared whole, so `manage` there grants the action spelled `report:manage`
and nothing else. In a permission string `manage` covers every action on that path and on the paths
under it, which [Standard actions](#standard-actions) states on the other side of this asymmetry. A
string copied from one model into the other changes meaning.

**2. Build a principal for the subject the request acts for.**

A `Principal` belongs to one request. Build one per request, from that request's claims, since one
held past its request answers every later check from the first request's subject.

Each role is keyed by the scope it is held at. So one principal can hold several roles in a single
organization, and roles in several organizations at once. See [Scoped roles](#scoped-roles) for
building the same map from a token's `roles` claim.

```kotlin
import group.phorus.authz.core.model.Principal
import group.phorus.authz.core.model.Scope

val principal = Principal(
    subjectId = subjectId,          // a java.util.UUID off this request's claims
    roles = mapOf(
        Scope("organization", organizationId.toString()) to setOf(RoleName("ADMIN")),
        Scope("project", projectId.toString()) to setOf(RoleName("APPROVER")),
    ),
)
```

`Principal` takes a third argument, `scope`, which holds the OAuth `scope` claim as a list of
strings and defaults to an empty list. `Authorizer` reads it only when constructed with
`narrowByScope = true`. The `Scope` type keying the roles map is a different type, a resource type
with one instance of it. See [Delegated scope](#delegated-scope) for what the claim does.

**3. Check an action against the scope chain the object sits in.**

`Authorizer` holds the catalogue and nothing else, so one instance serves every request. Build it at
startup.

The scope chain is the list of scopes the target object sits inside, outermost first. The caller
builds it, and `permits` tries each link on its own, so the order is for the reader rather than for
the library. Where the stored record names the containers an object sits in, read the chain off that
record, as the snippet below does with a loaded `document`.

```kotlin
import group.phorus.authz.core.evaluation.Authorizer

val authorizer = Authorizer(ApplicationRoles)

val chain = listOf(
    Scope("organization", document.project.organization.id.toString()),
    Scope("project", document.project.id.toString()),
)

authorizer.permits(principal, "document:approve", chain)   // true
```

**4. Match permission strings where authority was granted on one named object.**

A permission string is a resource path and an action joined by `:`. `covers` answers whether the
permission a subject was granted is broad enough for the one a check requires.

```kotlin
import group.phorus.authz.core.evaluation.PermissionMatcher

PermissionMatcher.covers(
    granted = "organization/org_123:manage",
    required = "organization/org_123/project/proj_456:read",
)   // true: manage covers read, and the organization path covers the project inside it
```

**What you get:**

- **From `permits`**: `true` here. The `ADMIN` role above is held at the organization, the chain
  reaches inside it, and `document:approve` is in that role's set.
- **From `covers`**: `true` when the granted path covers the required path and the granted action
  covers the required action. `manage` on the organization covers `read` on a project inside it, as
  described in [Standard actions](#standard-actions) and
  [Hierarchy inheritance](#hierarchy-inheritance).
- **In both cases**: the decision comes off a map in memory and a string comparison, so a check does
  no I/O, needs no coroutine, and finishes on the calling thread from state the process already
  holds.

## Core concepts

### Scoped roles

A role name says what the subject is. A [`Scope`](#core-types-reference) says where the subject is
that thing. The two together are one scoped role, which Azure RBAC and GCP IAM call a role
assignment. A role definition carries actions alone, a scoped role adds the scope, and a `Principal`
holds those scoped roles for one subject. That is the same split those two products use.

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
`Scope` it is held at. Whatever issued the claim picks its shape, under
[RFC 7643 §4.1.2](https://datatracker.ietf.org/doc/html/rfc7643#section-4.1.2), which defines `roles`
and specifies no vocabulary or syntax for its values. These two shapes are the ones this library
documents, with the raw entry on the left and what a service reads it as on the right. An entry
naming no scope is held at the [platform scope](#the-platform-scope):

```
ADMIN@organization:org_123     RoleName("ADMIN") at Scope("organization", "org_123")
OWNER                          RoleName("OWNER") at Scope.PLATFORM
```

`Scope.parseOrNull` reads the scope half of such an entry. Splitting the entry at `@` is the
service's own step, as the snippet below does.

**A role entry arrives from outside the process, even when it arrives signed.** A signature names
which issuer sent a value, not that the value is well formed. So `parseOrNull` answers `null` for a
value that is not `type:id`:

```kotlin
Scope.parseOrNull("organization")    // null, no separator
Scope.parseOrNull(":org_123")        // null, blank type
Scope.parseOrNull("organization:")   // null, blank id
Scope.parseOrNull("")                // null
```

Call it from `mapNotNull` in your own per-request step that builds the principal, and it skips a
malformed entry and keeps the rest. The subject holds the roles that parsed, so a check needing a
skipped role answers `false` in the ordinary way. Log the entry that was skipped.

```kotlin
val roles: Map<Scope, Set<RoleName>> = rolesClaim
    .mapNotNull { entry ->
        val name = entry.substringBefore('@')
        val scope = if ('@' in entry) Scope.parseOrNull(entry.substringAfter('@')) else Scope.PLATFORM

        if (name.isBlank() || scope == null) null   // skips a malformed entry
        else scope to RoleName(name)
    }
    .groupBy({ it.first }, { it.second })
    .mapValues { (_, names) -> names.toSet() }

val principal = Principal(
    subjectId = subjectId,
    roles = roles,
    scope = scopeClaim,             // the scope claim, as a List<String>
)
```

#### The role catalogue

`RoleCatalog` has one method, and a service implements it:

```kotlin
fun actions(role: RoleName): Set<String>
```

The strings in the set are actions, and `Authorizer` compares each one to the requested action whole.
The action `"*"` is the exception, and it grants every action. A catalogue holds actions and
`PermissionMatcher` reads permission strings, so each way keeps its own vocabulary.

| What the catalogue answers for a name | What a subject holding that role may do |
|---|---|
| `setOf("report:read", "project:read")` | exactly those two actions |
| `setOf("*")` | every action |
| the empty set | nothing |

**Answer the empty set for an unknown name.** `Authorizer` asks the catalogue about the names a
principal holds at the scopes being checked, and those names arrived from outside the process, so it
is asked about unknown, misspelled and withdrawn names too. The `orEmpty()` in the quick start
answers the empty set, and the empty set grants no action, which is what makes such a name safe.

By convention a catalogue action names a type and a verb, as `document:approve` does, and a
permission string's action is the bare verb instead. The action names the type and the scope chain
names the object, so one definition serves every organization. The bridge in
[Writing an evaluator](#writing-an-evaluator) builds a catalogue action in that spelling, so an
evaluator answering from both models depends on it.

**Role inheritance, where a senior role absorbs a junior one, belongs inside your catalogue.** The
set `actions` answers is flat and `Authorizer` reads it as it comes. So compute the transitive
closure once at startup and answer the union: `ADMIN` absorbing `APPROVER` means the `ADMIN` name
answers its own actions and `APPROVER`'s together. Role inheritance is hierarchical RBAC,
standardised in ANSI INCITS 359-2004, and it is a separate mechanism from the
[hierarchy inheritance](#hierarchy-inheritance) between resource paths.

#### The scope chain

`Authorizer.permits` takes the scope chain the target object sits in, outermost first. A role grants
the action when its catalogue set holds that action and the role is held at any link of the chain,
so an organization administrator reaches every project inside the organization through that one
role. Where the subject holds several roles, any one of them granting the action is enough.

| Roles held | Chain passed | Result |
|---|---|---|
| `ADMIN` at `organization:o1` | `[organization:o1]` | granted, held at the scope checked |
| `ADMIN` at `organization:o1` | `[organization:o1, project:p1]` | granted, an outer link grants at an inner one |
| `APPROVER` at `project:p1` | `[organization:o1, project:p1]` | granted, the chain reaches the scope held |
| `ADMIN` at `organization:o1` | `[project:p1]` | refused, the chain omits the scope held |
| `APPROVER` at `project:p2` | `[organization:o1, project:p1]` | refused, another instance of the same type |
| `OWNER` at [`Scope.PLATFORM`](#the-platform-scope) | `[organization:o1]` | granted, the platform scope is consulted on every call |

**You pass the chain, because it is the only hierarchy a scoped-role check carries.** So a request
can carry the object's id alone. The service loads the object, reads the containers off the stored
record, and passes those as the chain. See
[instance checks once the object is loaded](#instance-checks-once-the-object-is-loaded) for that code.

#### The platform scope

`Scope.PLATFORM` is `Scope("platform", "*")`, where the `*` is a literal id, and `Authorizer`
consults it on every call, whatever the chain holds. So a role held there grants everywhere,
including when the chain is empty.

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
much of the subject's authority that application was consented to use. `Principal.scope` holds the
claim as it arrived, which
[RFC 6749 §3.3](https://datatracker.ietf.org/doc/html/rfc6749#section-3.3) defines as the authority
delegated to the client application. It is a list of strings. The `Scope` type above is its own
type: a resource type with one instance of it.

`Authorizer` reads the claim when you construct it with `narrowByScope = true`, and it then applies
as a second condition alongside the roles. Effective authority becomes the intersection of what the
subject holds and what the application was consented to do. The default is `false`.

```kotlin
val authorizer = Authorizer(ApplicationRoles)                          // roles decide alone
val narrowing  = Authorizer(ApplicationRoles, narrowByScope = true)    // scope narrows them
```

**Which setting to use depends on what the `scope` claim carries.** The claim carries two unrelated
kinds of value. OpenID Connect identity scopes such as `openid profile email` grant access to
identity claims. API scopes name actions, as in `scope: "report:read document:approve"`. The list
reads the same either way, so the setting is what states which kind the claim holds:

- **Leave it off** where the `scope` claim carries identity scopes or nothing. This is the default,
  and it is the answer for a first-party client.
- **Turn it on** once the authorization server issues API scopes drawn from the same vocabulary as
  the `RoleCatalog`. From then on a check grants only what the subject's roles and the delegated set
  both allow.

A value in the claim matches an action by equality, so the claim has to carry the action itself and
it carries no wildcard. An issuer of API scopes lists every action a client may perform, and
`listOf("*")` in the claim matches the action `"*"` alone, where `setOf("*")` in a catalogue grants
every action. Take `permits(principal, "report:manage", chain)` where the subject's roles already
grant `report:manage`:

| What `Principal.scope` holds | `narrowByScope = false` | `narrowByScope = true` |
|---|---|---|
| `emptyList()` | granted | refused, the claim lists no action |
| `listOf("openid", "profile", "email")` | granted | refused, the claim lists no action |
| `listOf("report:manage", "report:read")` | granted | granted, the action is listed |
| `listOf("report:read")` | granted | refused, the action is outside the delegated set |
| `listOf("*")` | granted | refused, `"*"` matches the action `"*"` alone |

### Permission strings

#### Format

A permission string is `<resource-path>:<action>`.

```
organization/org_123:read                       one organization, one action
organization/org_123/project/proj_456:manage    one project, every action on it
report:create                                   the report type, so every report, one action
*:*                                             any path, any action
```

The last `:` separates the path from the action, so a colon anywhere inside a permission string
belongs to the resource path. `Permission.parse` reads that form, and it throws
`IllegalArgumentException` for a blank string, for one with no `:`, and for one whose last `:` sits at
either end. Where a string reached the process from outside, catch it.

`Permission` has no non-throwing reader, so that exception is how a malformed string arrives.
`anyCovers` and `findMatch`, the two [matcher](#matching-rules) calls that search a list of
permission strings the subject holds, parse those strings in list order and stop at the first one
that covers. So a malformed entry ahead of the match throws from the matcher call, and one behind it
is never read. Validate held strings where they enter the process. `Scope.parseOrNull` answers
`null` and the caller skips the entry, while `Permission.parse` throws, so each model needs its own
guard at the boundary.

A catalogue action, a permission string and a `Scope` all read alike, and the colon does a different
job in each. `report:read` in your catalogue is one action, and `Authorizer` compares it to the
requested action whole, so the colon there is convention. `report:read` as a permission string is
the resource path `report` and the action `read`, and `covers` compares the two halves separately.
`organization:org_123` as a `Scope` is a resource type and one instance id. `Scope.parseOrNull`
splits at the first colon and `Permission.parse` at the last, so `organization:a:b` is the id `a:b`
to one and the action `b` to the other. Each value is read by the call of the model it came from.

#### Standard actions

Only `manage` and `*` carry matching behaviour in code. Every other action name matches by exact
string, so a name of your own works like `create`, `read`, `list`, `update` and `delete`, which are
the names the library documents.

| Action | What it means | How it matches |
|---|---|---|
| `create` | create a new resource | by exact string |
| `read` | read a single resource | by exact string |
| `list` | list resources | by exact string |
| `update` | modify an existing resource | by exact string |
| `delete` | remove a resource | by exact string |
| `manage` | full control | covers every required action on a path it covers |
| `*` | any action | covers every required action on a path it covers |

**`manage` and `*` carry that behaviour in a permission string only.** A `RoleCatalog` set holds
actions compared whole, so `report:manage` in a catalogue grants the action `report:manage` and
refuses a `report:read` check, while `PermissionMatcher.covers("report:manage", "report:read")`
answers `true`. Step 1 of the [quick start](#quick-start) shows both answers side by side.

#### Matching rules

| Rule | Granted | Required | Result |
|------|---------|----------|--------|
| Exact match | `report:read` | `report:read` | covers |
| Wildcard action | `report:*` | `report:delete` | covers |
| Manage action | `report:manage` | `report:read` | covers |
| Wildcard instance | `organization/*:read` | `organization/org_123:read` | covers |
| Type level | `organization:read` | `organization/org_123:read` | covers |
| Superadmin | `*:*` | `document/doc_789:delete` | covers |
| Hierarchy | `organization/org_123:manage` | `organization/org_123/project/proj_456:read` | covers |
| Narrower action | `report:read` | `report:delete` | does not cover |
| Narrower path | `organization/org_123/project/proj_456:manage` | `organization/org_123:read` | does not cover |

**`PermissionMatcher` holds the matching calls**, and it takes either raw strings or parsed
`Permission` objects. `anyCovers` and `findMatch` search a list the subject holds:

```kotlin
val held = listOf("organization/org_123:manage", "report:read", "report:list")

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
organization/org_123:manage
  covers  organization/org_123/project/proj_456:read                              yes
  covers  organization/org_123/project/proj_456:manage                            yes
  covers  organization/org_123/project/proj_456/document/doc_789:approve          yes
```

Inheritance applies to every action, so `organization/org_123:read` covers
`organization/org_123/project/proj_456:read`. It runs downward, from the granted path toward the
paths under it.

### Resource paths

A resource path is the path half of a permission string. If you only call `PermissionMatcher`, feel
free to skip to [the evaluation chain](#the-evaluation-chain).

#### Segments

A `ResourcePath` is an ordered list of `ResourceSegment`s, each one a type with an optional instance
id, and a raw path writes them separated by `/`. A `ResourceSegment` pairs a type with an instance
id as a `Scope` does, and writes it `organization/org_123` where a `Scope` writes
`organization:org_123`. The two belong to different ways of carrying authority: a segment is part of
a resource path, where a `Scope` keys a role and sits in a scope chain.

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

A `*` instance id is written into the string. A type-level segment is what `parse` leaves for a type
token standing alone. `covers` reads the two the same way, so either spelling works in a stored
permission string.

A `*` in the type position covers any type.

#### Ancestors

`ancestors()` answers a `Sequence`, walking up the hierarchy and yielding one path per segment above
the leaf. It starts at the direct parent and ends at the path holding the root segment alone. A
single-segment path yields an empty sequence. Walk it to look for a grant recorded on a container
above the object.

```kotlin
val path = ResourcePath.parse("organization/org_123/project/proj_456/document/doc_789")

path.ancestors().toList()
// [organization/org_123/project/proj_456, organization/org_123]
```

`isAncestorOf` asks the same question between two paths you already hold. A path is never its own
ancestor:

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
| a `RoleCatalog` set, as `setOf("*")` | every action |
| an action inside a `RoleCatalog` set, as `project:*` | the action written `project:*`, compared whole |
| the `scope` claim, as `listOf("*")` | the action `"*"` alone |
| `Scope.PLATFORM`, which is `Scope("platform", "*")` | the id of that one scope, matched as it reads |

```kotlin
ResourcePath.parse("organization/*").covers(ResourcePath.parse("organization/org_123"))   // true
ResourceSegment("*", "proj_456").covers(ResourceSegment("project", "proj_456"))           // true
```

`covers` asks the same question at three levels. `PermissionMatcher` compares two permissions,
`ResourcePath.covers` compares two paths, and `ResourceSegment.covers` compares two segments.

## The evaluation chain

### What the chain is for

`Authorizer` and `PermissionMatcher` each answer from one source. Once your service decides from
several sources at once, you need an order between them and a rule for what beats what.
`AuthorizationEvaluator` and `AuthorizationChain` supply both. The library ships the interface and the
composition, and you write one evaluator per source of authority.

The chain in this section holds evaluators. The scope chain a `permits` call takes holds scopes.

Each evaluator names the source it answers from, as an `AuthZSource`, and that name travels on the
result:

| `AuthZSource` | Stands for | What the evaluator reads | Example |
|---|---|---|---|
| `IMPLICIT` | a baseline every authenticated subject holds | the subject's own identity | `user/self:read` |
| `RBAC` | role-based access control | the roles the subject holds | a `VIEWER` role granting `report:read` |
| `REBAC` | relationship-based access control | a relationship recorded between the subject and the object | the subject owns `organization/org_123` |
| `ABAC` | attribute-based access control | attributes of the subject, the object or the moment | a policy refusing a subject outside the EU on a resource tagged `gdpr` |
| `GRANT` | a grant issued on demand for one object | a grant record | a one-time approval of `document/doc_789:approve` |

These five names are the vocabulary an audit record reads back, and an evaluator of your own picks
whichever one describes where its answer came from. The library reads an instance id as opaque, so
`self` in `user/self:read` is a path a service writes from the subject's own id.

### The three decisions

An evaluator answers with a `PolicyDecision`, which `AuthZResult.decision` carries:

| Decision | What it means |
|---|---|
| `ALLOW` | this source grants access |
| `DENY` | this source refuses access, and the refusal stands over any `ALLOW` |
| `ABSTAIN` | this source has nothing to say, so the chain carries on |

`AuthZResult` has one factory per decision, and one property reads each decision back:

| Factory | What it fills | Reads back as |
|---|---|---|
| `AuthZResult.allowed(source, matched, grantId = null)` | `source`, `matched`, `grantId` | `allowed` |
| `AuthZResult.denied(reason, source = null, matched = null)` | `reason`, `source`, `matched` | `denied` |
| `AuthZResult.abstain()` | the decision alone | `abstained` |

`matched` holds what granted access or what triggered the refusal, as a permission string, a
catalogue action, a relationship or a policy name. `grantId` is a `UUID` and it is filled where
`source` is `GRANT`, so a grant-based allow names the record it came from. `reason` carries the text
an audit record of a refusal reads. `source`, `matched`, `grantId` and `reason` are each nullable,
so one log line records whatever grounds the deciding evaluator supplied, and the chain's own
default `DENY` carries a reason alone.

### Phases and precedence

`AuthorizationChain` holds three lists of evaluators, one per phase. The block below is the route a
check takes through them, and the table after it carries the rule each phase runs under:

```
phase        what ends the phase           what happens then
granting     the first ALLOW or DENY       an ALLOW -> constraint, a DENY returns
             every evaluator abstained     -> fallback
constraint   the first DENY                that DENY returns instead of the ALLOW
             no DENY                       the ALLOW returns
fallback     the first ALLOW or DENY       an ALLOW -> constraint, a DENY returns
             every evaluator abstained     the default DENY returns
```

| Phase | What its evaluators are for | The rule it runs under |
|---|---|---|
| Granting | sources that confer authority | the first `ALLOW` or `DENY` ends it, an `ALLOW` running the constraint phase next and a `DENY` returning on the spot |
| Constraint | cross-cutting policies that restrict | they run in order until one answers `DENY`, that `DENY` replaces the `ALLOW`, and the rest never run |
| Fallback | sources consulted when the granting phase abstained | the first `ALLOW` or `DENY` ends it, an `ALLOW` running the constraint phase for the first time and a `DENY` returning on the spot |
| Default | the granting and fallback phases both abstained throughout | `DENY`, naming the required permission |

**Two consequences follow:** the granting phase stops at the first `ALLOW` or `DENY`, so a granting
evaluator placed after it never runs. And a policy in the constraint phase can refuse an `ALLOW`
that another evaluator produced. That is what makes the constraint phase the place for a rule that
has to hold whatever else granted.

### Writing an evaluator

`AuthorizationEvaluator` asks for the source and one `evaluate`. `evaluate` is a `suspend` function,
so your evaluator can read storage or call a service without a blocking wrapper around it, while
`Authorizer.permits` and `PermissionMatcher.covers` stay plain calls on the calling thread.

This one answers from the permission strings the subject holds, which it reads off
`context.permissions`. Those strings record a relationship with one named object, so it names `REBAC`
as the source its answer came from:

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
| `userId` | the subject's identifier, as a `UUID`; pass `Principal.subjectId` |
| `permissions` | the permission strings the subject holds, as raw strings in the `<resource-path>:<action>` form, which is what `findMatch` searches |
| `requiredPermission` | what the check requires, already parsed as a `Permission` |
| `attributes` | contextual values typed `Map<String, Any?>`, keyed by a dotted name whose first part groups related values, such as `"user.region"` to `"EU"` or `"env.business_hours"` to `true` |
| `grantToken` | a grant token as it arrived, as a `String?`, for a fallback evaluator to look up |
| `properties` | extra pairs of strings the service puts there for evaluators of its own |

An `attributes` value arrives as `Any?`, so the evaluator reading one compares or casts it as its own
policy needs. A grant token is the string a request carries to name a grant record, and the
fallback-phase evaluator holding the `GRANT` source is what looks that record up.

Those six fields are the whole context. `Authorizer.permits` reads a `Principal` and a scope chain,
which live outside it, so an evaluator answering from roles takes both in its own constructor. A
catalogue action is `"${required.resourcePath.leaf.type}:${required.action}"`, since the leaf
segment of the required permission's path carries the type and the action carries the verb:

```kotlin
import group.phorus.authz.core.evaluation.Authorizer
import group.phorus.authz.core.model.Principal
import group.phorus.authz.core.model.Scope

class ScopedRoleEvaluator(                  // one instance per request, it holds a Principal
    private val authorizer: Authorizer,
    private val principal: Principal,
    private val scopeChain: List<Scope>,
) : AuthorizationEvaluator {

    override val source = AuthZSource.RBAC

    override suspend fun evaluate(context: EvaluationContext): AuthZResult {
        val required = context.requiredPermission
        val action = "${required.resourcePath.leaf.type}:${required.action}"
        val granted = authorizer.permits(principal, action, scopeChain)

        return if (granted) AuthZResult.allowed(source, action)
        else AuthZResult.abstain()
    }
}
```

**An evaluator that holds a `Principal` belongs to one request.** `AuthorizationChain` keeps the
evaluator instances it was given, so the chain holding one is built per request. See
[Composing a chain](#composing-a-chain) for that code. An evaluator that reads the context alone,
such as `HeldPermissionEvaluator` above, is built once and passed to every chain.

The constraint phase reads a `DENY` and carries on past any other answer, so a constraint-phase
evaluator answers `DENY` or `ABSTAIN`:

```kotlin
class BusinessHoursPolicy : AuthorizationEvaluator {   // built once

    override val source = AuthZSource.ABAC

    override suspend fun evaluate(context: EvaluationContext): AuthZResult =
        if (context.attributes["env.business_hours"] == true) AuthZResult.abstain()
        else AuthZResult.denied(reason = "Outside business hours", source = source)
}
```

**Signal an authorization outcome through the return value, never by throwing.** An exception out of
`evaluate` means infrastructure failed, such as a database that could not be reached or configuration
that would not load. Returning `DENY` is how you refuse.

An exception out of `evaluate` reaches the caller of `AuthorizationChain.evaluate` and ends the check
there, so handle it where the chain is called.

### Composing a chain

`AuthorizationChain.standard` takes one evaluator per source and fills the three phases. It puts
`rbac`, `implicit` and `rebac` in the granting phase, `abac` in the constraint phase and `grant` in
the fallback phase. Every parameter accepts `null` and a `null` is skipped, so a service with one
source passes one argument.

A chain holding a request-scoped evaluator is built per request, which is what the function below
does with `ScopedRoleEvaluator`. In the two chain snippets `heldPermissionEvaluator` and
`businessHoursPolicy` are instances of the two classes above, built once and held by the enclosing
class along with the `authorizer`, while `baselineEvaluator` and `oneTimeGrantEvaluator` stand for
evaluators of your own, one per source you decide from.

```kotlin
import group.phorus.authz.core.evaluation.AuthorizationChain

fun chainFor(principal: Principal, scopeChain: List<Scope>) =
    AuthorizationChain.standard(
        rbac = ScopedRoleEvaluator(authorizer, principal, scopeChain),
        implicit = baselineEvaluator,
        rebac = heldPermissionEvaluator,
        abac = businessHoursPolicy,
        grant = oneTimeGrantEvaluator,
    )
```

`AuthorizationChain.evaluate` is a `suspend` function, and it takes an `EvaluationContext`. `userId`
and `requiredPermission` are the two required arguments, `permissions`, `attributes` and `properties`
default to empty, and `grantToken` defaults to `null`:

```kotlin
import group.phorus.authz.core.model.EvaluationContext
import group.phorus.authz.core.model.Permission

val context = EvaluationContext(        // one per check
    userId = principal.subjectId,
    permissions = listOf("organization/org_123:manage", "report:read"),
    requiredPermission = Permission.parse("organization/org_123/project/proj_456:read"),
    attributes = mapOf("env.business_hours" to true),
)

val result = chainFor(principal, scopeChain).evaluate(context)

result.allowed   // whether to proceed
result.source    // which layer decided, for an audit record
result.matched   // what granted access, or what triggered the refusal
result.grantId   // the grant record a grant-based allow came from
result.reason    // why access was refused
```

For any other order, construct `AuthorizationChain` directly and fill the three phase lists in the
order you want.

```kotlin
fun chainFor(principal: Principal, scopeChain: List<Scope>) =
    AuthorizationChain(
        grantingEvaluators = listOf(
            ScopedRoleEvaluator(authorizer, principal, scopeChain),
            heldPermissionEvaluator,
        ),
        constraintEvaluators = listOf(businessHoursPolicy),
        fallbackEvaluators = listOf(oneTimeGrantEvaluator),
    )
```

Whether each evaluator is built once or per request is
[the lifetime rule above](#writing-an-evaluator).

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
| `EvaluationContext` | `model` | one check's inputs: the subject's identifier, held permissions, required permission, attributes, grant token and extra properties |
| `RoleCatalog` | `evaluation` | the application's role definitions, implemented by a service |
| `Authorizer` | `evaluation` | the scoped-role decision over a `Principal` and a scope chain |
| `PermissionMatcher` | `evaluation` | permission-string matching with wildcards and hierarchy |
| `AuthorizationEvaluator` | `evaluation` | one source of authority, implemented by a service |
| `AuthorizationChain` | `evaluation` | a chain of evaluators with granting, constraint and fallback phases |

## Enforcement patterns

### Checks before the object is loaded

Where a check runs before the object is loaded, the action is all it has to go on. The question it
can answer is whether the subject holds that action at any scope:

```kotlin
fun permitsAnywhere(principal: Principal, action: String): Boolean =
    authorizer.permits(principal, action, principal.roles.keys.toList())
```

Passing every scope the subject holds a role at makes the check pass when any one of those roles
grants the action, since `permits` tries each link of the chain on its own. Treat it as a
pre-filter. It answers whether the subject holds the action anywhere, and the instance check then
answers whether it holds it here, because that check has the object's scope chain.

### Instance checks once the object is loaded

Where a request carries only an id, the scope chain comes from the loaded object, and `NotFound`
below is the service's own exception type:

```kotlin
suspend fun approve(principal: Principal, id: UUID) {
    val document = documentRepository.findById(id)
        ?: throw NotFound("Document $id not found")

    val chain = listOf(
        Scope("organization", document.project.organization.id.toString()),
        Scope("project", document.project.id.toString()),
    )

    if (!authorizer.permits(principal, "document:approve", chain)) {
        throw NotFound("Document $id not found")
    }
}
```

**Where the service speaks HTTP, answer the refusal with 404 rather than 403.** The check runs once
the object is loaded. So a 403 here confirms that the id exists.

A rule that reads the object belongs in this position too, such as an approval having to come from
somebody other than the person who requested it. A constraint-phase evaluator carries the same rule
where the service puts the loaded object in `EvaluationContext.attributes`, whose values are typed
`Any?`.

## Security considerations

- **`Authorizer` grants only the actions a role's set lists.** It grants where the requested action
  appears in the set the catalogue answers, or where `"*"` does. So a set that omits an action makes
  `permits` answer `false` for it, while a catalogue answering `"*"` for an unknown name turns the
  same omission into open access.
- **Return 404 where a 403 would confirm an id.** An instance check runs once the object is loaded,
  so the status code carries information on its own.
- **Set `narrowByScope` from what the `scope` claim carries.** A value in the claim matches an
  action by equality, so turn it on only once the claim carries API scopes. Turned on over identity
  scopes it answers `false` for every action. Left off over API scopes it gives a third-party
  integration the subject's full authority where its consented share is what it should get.
- **Build a chain holding a `Principal` per request.** `AuthorizationChain` keeps the evaluator
  instances it was given, for the life of the chain. So a chain cached past the request that built it
  answers every later check from the first request's subject.
- **Skip a malformed role entry and keep the rest.** `Scope.parseOrNull` returns `null`, so calling
  it from `mapNotNull` leaves the subject holding the roles that parsed. A role entry arrives from
  outside the process, even when it arrives signed.
- **A catalogue edit reaches every holder of the role at once.** Changing which actions a role grants
  applies to everybody holding that role, because the catalogue answers for the name alone.
- **Removing a role from a subject takes effect when the principal is next built.** So whatever
  carries the roles bounds how long that removal takes to apply.
- **Put scoped roles in what a subject carries and permission strings in storage.** The permission
  strings a subject holds grow with the objects they enumerate, so their count has no fixed bound.

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
