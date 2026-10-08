# AuthZ Core

[![GitHub license](https://img.shields.io/badge/license-Apache%20License%202.0-blue.svg?style=flat)](https://www.apache.org/licenses/LICENSE-2.0)
[![Maven Central](https://img.shields.io/maven-central/v/group.phorus/authz-core)](https://mvnrepository.com/artifact/group.phorus/authz-core)
[![codecov](https://codecov.io/gh/phorus-group/authz-core/branch/main/graph/badge.svg)](https://codecov.io/gh/phorus-group/authz-core)

Shared types, permission parsing, and evaluation interfaces for the authz library family.
This is the foundation that all other authz libraries (`authz-rbac`, `authz-rebac`, `authz-abac`,
`authz-grants`) depend on. It provides the permission string model, resource hierarchy, wildcard
matching, and the composable evaluator chain that wires everything together.

### Notes

> The project runs a vulnerability analysis pipeline regularly,
> any found vulnerabilities will be fixed as soon as possible.

> The project dependencies are being regularly updated by [Renovate](https://github.com/phorus-group/renovate).

> The project has been thoroughly tested to ensure that it is safe to use in a production environment.
> Currently, there are more than 75 tests validating all the functionality.

## Table of contents

- [What is the authz library family?](#what-is-the-authz-library-family)
- [Features](#features)
- [Getting started](#getting-started)
  - [Installation](#installation)
  - [Quick start](#quick-start)
- [Permission strings](#permission-strings)
  - [Format](#format)
  - [Matching rules](#matching-rules)
  - [Hierarchy inheritance](#hierarchy-inheritance)
- [Resource paths](#resource-paths)
  - [Segments](#segments)
  - [Ancestors and hierarchy](#ancestors-and-hierarchy)
  - [Wildcards](#wildcards)
- [Evaluation chain](#evaluation-chain)
  - [How the chain works](#how-the-chain-works)
  - [Standard chain](#standard-chain)
  - [Building a custom chain](#building-a-custom-chain)
- [Core types reference](#core-types-reference)
- [Using libraries together](#using-libraries-together)
- [Building and contributing](#building-and-contributing)
- [Authors and acknowledgment](#authors-and-acknowledgment)

***

## What is the authz library family?

If you are already familiar with the authz architecture, feel free to skip to [Features](#features).

<details open>
<summary><b>The problem</b></summary>

Most applications need multiple authorization models working together: role-based (RBAC) for
"can this user type do this action?", relationship-based (ReBAC) for "does this user own this
resource?", attribute-based (ABAC) for cross-cutting constraints like "block production deploys
outside business hours", and JIT grants for temporary one-time access.

Building all of this in a single monolith creates tight coupling and makes each model hard to
test in isolation. The authz library family addresses this with a modular architecture: each
model lives in its own library, all sharing a common core.
</details>

<details open>
<summary><b>The architecture</b></summary>

```
authz-core (you are here)
  ↑
  ├── authz-rbac      Role → Permission resolution, implicit permissions
  ├── authz-rebac     Ownership, membership, hierarchy traversal
  ├── authz-abac      Attribute-based policies with Kotlin DSL
  └── authz-grants    JIT grant tokens with HMAC signing
```

Each library provides an `AuthorizationEvaluator`. Services compose them into a chain:

```
RBAC → Implicit → ReBAC (granting) → ABAC (constraint) → Grant (fallback) → Deny
```

`authz-core` provides the types, interfaces, and chain that make this composition work.
</details>

## Features

- **Permission string parser**: Parses `resource/instance:action` strings into structured objects
  with resource path, action, wildcards, and hierarchy support.
- **Resource path model**: Hierarchical resource paths (`organization/org_123/project/proj_456`)
  with segment-level matching, ancestor traversal, and wildcard support.
- **Permission matching engine**: Exact match, wildcard actions (`*`, `manage`), wildcard resources,
  and hierarchy inheritance (parent permissions cascade to children).
- **AuthorizationEvaluator interface**: Common contract for all evaluators (RBAC, ReBAC, ABAC, Grant).
- **AuthorizationChain**: Composes evaluators into granting, constraint, and fallback phases.
- **AuthZResult**: Decision (ALLOW/DENY/ABSTAIN) with source attribution, matched permission, and reason.

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

**1. Parse and match permissions**

```kotlin
import group.phorus.authz.core.model.Permission
import group.phorus.authz.core.evaluation.PermissionMatcher

// Exact match
PermissionMatcher.covers("bit:read", "bit:read") // true

// Wildcard action: manage covers any action
PermissionMatcher.covers("bit:manage", "bit:delete") // true

// Hierarchy inheritance: parent covers child
PermissionMatcher.covers(
    "organization/org_123:manage",
    "organization/org_123/project/proj_456:read",
) // true

// Superadmin: * covers everything
PermissionMatcher.covers("*:*", "anything/at_all:delete") // true

// Check user privileges
val privileges = listOf("bit:read", "organization/org_123:manage")
val required = Permission.parse("organization/org_123/project/proj_456:read")
PermissionMatcher.anyCovers(privileges, required) // true
```

**2. Build an evaluation chain**

```kotlin
import group.phorus.authz.core.evaluation.AuthorizationChain

// Compose evaluators from the authz library family
val chain = AuthorizationChain.standard(
    rbac = rbacEvaluator,       // from authz-rbac
    implicit = implicitEvaluator, // from authz-rbac
    rebac = rebacEvaluator,     // from authz-rebac
    abac = abacEvaluator,       // from authz-abac
    grant = grantEvaluator,     // from authz-grants
)

val result = chain.evaluate(context)
if (result.allowed) {
    println("Access granted via ${result.source}, matched: ${result.matched}")
} else {
    println("Access denied: ${result.reason}")
}
```

## Permission strings

### Format

Permission strings follow the format `<resource-path>:<action>`:

```
organization/org_123:read
organization/org_123/project/proj_456:manage
bit:create
*:*
```

The resource path and action are separated by the last `:` in the string. This means resource
types and instance IDs can contain colons, but actions cannot.

### Matching rules

| Rule | Granted | Required | Result |
|------|---------|----------|--------|
| Exact match | `bit:read` | `bit:read` | Covers |
| Wildcard action (`*`) | `bit:*` | `bit:delete` | Covers |
| Manage action | `bit:manage` | `bit:read` | Covers |
| Wildcard instance | `organization/*:read` | `organization/org_123:read` | Covers |
| Type-level | `organization:read` | `organization/org_123:read` | Covers |
| Superadmin | `*:*` | `anything:delete` | Covers |
| Hierarchy | `organization/org_123:manage` | `organization/org_123/project/proj_456:read` | Covers |
| No match | `bit:read` | `bit:delete` | Does not cover |

### Hierarchy inheritance

Parent permissions automatically cascade to children. If a user has `organization/org_123:manage`,
they can perform any action on any resource under that organization:

```
organization/org_123:manage
  └── covers: organization/org_123/project/proj_456:read       ✓
  └── covers: organization/org_123/project/proj_456:manage     ✓
  └── covers: organization/org_123/project/proj_456/installation/inst_789:approve  ✓
```

This is how GCP IAM and Azure RBAC work: permissions at a broader scope inherit down.

## Resource paths

### Segments

A resource path is a sequence of segments, each with a type and an optional instance ID:

```kotlin
val path = ResourcePath.parse("organization/org_123/project/proj_456")
path.segments[0] // ResourceSegment(type = "organization", instanceId = "org_123")
path.segments[1] // ResourceSegment(type = "project", instanceId = "proj_456")
path.root         // ResourceSegment("organization", "org_123")
path.leaf         // ResourceSegment("project", "proj_456")
path.depth        // 2
```

### Ancestors and hierarchy

Walk up the resource hierarchy:

```kotlin
val path = ResourcePath.parse("organization/org_123/project/proj_456/installation/inst_789")
val ancestors = path.ancestors().toList()
// [organization/org_123/project/proj_456, organization/org_123]
```

Check ancestor relationships:

```kotlin
val org = ResourcePath.parse("organization/org_123")
val proj = ResourcePath.parse("organization/org_123/project/proj_456")
org.isAncestorOf(proj) // true
proj.isAncestorOf(org) // false
```

### Wildcards

Use `*` as an instance ID to match any instance of a resource type:

```kotlin
val wildcard = ResourcePath.parse("organization/*")
val specific = ResourcePath.parse("organization/org_123")
wildcard.covers(specific) // true
```

## Evaluation chain

### How the chain works

The `AuthorizationChain` processes evaluators in three phases:

1. **Granting evaluators** (RBAC, Implicit, ReBAC): First ALLOW wins.
2. **Constraint evaluators** (ABAC): Run after a granting evaluator allows. Any DENY overrides the grant.
3. **Fallback evaluators** (Grant): Only checked if no granting evaluator allowed.
4. **Default deny**: If nothing grants access, the chain denies.

```
┌─────────────────────────────────────────────────────────┐
│  Phase 1: Granting                                      │
│  RBAC → Implicit → ReBAC                                │
│  First ALLOW wins → go to Phase 2                       │
│  Any DENY → stop, return DENY                           │
│  All ABSTAIN → skip to Phase 3                          │
├─────────────────────────────────────────────────────────┤
│  Phase 2: Constraints                                   │
│  ABAC policies                                          │
│  Any DENY → stop, return DENY (overrides the grant)     │
│  No denial → return the Phase 1 ALLOW                   │
├─────────────────────────────────────────────────────────┤
│  Phase 3: Fallback                                      │
│  Grant evaluator                                        │
│  ALLOW → check constraints again → return result        │
│  No match → Phase 4                                     │
├─────────────────────────────────────────────────────────┤
│  Phase 4: Default deny                                  │
│  "No evaluator granted access"                          │
└─────────────────────────────────────────────────────────┘
```

### Standard chain

The `standard()` factory creates a chain with the recommended evaluation order:

```kotlin
val chain = AuthorizationChain.standard(
    rbac = rbacEvaluator,
    implicit = implicitEvaluator,
    rebac = rebacEvaluator,
    abac = abacEvaluator,
    grant = grantEvaluator,
)
```

Pass `null` for any evaluator to skip that layer. A service using only RBAC:

```kotlin
val chain = AuthorizationChain.standard(rbac = rbacEvaluator)
```

### Building a custom chain

For non-standard evaluation orders:

```kotlin
val chain = AuthorizationChain(
    grantingEvaluators = listOf(myCustomEvaluator, rbacEvaluator),
    constraintEvaluators = listOf(abacEvaluator, rateLimitEvaluator),
    fallbackEvaluators = listOf(grantEvaluator),
)
```

## Core types reference

| Type | Package | Description |
|------|---------|-------------|
| `Permission` | `model` | Parsed permission string with resource path and action |
| `ResourcePath` | `model` | Ordered sequence of resource segments |
| `ResourceSegment` | `model` | Single segment: type + optional instance ID |
| `AuthZResult` | `model` | Evaluation result: decision, source, matched, reason |
| `PolicyDecision` | `model` | Enum: `ALLOW`, `DENY`, `ABSTAIN` |
| `AuthZSource` | `model` | Enum: `IMPLICIT`, `RBAC`, `REBAC`, `ABAC`, `GRANT` |
| `EvaluationContext` | `model` | Input to evaluators: userId, privileges, required permission, attributes |
| `AuthorizationEvaluator` | `evaluation` | Interface all evaluators implement |
| `PermissionMatcher` | `evaluation` | Utility for matching permissions with wildcards and hierarchy |
| `AuthorizationChain` | `evaluation` | Composes evaluators into a sequential chain |

## Using libraries together

`authz-core` defines the interfaces and chain. The other libraries in the family provide the
evaluators. Pick the combination that fits your service.

**RBAC + ReBAC: roles for general access, relationships for per-resource ownership**

```kotlin
val chain = AuthorizationChain.standard(
    rbac = RbacEvaluator(roleDefinitions),
    implicit = ImplicitEvaluator(implicitPermissions),
    rebac = RebacEvaluator(resolvers = listOf(orgResolver, projectResolver)),
)

// RBAC resolves "Developers can create bits."
// ReBAC resolves "this user owns this specific organization."
val result = chain.evaluate(context)
```

**RBAC + ABAC: roles grant access, attribute policies enforce cross-cutting constraints**

```kotlin
val chain = AuthorizationChain.standard(
    rbac = RbacEvaluator(roleDefinitions),
    implicit = ImplicitEvaluator(implicitPermissions),
    abac = AbacEvaluator(
        policies = listOf(productionHoursPolicy, gdprRegionPolicy),
    ),
)

// RBAC grants the Deployer role permission to execute installations.
// ABAC blocks production deployments outside business hours, even for Deployers.
val result = chain.evaluate(context)
```

**Full chain: RBAC + ReBAC + ABAC + JIT Grants**

```kotlin
val chain = AuthorizationChain.standard(
    rbac = RbacEvaluator(roleDefinitions),
    implicit = ImplicitEvaluator(implicitPermissions),
    rebac = RebacEvaluator(resolvers = listOf(orgResolver, projectResolver)),
    abac = AbacEvaluator(policies = allPolicies),
    grant = GrantEvaluator(tokenFactory, grantRepository),
)

// RBAC and ReBAC handle everyday access.
// ABAC enforces environment and attribute constraints.
// Grants allow temporary JIT elevation for one-off or emergency cases.
val result = chain.evaluate(context)
```

See [`authz-rbac`](../authz-rbac), [`authz-rebac`](../authz-rebac), [`authz-abac`](../authz-abac),
and [`authz-grants`](../authz-grants) for each library's setup and configuration.

## Building and contributing

See [Contributing Guidelines](CONTRIBUTING.md).

## Authors and acknowledgment

Developed and maintained by the [Phorus Group](https://phorus.group) team.
