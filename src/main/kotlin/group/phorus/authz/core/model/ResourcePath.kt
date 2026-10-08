package group.phorus.authz.core.model

/**
 * A single segment in a resource path, consisting of a resource [type] and an optional [instanceId].
 *
 * Type-level segments represent a class of resources (e.g., `organization`), while instance-level
 * segments identify a specific resource (e.g., `organization/org_123`).
 *
 * ### Examples
 *
 * ```kotlin
 * ResourceSegment("organization", null)           // type-level: "organization"
 * ResourceSegment("organization", "org_123")      // instance-level: "organization/org_123"
 * ResourceSegment("project", "*")                 // wildcard instance
 * ```
 *
 * @property type The resource type name, e.g. `"organization"`, `"project"`, `"report"`.
 * @property instanceId The specific resource identifier, or `null` for type-level,
 *   or `"*"` for wildcard matching.
 */
data class ResourceSegment(
    val type: String,
    val instanceId: String? = null,
) {
    /** `true` when this segment targets all instances of the type. */
    val isWildcard: Boolean get() = instanceId == WILDCARD

    /** `true` when this segment targets a specific instance. */
    val isInstance: Boolean get() = instanceId != null && !isWildcard

    /** `true` when this segment targets the type level (no instance). */
    val isTypeLevel: Boolean get() = instanceId == null

    override fun toString(): String = if (instanceId != null) "$type/$instanceId" else type

    /**
     * Checks whether this segment covers [other].
     *
     * A segment covers another when:
     * - This segment's [type] is `*` (wildcard type), or both types are equal, **and**
     * - This segment's [instanceId] is `*` (wildcard), or both instance IDs are equal,
     *   or this segment is type-level (type-level covers any instance of the same type).
     */
    fun covers(other: ResourceSegment): Boolean {
        // Type matching: wildcard type covers any type, otherwise exact match
        if (type != WILDCARD && type != other.type) return false
        // Instance matching
        if (isWildcard) return true           // * covers any instance
        if (isTypeLevel) return true          // type-level covers any instance of this type
        return instanceId == other.instanceId // exact instance match
    }

    companion object {
        /** The wildcard token that matches any instance of a resource type. */
        const val WILDCARD = "*"
    }
}

/**
 * An ordered sequence of [ResourceSegment]s that represents a path through the resource hierarchy.
 *
 * Resource paths follow a hierarchical structure where parent resources contain child resources.
 * Permissions granted at a parent level cascade to all children (inspired by GCP IAM and Azure RBAC).
 *
 * ### Path format
 *
 * ```
 * type[/instance[/type[/instance]...]]
 * ```
 *
 * ### Examples
 *
 * ```kotlin
 * ResourcePath.parse("organization")                                    // type-level
 * ResourcePath.parse("organization/org_123")                            // instance
 * ResourcePath.parse("organization/org_123/project/proj_456")           // nested
 * // Wildcards: ResourcePath with segments [("organization","*"), ("project","*")]
 * ```
 *
 * @property segments The ordered list of resource segments, from root to leaf.
 */
data class ResourcePath(
    val segments: List<ResourceSegment>,
) {
    init {
        require(segments.isNotEmpty()) { "Resource path must have at least one segment" }
    }

    /** The leaf (most specific) segment in this path. */
    val leaf: ResourceSegment get() = segments.last()

    /** The root (most general) segment in this path. */
    val root: ResourceSegment get() = segments.first()

    /** Number of segments in this path. */
    val depth: Int get() = segments.size

    /**
     * Walks up the resource hierarchy, yielding every ancestor path from the direct parent
     * to the root.
     *
     * For `organization/org_123/project/proj_456/document/doc_789`, this yields:
     * 1. `organization/org_123/project/proj_456`
     * 2. `organization/org_123`
     *
     * Useful for checking whether a parent-level permission cascades down to this resource.
     */
    fun ancestors(): Sequence<ResourcePath> = sequence {
        var current = segments
        while (current.size > 1) {
            current = current.dropLast(1)
            yield(ResourcePath(current))
        }
    }

    /**
     * Returns `true` if this path is an ancestor of [other].
     *
     * A path is an ancestor when [other] starts with the same segments as this path
     * and has additional segments beyond it.
     *
     * ```kotlin
     * val org = ResourcePath.parse("organization/org_123")
     * val proj = ResourcePath.parse("organization/org_123/project/proj_456")
     * org.isAncestorOf(proj)  // true
     * proj.isAncestorOf(org)  // false
     * ```
     */
    fun isAncestorOf(other: ResourcePath): Boolean {
        if (segments.size >= other.segments.size) return false
        return segments.zip(other.segments).all { (mine, theirs) -> mine.covers(theirs) }
    }

    /**
     * Checks whether this resource path covers [other].
     *
     * A path covers another when:
     * - It has the same number of segments and each segment [covers][ResourceSegment.covers] the
     *   corresponding segment in [other], **or**
     * - It is an ancestor of [other] (parent permissions cascade to children).
     */
    fun covers(other: ResourcePath): Boolean {
        // Exact match (with wildcards)
        if (segments.size == other.segments.size) {
            return segments.zip(other.segments).all { (mine, theirs) -> mine.covers(theirs) }
        }
        // Ancestor match (parent covers child)
        return isAncestorOf(other)
    }

    override fun toString(): String = segments.joinToString("/")

    companion object {
        /**
         * Parses a raw resource path string into a [ResourcePath].
         *
         * The path format alternates between type and instance tokens separated by `/`:
         * ```
         * type[/instance[/type[/instance]...]]
         * ```
         *
         * Tokens at even indices (0, 2, 4, ...) are resource types.
         * Tokens at odd indices (1, 3, 5, ...) are instance IDs.
         *
         * @param raw The raw path string, e.g. `"organization/org_123/project/proj_456"`.
         * @throws IllegalArgumentException if [raw] is blank.
         */
        fun parse(raw: String): ResourcePath {
            require(raw.isNotBlank()) { "Resource path must not be blank" }

            val tokens = raw.split("/")
            val segments = mutableListOf<ResourceSegment>()
            var i = 0

            while (i < tokens.size) {
                val type = tokens[i]
                val instanceId = tokens.getOrNull(i + 1)

                if (instanceId != null) {
                    segments.add(ResourceSegment(type, instanceId))
                    i += 2
                } else {
                    segments.add(ResourceSegment(type))
                    i++
                }
            }

            return ResourcePath(segments)
        }
    }
}
