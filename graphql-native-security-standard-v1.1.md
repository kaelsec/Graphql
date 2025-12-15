# Vendor-Agnostic Native GraphQL Security Standard (v1.1)

## 0. Preface

### 0.1 Purpose

This document defines a **vendor-agnostic native security standard for GraphQL**.

Instead of treating GraphQL as “just another HTTP API,” it explicitly addresses the **architectural differences from REST** and the **graph traversal-specific threats** that arise from those differences. The goal is to provide a practical baseline for secure GraphQL design and operation in real-world systems.

### 0.2 Conventions (RFC 2119)

The key words **MUST**, **SHOULD**, and **MAY** in this document are to be interpreted as described in [RFC 2119].

- **MUST**: An absolute requirement of the specification for maintaining security.
- **SHOULD**: A strong recommendation; there may exist valid reasons to deviate, but the full implications MUST be understood.
- **MAY**: An optional behavior that is permitted but not required.

### 0.3 Scope

This standard is scoped to **GraphQL-specific concerns**, including:

- Schema design and exposure
- Resolver logic and authorization
- Query parsing, validation, and execution
- Federation gateway trust and subgraph isolation

It is intentionally **vendor-agnostic** and applies to any GraphQL implementation that adheres to the GraphQL Specification (e.g., October 2021 spec and later), including monolith and federated (supergraph/subgraph) architectures.

### 0.4 Non-Goals

The following topics are explicitly out of scope:

- **Infrastructure Hardening**: OS, container, network (L3/L4), and host-level security
- **Identity Provider Flows**: Detailed OAuth 2.0 / OIDC handshake sequences
- **Database Security**: Encryption at rest, database-specific access control, or key management

This document focuses on how GraphQL **consumes and propagates** identity and data, not how those identities or data stores are managed at a lower layer.

---

# 1. Threat Model & Risk Prioritization

This chapter defines the **architectural essence** of GraphQL, the **attack surface** exposed to attackers, and the **structural weaknesses** that are inherent to the model.

It is not a list of individual CVEs, but a description of root causes that manifest as many different vulnerabilities.

---

## 1.1 GraphQL Architectural Essence

While REST is fundamentally **resource-centric**, GraphQL is **relation-centric and traversal-centric**.

This shift changes the security paradigm:

### Inversion of Control

In REST, the server determines the shape and size of responses per endpoint.  
In GraphQL, the **client (including attackers)** dictates:

- Which fields to select
- How deep the traversal goes
- How many related nodes are fetched

This **inversion of control** over execution cost is a core source of risk.

### Single Entry Point

GraphQL typically exposes a **single endpoint** (e.g., `/graphql`) for:

- Queries
- Mutations
- Subscriptions (often via WebSocket)

Traditional security controls that heavily rely on HTTP method + URL patterns (WAF, API gateways) lose visibility and granularity when everything is multiplexed through a single path.

### Schema-First Contract

The GraphQL schema is:

- An executable contract
- A precise graph of types, fields, and relationships
- A form of **attack map** when exposed to untrusted clients

It is not merely documentation; it is a machine-readable **map of what exists and how it connects**.

---

## 1.2 Protected Assets

GraphQL security is not only about protecting raw data. The following assets MUST be treated as sensitive:

- **Schema & Meta-Information**  
  The domain model, relationships between types, and internal fields reveal business logic, authorization decisions, and internal naming conventions.

- **Supergraph (Federation)**  
  In a federated architecture, the supergraph is a virtual data layer composed of multiple subgraphs. Its structure reveals internal microservice boundaries and joins.

- **Execution Context**  
  The per-request context flowing through resolver chains (e.g., user identity, roles, tenant ID, feature flags) MUST be protected from tampering and leakage.

- **Underlying Data Sources**  
  Databases, microservices, and third-party APIs contacted by resolvers. GraphQL sits as a broker in front of them and can amplify or concentrate risk.

---

## 1.3 Attack Surface Model

An attacker interacts with a GraphQL system across several distinct surfaces. This standard groups them into **five layers**:

1. **Discovery Surface (Introspection)**  
   - If introspection is enabled in production, an attacker can discover the full schema, often equivalent to a database schema from a modeling perspective.
   - Error messages such as “Did you mean…” can leak field names even when introspection is disabled.

2. **Interaction Surface (Query Parsing & Validation)**  
   - The GraphQL engine parses and validates queries before execution.
   - Large-scale aliasing, circular fragments, and abusive use of directives can consume CPU and memory even before resolvers run.

3. **Execution Surface (Resolver Logic)**  
   - Resolver arguments are primary injection channels (SQL/NoSQL, command injection, etc.).
   - Poorly designed resolvers can trigger N+1 database queries, massively increasing execution cost and enabling DoS.

4. **Transport & Batching Surface**  
   - GraphQL query payloads are typically JSON over HTTP(S).
   - Query batching (an array of operations in a single HTTP request) can allow hundreds or thousands of login attempts or expensive queries in one network round-trip, bypassing naive rate limiting.

5. **Federation Surface (Inter-Service Communication)**  
   - **Gateway**: The front door for authentication, routing, and policy enforcement.
   - **Subgraphs**: Services hidden behind the gateway that often assume the gateway has enforced all security checks.
   - If attackers can bypass the gateway and talk directly to subgraphs, the entire federated system may be exposed.

---

## 1.4 Structural Weakness Model (Core Insights)

Rather than listing individual vulnerability classes, this standard defines four **structural weaknesses** that explain why many GraphQL vulnerabilities exist.

### SW-1. Recursive Resource Exhaustion

**Concept**  
GraphQL enables deep and wide traversal across relations. In theory, traversal depth and breadth are unbounded.

**Structural Flaw**  
The server has limited ability to know the **actual execution cost** of a query before parsing and analyzing it. Attackers can craft small textual queries whose **execution complexity grows exponentially** in depth or breadth, leading to DoS.

---

### SW-2. Authorization Context Fragmentation

**Concept**  
In REST, authorization is typically enforced at the endpoint level.  
In GraphQL, authorization SHOULD be enforced at the **field (resolver) level**.

**Structural Flaw**  
Authorization logic often becomes fragmented across:

- Schema directives,
- Resolver implementations,
- Data-access layers.

As a result, a user may be authorized to access a parent object but not the sensitive fields of a nested object. If nested-field checks are omitted, this leads to **vertical access control flaws**.

---

### SW-3. Transport Amplification

**Concept**  
GraphQL encourages network efficiency via batched operations and rich field selection.

**Structural Flaw**  
When:

- Many operations are packed into one HTTP request (batching), or
- A single query requests many heavy fields,

the **true cost** of a request is hidden from any control that only counts HTTP requests per second.

This can:

- Mask brute force attacks,
- Hide scraping,
- Evade per-request rate limiting.

---

### SW-4. Distributed Trust Fragility (Federation-Specific)

**Concept**  
Federated GraphQL architectures commonly assume:

> “The gateway has already authenticated and authorized everything.”

Subgraphs implicitly trust the gateway and the headers it forwards.

**Structural Flaw — “Soft Trust Boundary”**  

- **Impersonation**:  
  If subgraphs accept headers (e.g., `x-user-id`, `x-tenant-id`) without cryptographic validation, an attacker who bypasses the gateway can forge these headers and gain arbitrary privileges.

- **Plan Exposure**:  
  If query plans generated by the gateway are exposed (logs, debug tools, etc.), they can reveal internal microservice topology and optimization strategies.

---

## 1.5 Risk Prioritization Matrix

When engineering teams have limited resources, they MUST prioritize based on impact and exploitability.

| Priority | Risk Category                    | Rationale                                                                 |
|----------|----------------------------------|---------------------------------------------------------------------------|
| **P1**   | Recursive Resource Exhaustion    | Can immediately disrupt availability with cheap attacks                  |
| **P1**   | Authorization Fragmentation      | Primary driver of data leakage in GraphQL; endpoint-based defenses fail  |
| **P1**   | Federation Trust Breakage        | In MSA/federation, gateway bypass compromises all internal services      |
| **P2**   | Injection via Arguments          | Traditional class, but harder to detect due to nesting                   |
| **P2**   | Schema Exposure                  | Accelerates attack path; not always directly exploitable alone           |
| **P3**   | Batching / Transport Abuse       | Can be partially mitigated with WAF rules and advanced rate limiting     |

---

# 2. Core Principles

This chapter defines **five overarching security principles** for GraphQL.  
They are not optional “nice-to-haves”; they are direct responses to the structural weaknesses defined in Section 1.

---

## 2.1 Least Exposure Principle

**Objective:** Minimize information advantage granted to attackers.

GraphQL’s **self-documenting** nature increases developer velocity but also increases information disclosure risk.

**Mandates**

- Introspection in production environments **MUST** be disabled for untrusted clients.
- Detailed error responses (stack traces, field suggestions, internal type names) **MUST** be masked or removed before being returned to clients.

---

## 2.2 Schema Integrity Principle

**Objective:** Make the schema act as a **first line of defense**.

The schema is the boundary between:

- Business logic, and
- External clients.

There MUST be no “hidden” inputs or outputs that bypass the type system.

**Mandates**

- Every field **MUST** have an explicit type and associated validation or constraints (e.g., scalar restrictions).
- Internal-only fields and public fields **SHOULD** be separated (e.g., separate schemas, schemas per audience, or field visibility controls).

---

## 2.3 Execution Safety Principle

**Objective:** Defend against **Recursive Resource Exhaustion** (SW-1).

Since servers cannot trivially know execution cost, they MUST enforce **static pre-execution checks**.

**Mandates**

- Every request **MUST** pass through a static analysis step before execution.
- If the computed query depth or complexity score exceeds configured thresholds, the request **MUST** be rejected before resolver execution begins.

---

## 2.4 Authorization Coherence Principle

**Objective:** Address **Authorization Context Fragmentation** (SW-2).

Authorization MUST be coherent and consistently applied across:

- Nodes,
- Fields,
- Relations.

**Mandates**

- Authentication may be implemented at middleware or context level, but **authorization MUST be enforced at resolver level** (or via schema directives tightly bound to resolvers).
- Parent-level authorization **MUST NOT** implicitly imply authorization for all nested fields. The default posture SHOULD be “deny by default” for sensitive nested fields.

---

## 2.5 Federation Trust Principle

**Objective:** Address **Distributed Trust Fragility** (SW-4).

Trust between gateway and subgraphs MUST be explicit and verifiable.

**Mandates**

- Subgraphs **MUST** be reachable only via the gateway at both network and identity layers (e.g., private subnets, firewall rules).
- Context propagated from the gateway (identity, tenant, roles) **MUST** be cryptographically protected (e.g., signed or encrypted tokens) to prevent tampering.

---

# 3. Schema Security Baseline

This chapter defines minimal security controls for the **schema** layer.

---

## 3.1 Schema Exposure Control

**Requirements**

- Introspection queries **MUST** be disabled for untrusted clients in production environments.
- Deprecated or experimental fields **SHOULD** be hidden from auto-completion and introspection results to reduce accidental exposure.

---

## 3.2 Type-Safe Design Rules

**Input/Output Separation**

- Input types and output types **MUST** be clearly separated.  
  Database entities MUST NOT be directly exposed as both input and output types, to prevent mass assignment and over-posting vulnerabilities.

**Custom Scalars**

- Instead of using generic `String` or `Int` everywhere, developers **SHOULD** use semantic custom scalars (e.g., `Email`, `UUID`, `PositiveInt`) to enforce validation at the schema level.

---

# 4. Query Security Baseline

This chapter defines runtime protections for **incoming requests**.

---

## 4.1 Query Cost Model

Naive “requests per second” rate limiting is insufficient for GraphQL.

**Requirements**

- Servers **MUST** perform static analysis (or equivalent) of incoming requests to compute:
  - Maximum query depth
  - Overall complexity / cost score
- If depth or complexity thresholds are exceeded, the server **MUST** reject the query (e.g., with HTTP 400 and a generic error).

- Recursive or cyclic fragments **SHOULD** be disallowed at the parsing or validation stage.

---

## 4.2 Query Sanitization & Validation

**Persisted Queries**

- Where practical, servers **SHOULD** adopt a persisted queries (allow-list) model:
  - Only queries whose hashes have been pre-registered on the server are executed.
  - Clients send a query ID or hash instead of arbitrary query text.

This is one of the strongest controls for preventing arbitrary, attacker-crafted queries from being executed in production.

---

## 4.3 Transport & Session Security

GraphQL endpoints are not exempt from classic web vulnerabilities.

**CSRF Protection**

- If cookie-based authentication is used, GraphQL endpoints **MUST** implement anti-CSRF protections:
  - CSRF tokens, and/or
  - `SameSite=Strict` cookies.
- Relying solely on browser CORS behavior is **NOT** sufficient.

**Content-Type Enforcement**

- Servers **MUST** enforce `Content-Type: application/json` for GraphQL requests.
- Requests with `text/plain`, `application/x-www-form-urlencoded`, or other unexpected content types **MUST** be rejected to reduce CSRF vectors.

---

## 4.4 Realtime / Subscription Security

WebSocket-based subscriptions introduce **long-lived, stateful connections**.

**Stateful Authorization**

- Servers **MUST** validate authorization not only at the initial connection (e.g., `connection_init`) but also at event push time, especially when tokens or permissions can change or be revoked.

**Resource Management**

- Servers **SHOULD** limit:
  - The number of concurrent subscriptions per client, and
  - The maximum connection lifetime (idle timeouts, absolute timeouts),
  to reduce risk of socket exhaustion attacks.

---

# 5. Resolver Security Baseline

Resolvers are where **business logic, data access, and authorization** converge.

---

## 5.1 Authorization Binding & Multi-Tenancy

**Resolver-Level Authorization**

- Authorization logic **MUST** be enforced in resolvers (or tightly bound directives), not only in the gateway or middleware.

**Multi-Tenant Isolation**

- In multi-tenant SaaS environments:
  - A tenant identifier (e.g., `tenant_id`) extracted from the **trusted context** **MUST** be injected into all downstream data access queries as a filter (e.g., SQL `WHERE tenant_id = :tenant_id`).
  - Tenant identifiers provided directly by clients via arguments **MUST NOT** be trusted as the primary isolation mechanism.

---

## 5.2 Argument Injection Prevention

GraphQL arguments are equivalent to query parameters in REST; they are fully attacker-controlled.

**Requirements**

- All resolver arguments **MUST** be treated as untrusted input.
- For database queries:
  - Parameter binding or prepared statements **MUST** be used.
  - Building queries via raw string concatenation **MUST NOT** be used for untrusted data.
- Similar principles apply to NoSQL queries and command invocation (e.g., no direct concatenation into shell commands).

---

## 5.3 Resolver Chaining Risk

N+1 query patterns can be exploited to magnify load through deeply nested queries.

**Requirements**

- Implementations **SHOULD** use batching mechanisms (e.g., DataLoader pattern) to:
  - Reduce redundant queries, and
  - Keep database load predictable and bounded.

---

# 6. Federation Security Baseline

Federated GraphQL architectures (supergraph/subgraph) require additional controls.

---

## 6.1 Gateway Trust Model

**Requirements**

- Communication between the gateway and subgraphs **MUST** use:
  - Mutual TLS (mTLS), and/or
  - Signed headers or tokens that allow subgraphs to cryptographically verify that the caller is the legitimate gateway.
- Subgraphs **MUST NOT** assume that any request reaching them is trusted purely based on network location or hostname.

---

## 6.2 Subgraph Isolation

**Requirements**

- Subgraph endpoints **MUST** NOT be directly accessible from the public internet.
- Network-level isolation (e.g., private subnets, firewall ACLs, service meshes) **MUST** be used so that:
  - Only the gateway (or explicitly trusted infrastructure components) can call subgraphs.

---

# 7. Operational Security Baseline

This chapter covers **runtime operations, monitoring, and observability** for GraphQL systems.

---

## 7.1 Rate Limiting & Throttling

**Requirements**

- Rate limiting and throttling policies **MUST** be based on:
  - Query complexity score, and/or
  - Resource usage (e.g., object count fetched),
  rather than request count alone.

Per-user, per-token, or per-IP thresholds SHOULD be adapted to GraphQL’s execution cost, not just its transport-level signature.

---

## 7.2 Logging & Traceability

**Requirements**

- Structured logs **SHOULD** include:
  - Operation name
  - Query hash or identifier
  - Key variables (appropriately sanitized)
- Personally Identifiable Information (PII) **SHOULD** be masked or omitted from logs by default.

These practices improve incident response, anomaly detection, and forensics while reducing privacy risk.

---

# 8. Security Testing Guide

This chapter provides **attack patterns** and **test payloads** that SHOULD be integrated into CI/CD pipelines as part of DAST (Dynamic Application Security Testing).

---

## 8.1 Attack Pattern Matrix

| Priority | Attack Vector                | ID      | Test Goal                                                                 |
|----------|------------------------------|---------|---------------------------------------------------------------------------|
| P1       | Recursive DoS               | TEST-01 | Verify deep nesting is rejected and resource usage is controlled         |
| P1       | Tenant Isolation Failure    | TEST-02 | Verify tenant isolation enforced via context, not client-provided IDs    |
| P2       | Argument Injection          | TEST-03 | Verify DB query and command injection attempts are blocked or sanitized  |
| P2       | Batching Abuse              | TEST-04 | Verify rate limiting on batched operations                               |
| P2       | Introspection Leak          | TEST-05 | Verify introspection and suggestion-based schema enumeration are blocked |

---

## 8.2 Reproducible Test Scenarios (PoC)

### TEST-01: Recursive Resource Exhaustion (DoS)

**Goal**  
Confirm that deeply nested or cyclic queries are rejected by depth and complexity limits.

```graphql
query MaliciousRecursion {
  author {
    posts {            # Depth 2
      comments {       # Depth 3
        author {       # Depth 4 (cycle start)
          posts {      # Depth 5
            comments {
              author {
                posts { ... }  # Repeat until server rejects
              }
            }
          }
        }
      }
    }
  }
}
```

**Expected Result**

- The server rejects the request before execution.
- An error such as **“Max query depth exceeded”** or **“Query complexity too high”** is returned.
- No excessive CPU, memory, or database resource consumption occurs.

---

### TEST-02: Tenant Isolation / IDOR (SaaS-Specific)

**Goal**  
Verify that resolvers enforce tenant isolation using server-side context rather than client-supplied arguments.

**Assumption**  
The attacker is authenticated as a user from **Tenant A** but attempts to access data belonging to **Tenant B**.

```graphql
query TenantBreach {
  # 1. Direct object access
  organization(id: "uuid-of-tenant-b") {
    name
    users {
      email
    }
  }

  # 2. Global node interface abuse
  node(id: "base64-encoded-id-of-resource-in-tenant-b") {
    ... on Invoice {
      amount
      currency
    }
  }
}
```

**Expected Result**

- Access is denied.
- The response returns `null` and/or a **“Not Authorized”** error.
- No cross-tenant data is disclosed.

---

### TEST-03: Argument Injection (SQLi / NoSQLi)

**Goal**  
Verify that GraphQL arguments are sanitized and not directly concatenated into backend queries.

**SQL Injection Probe**

```graphql
query InjectionProbe {
  users(search: "admin' OR '1'='1") {
    id
    username
    passwordHash   # Must never be exposed
  }
}
```

**NoSQL / Command Injection via JSON Scalar**

```graphql
mutation CommandInjection {
  updateUserProfile(
    id: 1,
    preferences: {
      theme: { "$ne": null },
      debug: "; cat /etc/passwd"
    }
  ) {
    success
  }
}
```

**Expected Result**

- No raw database syntax errors are exposed.
- No command execution or query manipulation occurs.
- The application returns a generic, sanitized error message without backend leakage.

---

### TEST-04: Batching & Amplification Abuse

**Goal**  
Verify that query batching is either disabled or constrained by cost and rate-limiting policies.

**Example HTTP POST Body (Array of Operations)**

```json
[
  { "query": "query { login(u: \"admin\", p: \"1234\") { token } }" },
  { "query": "query { login(u: \"admin\", p: \"1111\") { token } }" },
  { "query": "query { login(u: \"admin\", p: \"2222\") { token } }" }
  // ... repeated up to 100 or more attempts ...
]
```

**Expected Result**

- The server rejects the batch as **too large** or **too costly**, or
- Enforces rate limiting and lockout policies by evaluating the batch **as a single risk unit**.

---

### TEST-05: Introspection & Field Discovery

**Goal**  
Ensure that schema discovery remains controlled even when introspection is disabled.

**Introspection Attempt**

```graphql
query {
  __schema {
    types {
      name
    }
  }
}
```

**Field Fuzzing / Suggestion Leak Test**

```graphql
query {
  user {
    passwrod   # Intentional typo
  }
}
```

**Expected Result**

- The `__schema` query is rejected or disabled in non-public environments.
- Error messages MUST NOT reveal valid field names.
- Responses such as **“Did you mean ‘password’?”** MUST NOT be returned.

## 9. Mapping to Existing Standards

This section explains how this document aligns with existing security standards,
and why a **native, GraphQL-specific security standard** is required.

This standard is designed to be **complementary**, not competitive, with
well-established application and API security frameworks.

---

### 9.1 Why a Native GraphQL Security Standard Is Required

Most existing application security standards (e.g., **OWASP ASVS**) are
fundamentally **REST-centric**. They implicitly assume:

- Multiple endpoints as security boundaries
- HTTP methods (`GET`, `POST`, `PUT`, `DELETE`) as authorization and rate-limiting units
- Predictable request-to-resource mapping

GraphQL violates these assumptions by design.

GraphQL introduces:

- A **single endpoint** serving all operations
- **Client-defined execution paths**
- **Field-level execution** with resolver chaining
- Execution cost that is **decoupled from request size**

When REST-oriented controls are applied directly to GraphQL,
the following blind spots emerge:

- No stable mapping between URL and privilege
- Ineffective per-endpoint rate limiting
- Over-reliance on network perimeter defenses
- Authorization checks fragmented across resolvers

This document defines a **native GraphQL security context**
that treats **query structure, execution cost, and resolver behavior**
as first-class security boundaries.

---

### 9.2 Alignment with OWASP ASVS

This standard aligns with OWASP ASVS at the **control objective level**,
while redefining the **enforcement layer** to match GraphQL execution semantics.

| OWASP ASVS Domain | Relevant ASVS Control | Alignment in This Standard |
|------------------|----------------------|----------------------------|
| Validation | V5: Input Validation | Section 3.2 (Type-Safe Design), Section 4.2 (Query Validation) |
| Access Control | V4: Access Control | Section 5.1 (Resolver-Level Authorization Binding) |
| Error Handling | V7: Error Handling | Section 2.1 (Least Exposure Principle) |
| API Security | V13: API and Web Services | Section 4 (Query Security Baseline), Section 6 (Federation Security) |

Key distinction:

- **ASVS** assumes validation at endpoint boundaries
- **This standard** enforces validation at **query parsing and resolver execution boundaries**

---

### 9.3 Alignment with OWASP GraphQL Cheat Sheet

The OWASP GraphQL Cheat Sheet provides a **tactical list of known attack vectors**,
including:

- Query depth abuse
- Batching attacks
- Injection via arguments
- Introspection abuse

This document builds upon that work by:

- Normalizing these issues into **structural weakness categories**
- Introducing **risk prioritization**
- Extending coverage to **federated architectures**
- Defining **design-time principles**, not only runtime mitigations

In short:

> The Cheat Sheet answers *“what can go wrong”*  
> This standard answers *“why it goes wrong and how to design against it”*

---

### 9.4 Alignment with Apollo, Hasura, and Vendor Documentation

Vendor documentation provides **implementation-specific guidance**.
This standard abstracts those practices into **vendor-agnostic requirements**.

| Vendor Concept | Vendor Term | Normalized Term in This Standard |
|---------------|-------------|----------------------------------|
| Apollo | Query Cost / Operation Limits | Query Complexity Model (Section 4.1) |
| Apollo | Federation Gateway Trust | Federation Trust Principle (Section 2.5) |
| Hasura | Allow-listed Operations | Persisted Queries (Section 4.2) |
| Hasura | Role-based Permissions | Resolver-Level Authorization Binding (Section 5.1) |

This abstraction allows the standard to remain stable even as
individual vendor implementations evolve.

---

### 9.5 Alignment with NIST SP 800-204B (Microservices Security)

NIST SP 800-204B defines security principles for microservices architectures,
including:

- Gateway-centric trust
- Service-to-service authentication
- Network isolation

These principles map directly to **GraphQL Federation environments**:

| NIST Concept | Mapping in This Standard |
|-------------|--------------------------|
| Service Identity | Signed Execution Context (Section 6.1) |
| Zero Trust Between Services | Subgraph Isolation (Section 6.2) |
| Gateway Enforcement | Federation Trust Model (Section 6) |

This confirms that GraphQL Federation introduces **microservice-grade trust risks**
and must be governed accordingly.

---

## 10. Appendix

### 10.1 Terminology & Normalization

This table maps commonly used vendor or community terminology
to the standardized terms used in this document.

| Standardized Term | Vendor / Community Term | Definition |
|------------------|-------------------------|------------|
| Recursive Resource Exhaustion | DoS, Query Depth Attack | Resource exhaustion via deep or broad graph traversal |
| Authorization Context Fragmentation | Broken Access Control, IDOR | Loss of authorization guarantees due to fragmented checks |
| Query Complexity | Cost Analysis | Estimated execution cost of a query |
| Persisted Queries | Allow-list, Saved Operations | Execution model allowing only pre-registered operations |
| Supergraph / Subgraph | Federated Graph, Microservices | Unified graph and its constituent services |

---

### 10.2 Complexity Calculation Example (Informative)

This document does not mandate a specific complexity formula.

An implementation **MAY** consider:

- Per-field base cost weights
- Multipliers based on arguments (e.g., `first`, `limit`)
- Recursive traversal penalties
- Global and per-user maximum thresholds

The goal is **predictability**, not precision.

---

### 10.3 Federation Trust Architecture (Informative)

A reference architecture SHOULD illustrate:

- Gateway ↔ Subgraph communication protected by mTLS
- Signed or encrypted identity context propagation
- Explicit network isolation preventing direct subgraph access

---

**End of Document**  
*Vendor-Agnostic Native GraphQL Security Standard (v1.1)*

