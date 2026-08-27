---
name: govern-agent-stack
description: "Govern evaluation, adoption, installation, update, propagation, and retirement of agent-stack capabilities across machines and harnesses. USE WHEN adding or changing a CLI, skill, plugin, hook, MCP server, connector, service, harness, automation, shared capability, or checking whether an update reached every harness. Report `update not complete` until owner, pin, projections, fresh behavior, and idempotence converge. NOT FOR authoring a canonical skill body without its owner workflow."
---

# Govern Agent Stack

Adopt capabilities from the operator's goals and constraints, not from another person's setup.
Keep evidence, policy, implementation, and runtime state separate.

## Grounding

1. Read repository instructions and current runtime evidence.
2. Load the first applicable operator policy when present:
   - an explicitly supplied policy;
   - project-bound policy declared by repository instructions;
   - `~/projects/agent-skill-registry/config/agent-stack-policy.json`;
   Treat an explicit policy as the task-scoped override; do not silently merge conflicting policies.
3. Treat external setups and dated research as evidence, never local authority.
4. Use `govern-shared-skills` as the subordinate workflow for skill ownership, adapters,
   projections, loader collisions, and routing visibility.

## Admission workflow

1. State the capability and the concrete problem it solves.
2. Classify it as `skill`, `cli`, `plugin`, `hook`, `mcp`, `connector`, `archive`, `service`,
   `harness`, or `remote-runtime`.
3. Inventory existing owners and overlapping capabilities before installing anything.
4. Bind one canonical owner, immutable upstream pin, update mechanism, platforms, and runtime
   dependencies.
5. Inspect for foreign identity, accounts, hosts, credentials, topology, model, subscription,
   authority, and destructive-effect assumptions.
6. Choose one disposition:
   - `adopt`: usable unchanged;
   - `adapt`: retain upstream provenance and add the smallest local boundary;
   - `reference`: searchable evidence only;
   - `defer`: useful, but no demonstrated present need or dependency readiness;
   - `reject`: collision, unsafe boundary, wrong topology, or inferior existing owner.
7. Choose minimum visibility: project-local, explicit-only, router, global leaf, or native runtime.
8. Bind permissions, secrets, network, spend, external-write, persistence, and background-process
   boundaries before activation.
9. Define deterministic install/update, fresh-runtime proof, failure probe, rollback, and review
   cadence.
10. Preview mutations. Apply only through the owning installer or registry. Verify idempotence and
    real routing/runtime behavior.

## Completion Invariant

An update is complete only when the canonical owner and immutable pin match, every declared
projection converges, fresh behavior passes in each declared harness, and a second read-only check
reports zero actions. Run the governing registry's scoped consolidation check; do not repair loader
directories by hand. If any gate fails, report the exact verdict `update not complete`, identify the
failing owner or projection, and keep the operational work item open.

## Decision rules

- Prefer an existing native or canonical owner over a duplicate.
- Prefer CLIs for stateless, composable operations; use MCP or plugins for stateful, interactive,
  pushed, or lifecycle-bound behavior.
- Prefer one router over a globally exposed vendor catalog.
- Keep raw archives and session history out of always-on context; expose bounded search instead.
- Separate communication plane, agent loop, task ledger, product authority, evidence, and runtime
  state.
- Do not inherit another operator's identities, machine fleet, credentials, model pins, landing
  authority, polling frequency, or risk tolerance.
- Do not call a capability installed until dependencies exist, permissions are granted, a fresh
  runtime discovers it, and its defining behavior is observed.
- A scheduled or manual consolidation batch may detect drift, but it never gains authority to apply
  changes; correction still runs through the canonical owner and its previewed lifecycle tool.

## Output

Report:

- problem and disposition;
- canonical owner and pin;
- overlap and identity assumptions;
- placement and visibility;
- permissions and effects;
- install/update/rollback path;
- verification performed and remaining gates.

Persist durable decisions in the owning registry or policy. Keep dated research in an evidence
dossier; never copy it into this skill body.
