# Review Routing Contract

Read this file before deciding whether a review is required or selecting a reviewer.

## Resolution layers

Resolve review policy from three layers:

1. This canonical contract.
2. The reviewed repository or worktree root's `.autoreview/profile.yaml`, unless the work-item contract explicitly binds a nested scope as described below.
3. The current work-item contract in the claimed task, ISA/spec, or explicit review prompt.

Explicit principal direction wins when it names the override. Otherwise combine all applicable layers using the strictest review classification, gate, threat boundary, evidence requirement, and specialist budget. A work-item contract may specialize a project profile but cannot silently downgrade it. Repository instructions and the current work-item contract may tighten this canonical contract. Do not weaken security, release, live-effect, or destructive-operation boundaries without explicit authority.

Project profiles define stable project-specific risk classes and gates. They must not contain current task IDs, commits, branch names, or temporary exceptions. Current facts belong in the work-item contract.

Anchor profile discovery to the repository or worktree whose diff or artifact is being reviewed, never to an unrelated launcher directory. Use its root profile by default. If the review contract explicitly binds a nested target path, search from that path upward and stop at the reviewed repository root. Never cross that root or inherit a profile from another checkout.

The review helper is intentionally stateless transport, not policy authority. Its acceptance of an engine or model proves only CLI capability. The calling agent must resolve and obey this contract before invocation. If Fable eligibility or prior use cannot be established from the current durable work-item context, do not invoke Fable. Do not add a review ledger, hook, daemon, or hidden state store to enforce this routing policy.

## Context fingerprint

Before round one, bind:

- repository root and work-item identity;
- protected claim and review mode;
- project-profile path and content digest;
- base revision and reviewed diff or artifact digest;
- relevant product, protocol, release, and authority pins;
- review-family ID and prior specialist-review usage.

Re-resolve routing when any bound value changes materially. A repository switch, new work item, changed protected claim, changed profile, changed authority pin, or materially changed diff starts a new classification. Prior review remains historical evidence; it is not automatically applicable to the new context.

Fixes made inside the same protected claim and review family do not create a new family or reset specialist budgets.

## Review classes

### Deterministic-only

Skip semantic model review when every relevant correctness claim is mechanically decidable and no project profile promotes the change. Examples:

- formatting and generated inventories;
- exact SHA, digest, pin, count, stable-ID, dependency, or mapping reconciliation;
- mechanical ISA progress/evidence reconciliation after the underlying implementation and claim were already reviewed;
- byte-for-byte copy or projection checks.

Run the named deterministic validators. Escalate to semantic review if the change alters criterion meaning, authority, dependencies, threat model, release claims, or effect boundaries.

### Standard semantic

Use Codex `gpt-5.6-sol` with `medium` reasoning for material implementation, behavior, contract, or architecture changes that are not load-bearing under the project profile or work-item contract.

Invoke the helper explicitly when reproducibility matters:

```bash
autoreview --engine codex --model gpt-5.6-sol --thinking medium ...
```

### Load-bearing

Load-bearing work includes any class named by the project profile or work-item contract, especially protocol semantics, security or identity boundaries, persistence and recovery, authority joins, migrations, release/product claims, and live or irreversible effects.

Run deterministic gates and the standard Codex review first. Then use at most one completed Fable pass for the explicitly named load-bearing passages:

```bash
autoreview --engine claude --model claude-fable-5 --thinking max ...
```

The prompt must identify the protected claim, exact passages, admitted threats, and stopping condition. Do not send the whole repository merely because one passage is load-bearing.

If another cross-vendor recheck is justified after the Fable pass, use Claude Opus 4.8 with `high` effort, not Fable:

```bash
autoreview --engine claude --model claude-opus-4-8 --thinking high ...
```

## Fable budget

- Budget: one completed, valid Fable pass per review family and protected claim.
- Interrupted, tool-failed, or structurally invalid runs do not consume the budget.
- Corrective edits and follow-up rounds do not reset it.
- A new repository, work item, or protected claim requires fresh classification; it does not silently inherit or evade the old budget.
- Only explicit principal authorization may grant another Fable pass for the same family and claim.
- A direct CLI invocation, panel selection, or new session never proves eligibility and never resets the budget.

## Loop and stopping rule

Accept and correct in-model P0/P1 findings and P2 findings that concretely leave the protected claim bypassable. Fix the root-cause class, add a deterministic falsifier where practical, run focused proof, then recheck with Codex.

Disposition out-of-model findings, duplicate spellings, residual P3, and claim-external P2. P3 remains actionable when it touches protocol semantics, security, persistence/recovery, authority/join, release, or live/destructive effects.

Do not chase clean wording, broaden the threat model, or add a general subsystem to satisfy a reviewer. A clean pass is snapshot-bounded review evidence, not product completion, conformance, release, or live-behavior proof.

## Evidence

Persist review output when it supports a product claim, release, protocol/security authority, migration, or externally consumed qualification. Bind the record to the context fingerprint, engine/model/effort, prompt or contract digest, and reviewed snapshot.

Ordinary implementation reviews may remain structured command output unless the work-item contract or project profile names a durable evidence destination. Never use a review record as a second task ledger.
