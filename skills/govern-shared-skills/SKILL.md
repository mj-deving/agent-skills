---
name: govern-shared-skills
description: "Govern creation, adoption, installation, migration, update, and audit of skills shared across Codex, Claude Code, OpenClaw, and other agent harnesses. Use when deciding canonical ownership, pins, adapters, routers, loader targets, symlink versus generated-copy strategy, collision policy, or when diagnosing cross-harness skill drift."
---

# Govern Shared Skills

Keep one canonical owner for each logical skill and make every harness-visible copy a reproducible projection. Treat loader directories as runtime surfaces, never implicit sources of truth.

## Invariants

- Assign exactly one canonical owner and source to each logical skill.
- Pin external sources by immutable commit, release, or package version.
- Keep shared doctrine in the canonical body. Keep adapters limited to harness translation.
- Make projections disposable and reproducible from source, registry, and adapter.
- Preserve harness-native, plugin-managed, and package-managed ownership. Do not fork them merely to centralize files.
- Keep project-specific skills local unless they are deliberately admitted as reusable.
- Use logical roots or platform-aware expansion. Never encode one workstation's home path as portable configuration.
- Expose only useful global routing metadata. Avoid normalized-name collisions and redundant leaf catalogs.
- Verify routing from a fresh harness session; filesystem presence alone does not prove discoverability.

## Classify Before Installing

Choose one class from live evidence:

- `shared-source`: harness-neutral skill owned by a source repository; normally project to loaders with symlinks.
- `adapter`: small harness-specific translation owned separately; point it at live canonical doctrine.
- `generated-suite`: vendor source with provider-specific generation; pin the source and regenerate projections rather than symlinking unlike outputs.
- `native-runtime`: system, plugin, or runtime-managed skill; register ownership and boundaries without copying it.
- `project-local`: skill whose doctrine depends on one repository; keep it under that repository's loader surface.
- `router`: compact globally visible routing layer over a larger suite; prove that its startup metadata exposes every required use-when condition.

Do not classify by folder name. Inspect the owning repository, installer, update mechanism, generated differences, and loader contract.

## Workflow

1. Read repository instructions and locate the existing registry, installers, sync tools, and loader roots.
2. Audit every candidate path: file type, resolved target, Git owner, clean state, version or commit, and content hash where useful.
3. Identify the canonical source. Stop if two writable locations both appear authoritative.
4. Classify the skill and declare:
   - source and owner
   - immutable pin
   - visibility and platforms
   - adapter and projection mode
   - loader targets
   - conflict policy
   - verification and rollback
5. Check normalized names across every target harness before mutation.
6. Preview the exact mutation. Preserve unrelated files and harness-managed state.
7. Install through the owning sync tool or vendor installer. Never hand-edit a generated projection.
8. Run the same sync in check/dry-run mode again; require zero planned actions.
9. Verify links or generated hashes, executable helpers, hook targets, and platform-independent paths.
10. Start a fresh session in each affected harness and verify the expected routing descriptions are model-visible.

## Decision Rules

- Prefer a symlink when source and target consume the same format on the same machine.
- Prefer a generated copy when the harness requires rewritten metadata, paths, hooks, commands, or assets.
- Prefer a thin adapter when canonical doctrine is usable but runtime semantics differ.
- Prefer a router when exposing every leaf would create collisions or excessive startup context. The router must enumerate sufficient trigger metadata for all hidden leaves.
- Prefer native ownership when a plugin manager, system package, or standalone runtime controls updates.
- Never move a vendor suite into a shared-skills repository merely to obtain one directory tree.

## Drift Gates

Fail the audit when any of these is true:

- missing owner, source, pin, target, conflict policy, verification, or rollback
- mutable external source without an exact admitted pin
- broken or escaping symlink
- generated target without reproducible generation provenance
- adapter duplicates material canonical doctrine
- two admissions normalize to the same name in one harness
- hook or helper points to a target absent on a fresh installation
- sync check proposes changes immediately after sync
- required use-when metadata is absent from a fresh harness catalog
- runtime projection contains untracked edits treated as source

## Output

Report:

- canonical owner and pin
- classification and rationale
- targets and projection modes
- collisions or drift found
- mutations performed
- idempotence and fresh-session routing evidence
- remaining approval or migration boundary

Do not claim canonical installation from directory presence alone.
