---
name: govern-shared-skills
description: "Govern the complete skill lifecycle across Codex, Claude Code, OpenClaw, and other harnesses: classify global, router, native, generated, or project-local ownership; bind source, pins, budgets, projections, collisions, verification, and rollback. USE WHEN adding, installing, exposing, migrating, updating, or auditing any skill in any harness. NOT FOR authoring the canonical skill body without its owning skill-creation workflow."
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

## Default Visibility

Use `global` for a reusable capability that should route in more than one project. Global does not mean copied everywhere: it means governed once and projected only into declared harnesses.

Use `project-local` only when the skill depends on one repository's files, authority, runtime, private semantics, or contributor workflow and has no demonstrated reusable boundary. A project-local skill lives in that repository's supported loader directory and remains outside the global registry until deliberately promoted.

Use a global router instead of global leaves when a suite would create excessive startup context, collisions, or a vendor-owned internal catalog. Use native/package ownership when the harness or package manager owns installation and updates.

Promotion from project-local to global requires a stable cross-project contract, a canonical owner, harness targets, an update path, and the same admission gates as a new global skill.

## Mandatory Admission Questions

Answer these before creating or changing any harness-visible entry:

1. What is the one canonical body, owner, and source repository or package?
2. Is the capability reusable and therefore global, or genuinely bound to one repository?
3. Which harnesses and platforms must discover it, and through which exact loader roots?
4. What immutable commit, release, or package version controls external updates?
5. Which names, aliases, capabilities, and effects overlap existing skills?
6. Is this a leaf, router, native runtime, generated suite, adapter, or project-local skill?
7. Does the routing description state the capability, `USE WHEN`, and—where overlap, hidden leaves, or material effects exist—`NOT FOR`?
8. What startup-context budget applies to the leaf or suite, and why is the chosen projection worth it?
9. Is projection direct, symlinked, generated, wrapped, or package-managed? Who may rewrite it?
10. What exact preview, idempotence check, fresh-session routing probe, rollback, and upgrade command prove the lifecycle?

Record the answers as an admission receipt in the governing registry, as an equivalent receipt inside the declared native/package owner envelope, or as a project-local receipt in repository doctrine. Missing answers block installation.

## Hard Rule: No Direct Loader Installs

Never install or modify a global skill directly inside `~/.codex/skills`, `~/.claude/skills`, `~/.agents/skills`, or another harness loader—not even when its canonical body exists elsewhere. Every loader projection must be produced by its declared registry sync, native/package manager, or generator. Loader entries without exactly one recognized owner envelope and lifecycle tool are drift and must fail the live audit.

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
2. If the canonical skill body changes, invoke its owning skill-creation or validation workflow before editing it.
3. Audit every candidate path: file type, resolved target, Git owner, clean state, version or commit, and content hash where useful.
4. Identify the canonical source. Stop if two writable locations both appear authoritative.
5. Classify the skill and declare:
   - source and owner
   - immutable pin
   - visibility and platforms
   - adapter and projection mode
   - loader targets
   - conflict policy
   - routing description class and startup-context budget
   - verification and rollback
6. Check normalized names and capability overlap across every target harness before mutation.
7. Preview the exact mutation. Preserve unrelated files and harness-managed state.
8. Install through the owning sync tool or vendor installer. Never hand-edit a generated projection.
9. Run the same sync in check/dry-run mode again; require zero planned actions.
10. Run the aggregate live audit; require every visible entry to resolve to exactly one owner envelope.
11. Verify links or generated hashes, executable helpers, hook targets, and platform-independent paths.
12. Start a fresh session in each affected harness and verify the expected routing descriptions are model-visible.

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
- required `USE WHEN` or applicable `NOT FOR` routing metadata is absent
- a leaf or suite exceeds its declared startup-context budget without an explicit exception and fresh-session proof
- a global loader entry has no recognized admission, native/package owner, or generated owner envelope
- runtime projection contains untracked edits treated as source

## Examples

### Reusable leaf: global direct projection

A source-blind CLI behavior validator is useful across repositories. Keep one canonical body in its owner repository, pin that repository, admit explicit Codex and Claude targets, preview the links, apply through sync, then prove zero-action convergence and fresh-session routing.

### Vendor suite: global router

A vendor ships fifty related leaves. Keep the suite vendor-owned, expose one global router whose `USE WHEN` covers common intents and whose `NOT FOR` separates neighboring owners, declare the suite budget, and resolve hidden leaves only after the router fires.

### Repository workflow: project-local

A release skill depends on one repository's private ISA, scripts, branch rules, and CI. Store it in that repository's supported skill directory, document the project-local owner, and do not add a global loader entry. Promote it only after extracting a stable reusable contract.

## Gotchas

- A directory in a loader proves presence, not model visibility or correct routing.
- A shared `~/.agents/skills` root is not automatically consumed by every harness.
- A symlinked `SKILL.md` can escape an apparently local directory; audit the resolved file and Git owner.
- A package-managed skill may be global without a registry admission, but its explicit native/package owner envelope must contain the equivalent admission receipt and lifecycle tool.
- A router that omits niche `USE WHEN` triggers makes its hidden leaves effectively name-only.
- `sync --apply` changes projections; `upgrade` changes canonical source pins. Do not conflate them.
- A successful apply is incomplete until a second check has zero actions and a fresh session sees the intended metadata.

## Output

Report:

- canonical owner and pin
- classification and rationale
- targets and projection modes
- collisions or drift found
- mutations performed
- description and suite-budget disposition
- idempotence and fresh-session routing evidence
- remaining approval or migration boundary

Do not claim canonical installation from directory presence alone.
