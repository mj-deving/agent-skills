---
name: github-public-writing
description: "Draft, review, edit, or publish public GitHub issues, pull-request descriptions, review findings, comments, contribution notes, and release discussions so a reader using only the public record can correctly interpret and act on the contribution. Adapts context and evidence depth to the artifact and risk while preventing private-context dependencies and status overclaims. Use for any outward GitHub prose or before a public gh write."
---

# GitHub Public Writing

## Standard

Write for a technically capable reader arriving cold. Cold means the reader has only the public record: the repository, the thread, and what you link. The body must not depend on private chat, internal task or session IDs, local paths, internal nicknames, or unstated history. Reference public thread context by link or short anchor instead of replaying it; repeat only what the reader needs to act on this contribution.

Prefer the shortest version that lets the reader interpret the claim and take the intended next action. Do not turn provenance into a project history.

## Workflow

Scale steps 2 through 5 to what the contribution raises; every public write keeps steps 1 and 6 through 8.

1. Read the live issue, PR, diff, reviews, CI state, and relevant source. Identify the exact public surface and current state. Check the repository's CONTRIBUTING guide, issue/PR templates, security policy, and tracker for duplicates. Repository conventions override this skill's artifact shapes; add new evidence to an existing thread instead of opening a duplicate.
2. State what the named project or component is in one sentence when an outsider would not know it.
3. Separate facts by epistemic status:
   - implemented now;
   - observed and reproduced;
   - proposed or recommended;
   - intentionally unsupported or not yet implemented.
4. Give provenance proportional to the claim: commit or version, file/type/field, test or verifier result, and primary-source link when useful.
5. State the impact and exact requested decision or next action. The intended reader must know what happens next and how completion will be recognized.
6. Run the gates below. Show the exact draft and wait unless the user already authorized this specific public write.
7. Immediately before writing, re-read the live target. If it changed materially, revise and re-gate.
8. Write through a temporary body file, inspect it, publish through a mechanism that transmits the exact inspected body (body file via platform CLI or API), then read the created or edited body back from GitHub and return its link.

## Cold-reader gate

Before approval or publication, verify that a reader with only the public record can answer each question the contribution actually raises:

- What is this project or component?
- What exists today, and what is only proposed?
- What exact behavior, defect, or decision is under discussion?
- What evidence supports the claim?
- What must change, where, and under which accept/reject condition?
- What remains compatible, legacy-only, deferred, or out of scope?

If any relevant answer depends on private or unstated context, revise. Skip questions the contribution does not raise; a typo fix needs only the correct claim.

## Specificity gate

When implementation or a decision is the requested outcome, be concrete enough to act on without a follow-up question. For code and protocol recommendations that usually means:

- the target artifact and exact field, type, path, or protocol phase;
- the source of each value;
- required equality, validation, transition, and failure behavior;
- legacy read behavior and new-write behavior;
- tests or vectors that prove the rule.

For non-code contributions such as governance, docs, design, or process, name the affected artifact or process, exact proposed change, decision owner when relevant, and how adoption will be judged.

Do not leave an unresolved choice when giving a recommendation intended for implementation. Pick the recommended rule and state the tradeoff. Open design questions are acceptable only when the purpose of the comment is explicitly to request that decision.

Example:

Weak: `Mirror upstream's x402Version number rather than introducing protocolVersion string.`

Actionable: `In the new kind: "x402" payment transaction reference used with x402:protocol, use x402Version: number. Copy it from the validated PaymentRequired.x402Version and require equality with the agreement-pinned selection. Continue reading protocolVersion: string only for legacy x402:default evidence; new sessions must not emit it.`

## Artifact conventions

- Issue: current behavior, evidence, impact, requested ruling or acceptance criteria, to the depth the issue needs.
- PR description: what changes and why; add scope, implementation, risk, verification, and reviewer guidance when they materially help review. Keep small changes small, and update the description when the PR changes during review.
- Review finding: location, triggering behavior, impact, required correction, and whether it blocks. Require regression proof for correctness and security findings, not for style or naming nits.
- Comment: enough local context to stand alone, then only the new evidence or decision. Do not replay the whole thread.
- Governance/design/process: affected artifact or process, decision sought, tradeoff, decision owner when relevant, and adoption signal.
- Release discussion: shipped state and proof only. Keep planned, merged, deployed, and adopted distinct.

## Review communication

- Address the work, never the contributor. Be direct, respectful, and technically specific.
- Mark required changes, suggestions, nits, and informational notes so the author knows what blocks progress.
- Explain why when the reason is not evident. Give the minimum guidance that helps; do not redesign the change for the author unless exact direction is safer or materially faster.
- Prefer facts, repository policy, and demonstrated behavior over taste. Record the outcome of any off-thread decision back into the public record.
- Keep discussion aimed at a decision, correction, or next action.

## Independent clarity pass

Run an independent outside-voice pass for protocol, security, normative, architecture, release, or otherwise high-blast-radius contributions, and whenever the user requests one. Use the strongest independent reviewer available: a separate model, a fresh session, or a human colleague. Give it the raw draft plus source facts, ask it to find ambiguity and overclaiming, and reconcile every material change.

When a specific model is requested, verify the executed model from runtime evidence; a requested model name or wrapper label is not proof. Report unavailable or downgraded passes honestly.

## Public-write boundary

- Before any public write, check whether the content discloses an unfixed or undisclosed vulnerability, exploit path, credential, or sensitive personal information. If it might, stop and use the repository's security policy, private vulnerability reporting, or maintainer contact with user approval. A public surface is never the first channel for a sensitive finding.
- Drafting or review does not authorize publication.
- Explicit `post`, `publish`, `replace`, `submit`, or equivalent instruction authorizes only the named surface.
- Preserve contributor credit and never imply steward endorsement, release, adoption, or production proof without direct evidence.
- Use plain language. Expand non-obvious acronyms on first use. Resolve pronouns and project names.
- Omit private runtime IDs, absolute paths, internal steering, hidden coordination, and credentials. Do not rely on external links alone when their essential context may disappear or be inaccessible.

## Examples

- "Draft a PR description for this change" → ground it in the live diff and repository rules, separate implemented from proposed state, then return the exact draft without publishing.
- "Post this review finding" → verify the live head and location, make the impact and required correction actionable, publish only when that exact write is authorized, then read the live body back.
- "Update my issue with the new test result" → add only the new evidence and resulting decision to the existing public thread; do not replay private history.

## Gotchas

- A locally correct draft can still be wrong when the live target, head, or CI state has moved; re-read immediately before publishing.
- A private task ID, local path, or chat-derived nickname is not usable provenance for a public reader.
- `gh` command success proves transport, not the exact rendered body; read the live GitHub surface back.
- Review cleanliness, mergeability, deployment, adoption, and release are distinct states and need separate evidence.

## Done

Done means the live GitHub body was read back and a cold reader can correctly interpret and act on the contribution from the public record alone. The necessary context, evidence, action, validation, and boundary scale with what that contribution actually raises.
