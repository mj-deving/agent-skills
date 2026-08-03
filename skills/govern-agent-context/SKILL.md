---
name: govern-agent-context
description: "Design, audit, or refactor progressive-disclosure routing for agent instructions, repository docs, company knowledge, second brains, wikis, research corpora, and retrieval systems. Use when deciding what belongs in AGENTS.md or CLAUDE.md, adding read_when metadata or indexes, reducing always-on context, preventing stale knowledge, or making documents cheaply discoverable and lazily loadable."
---

# Govern Agent Context

Make the smallest correct context visible first and preserve a deterministic path to deeper
authority. Do not turn every document into a skill or preload every index body.

## Layers

1. **Bootstrap:** hard rules, authority boundaries, and compact routing pointers in harness-native
   instruction files.
2. **Catalog:** cheap metadata for each routable unit: title, summary, `read_when`, authority,
   freshness, sensitivity, and location.
3. **Focused knowledge:** bounded documents or skill bodies loaded only after a routing match.
4. **Evidence:** raw sources, transcripts, archives, datasets, receipts, and historical snapshots
   accessed only for a named need.

## Workflow

1. Identify the consumers, tasks, loaders, context budgets, and authoritative knowledge surfaces.
2. Inventory always-on instructions, indexes, documents, raw corpora, generated views, and search
   systems. Measure duplication and unreachable material.
3. Classify each item as bootstrap rule, catalog metadata, focused knowledge, raw evidence,
   generated projection, or runtime state.
4. Assign one authority and lifecycle. Record freshness requirements where claims can drift.
5. Provide one cheap discovery path for every agent-consumable focused document:
   - frontmatter;
   - a docs index;
   - a generated manifest;
   - bounded lexical/semantic search.
6. Write `read_when` as observable task/context conditions, not vague topics. Keep summaries factual
   and small enough to scan as a catalog.
7. Keep bootstrap files limited to invariants and pointers. Move examples, explanations, history,
   niche procedures, and evidence down a layer.
8. Preserve source versus projection boundaries. Generated indexes and compiled wikis never become
   authority merely because retrieval ranks them highly.
9. Add gates for broken links, duplicate authority, missing catalog entries, stale claims, sensitive
   leakage, context budget, and query-to-document routing.
10. Test with fresh sessions and representative questions. Prove both recall and non-loading of
    irrelevant niche context.

## Routing rules

- Prefer deterministic metadata filtering before semantic retrieval.
- Resolve authority and sensitivity before relevance ranking.
- Load the smallest sufficient unit; follow deeper references only when required.
- Keep historical evidence dated and source-pinned.
- Keep personal identity, company knowledge, project doctrine, and general engineering guidance in
  separate scopes.
- Make raw archives searchable rather than prompt-resident.
- Treat missing freshness evidence as unknown, not current truth.
- Promote repeated hard-won procedures into a module or skill only when a stable reuse boundary is
  demonstrated.

## Output

Report the layer map, authorities, routing metadata, context budget, unreachable or duplicated
knowledge, mutations, routing tests, and remaining freshness or sensitivity gates.
