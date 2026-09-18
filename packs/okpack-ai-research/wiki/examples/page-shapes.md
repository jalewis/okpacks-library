---
type: concept
id: concept-page-shapes
title: "AI / LLM Research Watch — example page shapes"
---

# Example page shapes

These examples show the intended structure for generated pages. They are not
claims about a real feed item and should not be treated as source material.

> **This is a shipped example — remove it once you're oriented.** It's a demo, not
> real knowledge. To remove it: `rm -r wiki/examples/` in your vault and re-run the
> index drains (`build-index-tree` / `rebuild-index`), or tombstone it via the MCP
> write path. Removing it from the pack means future pulls won't re-add it.

## Source page

Path pattern: `wiki/sources/YYYY/MM/<slug>.md`

```md
---
type: source
title: "Example Lab announces Example-2"
source_kind: lab-post
published: 2026-06-16
raw: raw:ai/example-lab-announces-example-2
authors:
  - Example Lab
---

# Example Lab announces Example-2

Short summary of the source in the pack voice. Capture what is new, what changed
relative to prior systems, and why it matters.

## Key claims

- Example-2 improves long-context retrieval on [[example-benchmark]].
- The system uses [[test-time-compute]] for harder prompts.

## Links

- Model: [[example-2]]
- Lab: [[example-lab]]
```

## Entity page

Path pattern: `wiki/entities/e/example-2.md`

```md
---
type: model
title: "Example-2"
lab: "[[example-lab]]"
released: 2026-06-16
sources:
  - "[[example-lab-announces-example-2]]"
---

# Example-2

Example-2 is a model/system worth tracking over time because multiple sources
are likely to refer back to its capabilities, release history, or eval results.

## Capabilities

Grounded summary of reported capabilities, avoiding unsupported extrapolation.

## Benchmarks

- [[example-benchmark]]: report the measured result and cite the source page.
```

## Concept page

Path pattern: `wiki/concepts/t/test-time-compute.md`

```md
---
type: method
title: "Test-time compute"
sources:
  - "[[example-lab-announces-example-2]]"
---

# Test-time compute

Synthesis of the method across sources. Do not restate a single paper when the
concept should represent an accumulating research theme.

## Why it matters

Explain what capability or reliability frontier the method affects.
```

## Prediction page

Path pattern: `wiki/predictions/<slug>.md`

```md
---
type: prediction
title: "Example-2 will be surpassed on Example Benchmark by 2026-12-31"
status: open
confidence: medium
subject: "[[example-2]]"
resolves_by: 2026-12-31
sources:
  - "[[example-lab-announces-example-2]]"
---

# Example-2 will be surpassed on Example Benchmark by 2026-12-31

Falsifiable claim with an observable resolution condition.

## What would refute this

No public model report or benchmark submission exceeds the stated Example-2
score on Example Benchmark by 2026-12-31.

## Evidence log

- 2026-06-16: Initial claim filed from the source page.
```
