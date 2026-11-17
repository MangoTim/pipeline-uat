# `docs/` — the design picture

The pipeline in this repository is the one drawn in
`diagrams/pipeline/Pipeline-Design-UAT-PROD.png`.

| | |
|---|---|
| `diagrams/pipeline/Pipeline-Design-UAT-PROD.png` | the picture — the CI band, the three tiers, the approval gate |
| `diagrams/pipeline/build_design.py` | the builder that draws it |
| `diagrams/pipeline/build_diagrams.py` | the shared renderer the builder imports |
| `diagrams/pipeline/reference-redhat-pipeline.png` | the Red Hat reference pipeline the CI band order is taken from |

## Rebuilding the picture

```bash
cd docs/diagrams/pipeline
python3 build_design.py
```

It writes `Pipeline-Design-UAT-PROD.png` next to itself. Nothing else in the
repository depends on the picture — the Jenkinsfile is the source of truth
for what the pipeline does, and the picture is how it is explained.

## What the picture says

- **Three tiers, three hosts.** `.103` is the data tier (PostgreSQL 14).
  `.104` is UAT **and** CI — Jenkins, the image registry, Aqua, plus the UAT
  container. `.105` is PROD, and nothing else.
- **The CI band reads left to right.** `code scan → build → push → image
  scan`. The code scan comes first on purpose: a hardcoded secret is caught
  before it is baked into a layer and pushed to the registry.
- **The approval gate sits between UAT and PROD.** Both sites run the *same*
  image tag, so the gate decides *whether* those bytes reach production, never
  *which* bytes that is.
