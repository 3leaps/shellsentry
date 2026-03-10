# Agent Roles (Local Catalog)

This catalog mirrors the baseline roles from 3leaps Crucible so shellsentry can work offline. Keep it lean and use only when needed.

**Default to `devlead`** for most implementation work.

## Development & Engineering

| Role      | Focus                        | Use When                                          |
| --------- | ---------------------------- | ------------------------------------------------- |
| `devlead` | Implementation, architecture | Building features, fixes, refactors, core design  |
| `devrev`  | Code review, bug finding     | Four-eyes review for correctness, maintainability |
| `qa`      | Testing, quality gates       | Test design, coverage analysis, dogfood testing   |
| `secrev`  | Security analysis            | Verification logic, trust model, supply-chain     |
| `releng`  | Releases, CI/CD              | Version bumps, changelogs, release automation     |

## Documentation & Governance

| Role       | Focus                       | Use When                               |
| ---------- | --------------------------- | -------------------------------------- |
| `infoarch` | Documentation, schema       | Docs updates, user-facing guidance     |
| `prodmktg` | Brand, content, positioning | README, messaging, adoption guidance   |
| `dispatch` | Coordination, handoffs      | Cross-session routing, formal handoffs |

## Source and References

- Baseline roles: `../crucible/config/agentic/roles/*.yaml`
- Marketing role: `../fulmenhq/crucible/config/agentic/roles/prodmktg.yaml`
- Catalog summary: `../crucible/config/agentic/roles/README.md`
- Online reference (when available): https://crucible.3leaps.dev/catalog/roles
