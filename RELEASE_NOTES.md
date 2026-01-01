# Release Notes

Note: Keep only the latest three releases here, in newest-to-oldest order.

## v0.1.0

### Highlights

- SARIF output validation now runs locally against the official SARIF schema.
- Heredoc content is preserved during Level 1 comment stripping.
- Goneat pre-commit and pre-push hooks are configured with guardian support.

### Added

- SARIF schema validation targets (`schema-validate`, `schema-meta`, `sarif-validate`).
- Vendored SARIF 2.1.0 JSON schema for offline validation.
- Pre-commit and pre-push Make targets for local validation flows.

### Changed

- Pinned tool minimums: sfetch v0.3.1 and goneat v0.4.0 (existing installs respected).
- Normalized formatting across docs, schemas, and testdata with goneat format.

### Testing

- Dogfood check: `make dogfood`
