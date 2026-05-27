<!--
Use this template when opening a PR against this repository.
Keep checked items honest — if a box is ticked, the reviewer expects evidence.
-->

## Summary

<!-- 1–3 sentences. What problem does this PR address? -->

## Changes

<!-- Bullet list of the concrete changes. Cite files, not vague areas. -->

## Design considerations

<!-- Cross-link any new doc, ADR, or interface this PR introduces. -->

## Threat model impact

<!-- Does this change touch any vulnerability class V1–V33 from docs/07-threat-model.md?
     If yes, name the class and explain the impact. If no, state "none". -->

## Checklist

- [ ] All new docs follow the template in `docs/00-overview.md`.
- [ ] All new ADRs follow `Status / Context / Decision / Consequences / Alternatives / Open questions / References`.
- [ ] No Solidity function bodies introduced (this repo is interfaces-only until v2).
- [ ] All new TypeScript files are declaration-only (no runtime logic).
- [ ] All new Mermaid diagrams begin with a valid diagram-type header.
- [ ] Shared cross-repo contract files were not modified without coordinating with `lehelkovach/human-key-core`.
- [ ] Traceability matrix in `docs/00-overview.md` updated if new docs / interfaces / diagrams / ADRs were added.
