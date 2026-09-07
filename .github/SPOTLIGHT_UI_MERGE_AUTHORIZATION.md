# Spotlight UI merge authorization

`spotlight-link-sync.yml` may reconcile presentation/navigation drift by planning the exact published Spotlight projection, updating the fixed README-only automation branch, opening or refreshing its pull request, and approving the canonical pull-request workflows when GitHub requires execution approval.

Final README/UI merge authority is separate. The `workflow_dispatch` boolean input `merge_ui_after_checks` defaults to `false`. The merge job is eligible only when a human explicitly starts `Sync Spotlight profile links` with that input set to `true`.

Scheduled reconciliation is never UI-merge-authorized. The post-publication bot dispatch from `Update profile stats` is also never UI-merge-authorized because it sends only `ref=main` and does not provide `merge_ui_after_checks`. A normal manual dispatch that leaves the input at its default is likewise merge-ineligible.

Explicit manual authorization does not bypass repository governance. Before a permitted merge, the synchronization workflow must still bind the exact README-only head and reviewed base/generated SHAs and require the same five protected-main checks: `analyze-actions`, `analyze-python`, `dependency-review`, `integration-pinned-upstream`, and `validate-contracts`. `Protect Main` remains the server-side arbiter and the workflow has no bypass actor.

This policy separates automated evidence/presentation reconciliation from the decision to publish a UI change. Automation may prepare a reviewed candidate; UI merge remains an explicit opt-in action.
