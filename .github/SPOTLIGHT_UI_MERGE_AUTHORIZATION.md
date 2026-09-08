# Spotlight UI merge authorization

`spotlight-link-sync.yml` has standing authorization to reconcile and merge one narrowly defined automation-managed presentation change: the guarded rotating Spotlight direct-link block in `README.md`. This standing authorization applies only to pull requests from the fixed `automation/spotlight-links` branch that are produced by the reviewed synchronization workflow.

Scheduled reconciliation and the post-publication bot dispatch may therefore complete the merge automatically. A manual `workflow_dispatch` follows the same guarded path and does not add broader authority. The workflow has no merge-authorization input and there is no alternate comment-, issue-, or actor-driven merge path.

Standing authorization is conditional, not a bypass. The workflow must reconstruct the exact published Spotlight projection from the validated Portfolio Evidence Ledger, byte-compare all six generated card variants, bind the proposal to the exact reviewed `main` and `generated` SHAs, and prove that the proposed head is exactly one README-only commit. The merge job then requires the same five protected-main checks from GitHub Actions integration id `15368`: `analyze-actions`, `analyze-python`, `dependency-review`, `integration-pinned-upstream`, and `validate-contracts`.

Immediately before merge, the workflow rechecks the exact pull-request head, current `main` base, current `generated` evidence head, one-file `README.md` closure, and successful required checks. It requests a merge commit with the expected head SHA. `Protect Main` remains the server-side arbiter and the workflow has no bypass actor.

This standing authorization does not authorize arbitrary README/UI pull requests, Dependabot pull requests, dependency updates, workflow changes, source assets, or any other bot-authored change. Anything outside the fixed deterministic Spotlight synchronization class remains subject to its normal review and merge policy.
