---
name: work-issue
description: Work a Meerkat MFT GitHub issue from start to merge, following the issue workflow in docs/conventions.md. Use when asked to pick up, work on, implement, or fix an issue, such as "work on #19" or "take the next M1 issue".
---

# Work an issue

Follow these steps in order. The rules behind them are in `docs/conventions.md` and `CLAUDE.md`.

## 1. Read and check the issue

- Read the issue, its comments, and its "Done when" criteria. These are the spec for the work.
- Check every issue under "Depends on". If one is still open, stop and tell the user.
- Keep to the issue's milestone scope. Anything else becomes a new issue, not part of this pull request.
- Set the issue to In Progress on the Project board. If you can't, tell the user.

## 2. Plan first when the issue is labelled `needs-plan`

Post a plan as an issue comment, then stop and wait for the maintainer to approve it. Don't write code before approval. The plan covers:

- **Approach:** the change in a few sentences.
- **Files:** the packages and files to add or change.
- **Interfaces:** schema, API, protocol, or flow format changes, or "none".
- **ADR:** whether the change needs one, and why.
- **Tests:** what proves each "Done when" criterion.
- **Out of scope:** what this deliberately leaves out.

Without the label, go straight to step 3. If the work turns out larger or riskier than the issue suggests, post a plan anyway and ask.

## 3. Build

- Branch from the latest `main`, unless the session names a branch to use.
- Follow `GLOSSARY.md` terms and `docs/naming.md` names.
- With a schema change, update `docs/data-model.md`.
- With a change under `api/`, run `scripts/check-api.sh --write`. Never edit `gen/` by hand.
- With a decision that is expensive to reverse, add an ADR from `docs/adr/0000-template.md`.
- Before pushing, run the checks CI runs: `go build ./...`, `go test -race ./...`, `golangci-lint run`, and `scripts/check-api.sh`.

## 4. Open the pull request

- Title: Conventional Commits, such as `feat(agent): add file watcher`. The squash merge uses it as the commit on `main`, and CI checks it.
- Body: fill in `.github/pull_request_template.md`, starting with `Closes #n`.
- Copilot reviews the pull request automatically. If no review appears within a few minutes, request one.
- Watch the pull request for CI results and review comments.

## 5. Handle review and CI

- Fix each valid Copilot or maintainer comment, or reply with the reason it doesn't apply. Then resolve the thread, because the ruleset requires every conversation to be resolved before merging.
- When CI fails, reproduce the failure locally, fix it, and show the check passing. Never skip or disable a test to get green.

## 6. Merge and close

- The maintainer merges, or enables auto-merge. Don't merge unless the user asks.
- After the merge, confirm the issue is closed and shows as Done on the Project board.
