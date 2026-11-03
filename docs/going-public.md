# Going public

Steps for the maintainer to apply after `meerkat-mft/mmft` becomes public. Some of these features aren't available on a private repo under the free plan, so apply them straight after the change. Delete this file once they're done.

## 1. Change visibility

```bash
gh repo edit meerkat-mft/mmft --visibility public --accept-visibility-change-consequences
```

## 2. Security reporting and alerts

Turn these on first, because `SECURITY.md` depends on the first one.

Private vulnerability reporting ([#7](https://github.com/meerkat-mft/mmft/issues/7)):

```bash
gh api --method PUT repos/meerkat-mft/mmft/private-vulnerability-reporting
```

Dependabot alerts:

```bash
gh api --method PUT repos/meerkat-mft/mmft/vulnerability-alerts
```

Dependabot security updates:

```bash
gh api --method PUT repos/meerkat-mft/mmft/automated-security-fixes
```

Secret scanning and push protection:

```bash
gh api --method PATCH repos/meerkat-mft/mmft --input - <<'EOF'
{"security_and_analysis": {"secret_scanning": {"status": "enabled"}, "secret_scanning_push_protection": {"status": "enabled"}}}
EOF
```

## 3. Require CI on main

This covers [#6](https://github.com/meerkat-mft/mmft/issues/6). The ruleset requires a pull request and all five CI jobs, and blocks force pushes and branch deletion. It requires no approving review, because there's one maintainer. Nobody can bypass it, including administrators.

```bash
gh api --method POST repos/meerkat-mft/mmft/rulesets --input - <<'EOF'
{
  "name": "Protect main",
  "target": "branch",
  "enforcement": "active",
  "conditions": {"ref_name": {"include": ["~DEFAULT_BRANCH"], "exclude": []}},
  "rules": [
    {"type": "pull_request", "parameters": {
      "dismiss_stale_reviews_on_push": false,
      "require_code_owner_review": false,
      "require_last_push_approval": false,
      "required_approving_review_count": 0,
      "required_review_thread_resolution": false
    }},
    {"type": "required_status_checks", "parameters": {
      "strict_required_status_checks_policy": true,
      "required_status_checks": [
        {"context": "Build and test"},
        {"context": "Lint"},
        {"context": "API definitions"},
        {"context": "SBOM"},
        {"context": "Vulnerabilities"}
      ]
    }},
    {"type": "non_fast_forward"},
    {"type": "deletion"}
  ]
}
EOF
```

## 4. Actions permissions

Keep the default token read-only, and don't let workflows approve pull requests:

```bash
gh api --method PUT repos/meerkat-mft/mmft/actions/permissions/workflow -f default_workflow_permissions=read -F can_approve_pull_request_reviews=false
```

Require approval before workflows run for any outside contributor:

```bash
gh api --method PUT repos/meerkat-mft/mmft/actions/permissions/fork-pr-contributor-approval -f approval_policy=all_external_contributors
```

Allow only pinned, known actions:

```bash
gh api --method PUT repos/meerkat-mft/mmft/actions/permissions -F enabled=true -f allowed_actions=selected -F sha_pinning_required=true
```

```bash
gh api --method PUT repos/meerkat-mft/mmft/actions/permissions/selected-actions --input - <<'EOF'
{"github_owned_allowed": true, "verified_allowed": false, "patterns_allowed": ["golangci/golangci-lint-action@*", "anchore/sbom-action@*", "anchore/sbom-action/*@*"]}
EOF
```

Run CI on a test pull request after this, because actions that call other unpinned actions can fail under these rules. If one does, set `sha_pinning_required` back to `false` and investigate.

## 5. Project board

The board shows open issues, so it's reasonable to make it public. Skip this to keep planning private.

```bash
gh project edit 1 --owner meerkat-mft --visibility PUBLIC
```

## 6. Tidy up

Delete branches after merging, and allow squash merges only:

```bash
gh repo edit meerkat-mft/mmft --delete-branch-on-merge --enable-squash-merge --enable-merge-commit=false --enable-rebase-merge=false
```

## 7. Website

Merge the prepared pull request on `meerkat-mft/meerkat-mft.github.io`. It changes "Will be open source" and links the source code and security policy cards.

## 8. Verify

Open these in a private browser window, without being signed in:

- <https://github.com/meerkat-mft/mmft>
- <https://github.com/meerkat-mft/mmft/blob/main/SECURITY.md>
- <https://github.com/meerkat-mft/mmft/security/advisories/new>
- <https://mmft.dev>

Check that Go can resolve the module from outside the private repo:

```bash
GOPROXY=direct GONOSUMDB='mmft.dev/*' go list -m -versions mmft.dev/mmft
```

Check the settings:

```bash
gh api repos/meerkat-mft/mmft/private-vulnerability-reporting
```

```bash
gh api repos/meerkat-mft/mmft/rulesets --jq '.[] | {name, enforcement}'
```

## Trademark

[#9](https://github.com/meerkat-mft/mmft/issues/9) stays open until the searches are done. Search these terms on each register: `Meerkat`, then `Meerkat MFT`.

- **EU marks:** use [eSearch plus](https://euipo.europa.eu/eSearch/) at EUIPO. Search trade marks by name, and filter by Nice classes 9 and 42. Include marks in any status, not just registered ones, and try similar spellings.
- **Benelux marks:** use the [BOIP trademarks register](https://www.boip.int/en/trademarks-register). Use advanced search with the verbal element, then limit to classes 9 and 42.
- **Wider check:** [TMview](https://www.tmdn.org/tmview/) searches many offices together, which helps catch national marks in other EU countries.

Class 9 generally covers downloadable software, and class 42 covers software services. Record what you find on #19. A similar mark in these classes needs legal advice, as does any clearance decision.
