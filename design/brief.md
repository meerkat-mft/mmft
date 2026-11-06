# Console design brief

The one-page brief for the console's design language (#5). [DESIGN.md](DESIGN.md) is the design language that answers it.

## Who uses it

Administrators who run file movement for an organization: platform engineers, integration teams, and the people on call when a nightly run fails. They know their systems well. They open the console to answer a question fast, such as "did last night's run deliver everything?", "why did this one file fail?", or "can I show an auditor this file arrived unchanged?". They don't browse it for pleasure.

## What it must make obvious

1. **What happened, at a glance:** a run with 1 failed delivery among 400 must not look like a success. Partial failure is the normal hard case, so design for it first.
2. **Evidence, not just status:** a delivery is only proven when both agents have signed: the source's manifest and the destination's receipt. Make `verified`, `source_only`, and `none` as visible as `succeeded` and `failed`.
3. **Where to act, and where not to:** the console never approves flows or takes credentials. Those happen in the signed CLI. The console shows that a version is waiting for approval, who approved it, and the exact command to run, but it never offers an approve button.
4. **The flow as a tree:** flows are trees of cards (ADR 0006): a trigger, a source, rules, then one path per destination, with failure paths and outcomes. The canvas must make each path, and so each delivery, readable on its own.

## Constraints

- **Dark only.** There is no light theme, in mock-ups or in the product.
- **The brand's amber (`#E2A04A`) must never be mistaken for a warning.**
- **Status never relies on colour alone.** Every state also has a label, a shape, or an icon.
- **Untrusted text stays text.** File names, agent names, and error codes come from agents and administrators, so they are shown as plain text, never as markup. File names can be missing once retention has deleted them, and no screen may need them to make sense.
- **Every screen is built on the public API.** Each prototype screen lists the calls it would need, marked as built, specified, or missing.
- **No real companies or products** in example data.
- **Same-origin only:** the real console's content security policy allows no third-party fonts or scripts, so fonts are self-hosted.

## Where the decisions are

The design review for #5 settled the design language. [DESIGN.md](DESIGN.md) holds it: exact token values, the reasons for them, and the rules for components, motion, icons, and accessibility.
