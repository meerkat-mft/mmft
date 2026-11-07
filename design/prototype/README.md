# Console prototype

A clickable prototype of the console, built only from [DESIGN.md](../DESIGN.md). It runs on fake data and is never shipped. It exists to try the design language on real screens before the console is built.

## Running it

Serve the repository root, because the page loads the brand icon from `assets/`:

```sh
python3 -m http.server 8732 --bind 127.0.0.1
```

Then open http://localhost:8732/design/prototype/. It's built for a full-screen browser at 1080p or wider. From 1600 px wide, the panel docks beside the page instead of covering it.

## What's in it

- **Runs:**
  - The runs list, with filters.
  - An opened run, with tabs across the top: Deliveries, Overview, Evidence, and Activity.
  - A delivery in the right-hand panel. What needs attention sorts first.
- **Flows:** an opened flow's Overview, which shows the draft waiting for approval and the exact CLI command, and its Canvas, a read-only tree of paths.
- **Agents:** an opened agent, including one waiting for approval.
- **Live motion:** a few seconds after loading, the retrying delivery succeeds. Its chip changes, its receipt mark fills, the "need attention" count ticks down, and its timeline gains the receipt. A running transfer on `payroll-weekly` shows live progress.
- **Component sheet:** every part of the console in one place, at `#components`.
- **Palette:** `Ctrl/⌘ K` jumps to any flow, run, agent, or delivery.
- **Reduce motion:** in the account menu. It follows the operating system's setting until you change it.

Every route has its own address, so links and the back button work.

## Files

- `tokens.css` holds every colour, space, and radius. `tokens.sh` generates it from DESIGN.md, so the prototype never keeps its own copy of a value. Run `./tokens.sh` after changing DESIGN.md.
- `app.css` holds the styles. Its type levels and motion values mirror DESIGN.md's Typography and Motion sections, because the token export doesn't carry them yet.
- `data.js` holds the fake data, using the real statuses, evidence levels, and error codes.
- `app.js` holds the screens. It sets every value as text, never as markup, as the real console must.

Fonts and icons load from public services here for speed. The real console self-hosts them under a same-origin content security policy.
