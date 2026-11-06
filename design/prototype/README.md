# Console prototypes

Throwaway prototypes for the console's design language (#5). They are never shipped. Open `index.html` in a browser; no build step and no server are needed.

- `data.js` holds fake data that uses the real statuses, evidence levels, and error codes.
- `render.js` builds the three screens: the flow canvas, a run with partial failure, and one delivery's audit trail. It sets every value as text, never as markup.
- `base.css` is the structure every direction shares. `burrow.css`, `sentinel.css`, and `ledger.css` are the three directions.

The rules from [the brief](../brief.md) apply here too:

- Dark only.
- The console shows approvals, but never offers to approve a flow or take a credential. Those happen in the signed CLI.
- Status never relies on colour alone.
- Every screen lists the API calls it needs.
- No real company names in the data.
- Fonts load from a font service here for speed. The real console self-hosts them.
