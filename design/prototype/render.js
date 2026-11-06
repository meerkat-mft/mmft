// Renders the three prototype screens from MMFT_DATA. Every value is set with
// textContent, never as markup, as the real console must for untrusted names.
(function () {
  "use strict";
  const D = window.MMFT_DATA;
  const params = new URLSearchParams(location.search);
  const DIRECTIONS = {
    burrow: { name: "Burrow", line: "Warm and editorial. Amber is the brand, and warnings are coral." },
    sentinel: { name: "Sentinel", line: "A dense control room. Amber is only the mark, and warnings are hatched." },
    ledger: { name: "Ledger", line: "Quiet and exact, built around evidence. Warnings are violet." },
  };
  const SCREENS = { canvas: "Flow canvas", run: "Run", audit: "Audit trail" };
  const direction = DIRECTIONS[params.get("d")] ? params.get("d") : "burrow";
  const screen = SCREENS[params.get("s")] ? params.get("s") : "run";

  document.documentElement.dataset.direction = direction;
  const sheet = document.createElement("link");
  sheet.rel = "stylesheet";
  sheet.href = direction + ".css";
  document.head.appendChild(sheet);
  document.title = DIRECTIONS[direction].name + " · " + SCREENS[screen];

  // el builds an element. Strings become text nodes, never markup.
  function el(tag, attrs, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "class") n.className = v;
      else if (k === "data") Object.assign(n.dataset, v);
      else n.setAttribute(k, v);
    }
    for (const k of kids.flat()) {
      if (k == null || k === false) continue;
      n.appendChild(typeof k === "string" ? document.createTextNode(k) : k);
    }
    return n;
  }

  const STATUS = {
    succeeded: { label: "Succeeded", glyph: "✓" },
    failed: { label: "Failed", glyph: "✕" },
    retry_wait: { label: "Retrying", glyph: "↻" },
    partial_failure: { label: "Partial failure", glyph: "◐" },
    approved: { label: "Approved", glyph: "✓" },
  };
  const EVIDENCE = {
    verified: { label: "Verified", marks: [true, true], note: "Manifest and receipt signed" },
    source_only: { label: "Source only", marks: [true, false], note: "Manifest signed, no receipt" },
    none: { label: "No evidence", marks: [false, false], note: "Nothing signed" },
  };

  function status(s) {
    const st = STATUS[s];
    return el("span", { class: "status", data: { status: s } }, el("span", { class: "glyph", "aria-hidden": "true" }, st.glyph), st.label);
  }
  // evidence shows two marks: the source's manifest and the destination's receipt.
  function evidence(e) {
    const ev = EVIDENCE[e];
    return el(
      "span",
      { class: "evidence", data: { evidence: e }, title: ev.note },
      el("span", { class: "marks", "aria-hidden": "true" }, ev.marks.map((m, i) => el("span", { class: "mark" + (m ? " on" : ""), data: { which: i ? "receipt" : "manifest" } }))),
      ev.label
    );
  }
  function code(text) {
    return el("code", { class: "code" }, text);
  }
  function apiList(calls) {
    return el(
      "aside",
      { class: "api" },
      el("h3", {}, "API this screen needs"),
      el("ul", {}, calls.map(([call, state]) => el("li", { data: { state } }, code(call), el("span", { class: "api-state" }, state))))
    );
  }

  function header() {
    const nav = el(
      "nav",
      { class: "screens", "aria-label": "Screens" },
      Object.entries(SCREENS).map(([key, name]) =>
        el("a", { href: "?d=" + direction + "&s=" + key, class: key === screen ? "current" : "", "aria-current": key === screen ? "page" : "false" }, name)
      )
    );
    const dirs = el(
      "nav",
      { class: "directions", "aria-label": "Directions" },
      Object.entries(DIRECTIONS).map(([key, d]) => el("a", { href: "?d=" + key + "&s=" + screen, class: key === direction ? "current" : "" }, d.name))
    );
    return el(
      "header",
      { class: "top" },
      el("a", { class: "brand", href: "index.html" }, el("img", { src: "../../assets/brand/meerkat-icon.svg", alt: "", width: "28", height: "28" }), el("span", { class: "wordmark" }, "Meerkat"), el("span", { class: "ws" }, D.workspace)),
      nav,
      dirs
    );
  }

  // --- Flow canvas -----------------------------------------------------------
  function card(c, extra) {
    return el(
      "div",
      { class: "card", data: { kind: c.kind.toLowerCase().replace(/\s+/g, "-") } },
      el("div", { class: "card-kind" }, c.kind),
      c.agent ? el("div", { class: "card-agent" }, c.agent) : null,
      el("div", { class: "card-detail" }, c.detail),
      c.match ? el("div", { class: "card-match" }, code(c.match)) : null,
      extra || null
    );
  }
  function canvas() {
    const f = D.flow;
    const t = f.tree;
    const paths = t.rules.map((r, i) =>
      el(
        "div",
        { class: "path" },
        el("div", { class: "rule" }, el("span", { class: "rule-n" }, "Path " + (i + 1)), el("span", { class: "rule-label" }, r.label), code(r.when)),
        el("div", { class: "branch" }, r.destinations.map((d) => card(d, el("div", { class: "delivers" }, "One delivery per file")))),
        r.outcome ? card(r.outcome) : null,
        r.failure ? card(r.failure) : null
      )
    );
    return el(
      "main",
      { class: "screen screen-canvas" },
      el(
        "div",
        { class: "screen-head" },
        el("h1", {}, f.name),
        el("div", { class: "meta" }, el("span", { class: "version" }, "v" + f.version), status(f.status), el("span", { class: "who" }, "Approved by " + f.approvals.map((a) => a.by).join(" and ")))
      ),
      el(
        "div",
        { class: "draft-banner", role: "note" },
        el("strong", {}, "Draft v" + f.draft.version + " waits for " + f.draft.waitingFor + " approvals."),
        " " + f.draft.change + ". Approval happens in the signed CLI, never here:",
        code("mmft flow approve " + f.name + " --version " + f.draft.version)
      ),
      el(
        "div",
        { class: "tree" },
        el("div", { class: "spine" }, card(t.trigger), card(t.source)),
        el("div", { class: "paths" }, paths),
        el("div", { class: "unmatched" }, t.unmatched)
      ),
      apiList(f.api)
    );
  }

  // --- Run with partial failure ----------------------------------------------
  function run() {
    const r = D.run;
    const total = r.deliveries.length;
    const bar = el(
      "div",
      { class: "ratio", role: "img", "aria-label": r.counts.succeeded + " succeeded, " + r.counts.retry_wait + " retrying, " + r.counts.failed + " failed" },
      // Set through the style object, not a style attribute, which the real
      // console's content security policy would block.
      ["failed", "retry_wait", "succeeded"].map((s) => {
        const seg = el("span", { class: "seg", data: { status: s } });
        seg.style.flex = String(r.counts[s]);
        return seg;
      })
    );
    const attention = r.deliveries.filter((d) => d.status !== "succeeded");
    const row = (d) =>
      el(
        "tr",
        { data: { status: d.status } },
        el("td", { class: "c-status" }, status(d.status)),
        el("td", { class: "c-file" }, d.file === null ? el("span", { class: "gone" }, "Name deleted by retention") : el("span", { class: "filename" }, d.file)),
        el("td", { class: "c-route" }, d.from, el("span", { class: "arrow", "aria-hidden": "true" }, " → "), d.to),
        el("td", { class: "c-size" }, d.size),
        el("td", { class: "c-ev" }, evidence(d.evidence)),
        el("td", { class: "c-err" }, d.error ? code(d.error) : null, d.retry ? el("div", { class: "retry" }, d.retry) : null)
      );
    return el(
      "main",
      { class: "screen screen-run" },
      el(
        "div",
        { class: "screen-head" },
        el("h1", {}, r.flow, el("span", { class: "version" }, " v" + r.version)),
        el("div", { class: "meta" }, status(r.status), el("span", {}, r.trigger), el("span", {}, r.started + " to " + r.ended.slice(11)))
      ),
      el(
        "section",
        { class: "summary" },
        el("div", { class: "big" }, el("span", { class: "num" }, String(r.counts.failed + r.counts.retry_wait)), el("span", { class: "of" }, " of " + total + " deliveries need attention")),
        bar,
        el("div", { class: "legend" }, el("span", {}, r.counts.succeeded + " succeeded"), el("span", {}, r.counts.retry_wait + " retrying"), el("span", {}, r.counts.failed + " failed"))
      ),
      el(
        "section",
        { class: "attention" },
        el("h2", {}, "Needs attention"),
        el("table", { class: "deliveries" }, el("tbody", {}, attention.map(row)))
      ),
      el(
        "section",
        { class: "all" },
        el("h2", {}, "All deliveries"),
        el(
          "table",
          { class: "deliveries" },
          el("thead", {}, el("tr", {}, ["Status", "File", "Route", "Size", "Evidence", ""].map((h) => el("th", {}, h)))),
          el("tbody", {}, r.deliveries.map(row))
        )
      ),
      apiList(r.api)
    );
  }

  // --- One delivery's audit trail --------------------------------------------
  function audit() {
    const a = D.audit;
    return el(
      "main",
      { class: "screen screen-audit" },
      el(
        "div",
        { class: "screen-head" },
        el("h1", {}, "Delivery ", el("span", { class: "id" }, a.delivery.slice(0, 8) + "…")),
        el("div", { class: "meta" }, status(a.status), evidence(a.evidence))
      ),
      el(
        "section",
        { class: "facts" },
        el(
          "dl",
          {},
          el("dt", {}, "File"),
          el("dd", {}, el("span", { class: "filename" }, a.file), el("span", { class: "untrusted" }, "Untrusted text. Deleted after the retention period.")),
          el("dt", {}, "Route"),
          el("dd", {}, a.from + " → " + a.to),
          el("dt", {}, "Sealed file"),
          el("dd", {}, code(a.sealedSha256), el("span", { class: "size" }, a.sealedSize)),
          el("dt", {}, "Proof"),
          el("dd", {}, "The source signed the manifest, the destination signed the receipt over the same hash, and the checkpoint covers both.")
        )
      ),
      el(
        "ol",
        { class: "timeline" },
        a.events.map((e) =>
          el(
            "li",
            { data: { kind: e.kind } },
            el("time", {}, e.at),
            el("span", { class: "actor" }, e.actor),
            el("span", { class: "what" }, e.what),
            e.statement ? el("span", { class: "stmt" }, el("span", { class: "stmt-kind" }, e.statement), code(e.id)) : null
          )
        )
      ),
      apiList(a.api)
    );
  }

  const app = document.getElementById("app");
  app.appendChild(header());
  app.appendChild(el("p", { class: "direction-line" }, DIRECTIONS[direction].line));
  app.appendChild({ canvas, run, audit }[screen]());
})();
