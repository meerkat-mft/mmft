// The console prototype. Routes live in the hash, so every list, item, tab,
// and panel has its own address and the back button works. Every value from
// the data is set as text, never as markup, as the real console must do.
(function () {
  "use strict";
  const M = window.MMFT;
  const $ = (id) => document.getElementById(id);

  // ---- Small helpers ------------------------------------------------------
  function h(tag, attrs, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k === "class") n.className = v;
      else if (k === "data") Object.assign(n.dataset, v);
      else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
      else n.setAttribute(k, v === true ? "" : v);
    }
    for (const k of kids.flat()) {
      if (k == null || k === false) continue;
      n.append(typeof k === "string" || typeof k === "number" ? document.createTextNode(String(k)) : k);
    }
    return n;
  }
  function icon(name) {
    const key = name.replace(/(^|-)(\w)/g, (_, __, c) => c.toUpperCase());
    const node = window.lucide && window.lucide.icons[key];
    if (!node) return h("span", { "aria-hidden": "true" });
    const svg = window.lucide.createElement(node);
    svg.setAttribute("class", "lucide");
    svg.setAttribute("aria-hidden", "true");
    return svg;
  }
  const STATUS = {
    succeeded: ["success", "circle-check", "Succeeded"],
    approved: ["success", "circle-check", "Approved"],
    failed: ["error", "circle-x", "Failed"],
    revoked: ["error", "ban", "Revoked"],
    retry_wait: ["warning", "rotate-cw", "Retrying"],
    partial_failure: ["warning", "circle-alert", "Partial failure"],
    running: ["info", "clock", "Running"],
    transferring: ["info", "clock", "Transferring"],
    pending: ["info", "clock", "Waiting for approval"],
    draft: ["info", "clock", "Draft"],
    cancelled: ["cancelled", "ban", "Cancelled"],
  };
  function chip(status, changed, label) {
    const [tone, ic, name] = STATUS[status];
    return h("span", { class: "chip" + (changed ? " changed" : ""), data: { tone } }, icon(ic), label || name);
  }
  function statusIcon(status) {
    const [tone, ic, label] = STATUS[status];
    return h("span", { class: "status-icon" + (status === "running" ? " spin" : ""), data: { tone }, title: label, role: "img", "aria-label": label }, icon(ic));
  }
  const EVIDENCE = { verified: ["Verified", 2], source_only: ["Source only", 1], none: ["No evidence", 0] };
  // Two marks: the source's manifest, then the destination's receipt.
  function evidence(level, filling) {
    const [label, n] = EVIDENCE[level];
    return h(
      "span",
      { class: "evidence", data: { level }, title: ["Nothing signed yet", "Manifest signed, no receipt yet", "Manifest and receipt signed"][n] },
      h("span", { class: "marks", "aria-hidden": "true" }, h("span", { class: "mark" + (n >= 1 ? " on" : "") }), h("span", { class: "mark" + (n >= 2 ? " on" : "") + (filling && n >= 2 ? " filling" : "") })),
      label
    );
  }
  function fileName(name) {
    return name == null ? h("span", { class: "gone" }, "Name deleted by retention") : h("span", { title: name }, name);
  }
  function copyButton(text, label) {
    return h("button", {
      class: "icon-button", type: "button", "aria-label": label || "Copy",
      onclick: (e) => {
        const btn = e.currentTarget;
        const done = () => { btn.replaceChildren(icon("check")); setTimeout(() => btn.replaceChildren(icon("copy")), 1200); };
        try { navigator.clipboard.writeText(text).then(done, done); } catch (err) { done(); }
      },
    }, icon("copy"));
  }
  function codeBlock(text) {
    return h("div", { class: "code-block" }, h("code", {}, text), copyButton(text, "Copy the command"));
  }
  // Tabs across the top of an opened item: Azure-style sections, laid out
  // horizontally so the content keeps the full width.
  function tabBar(label, base, tabs, current) {
    return h("nav", { class: "tabs", "aria-label": label },
      tabs.map(([k, l, n]) => h("a", { class: "tab", href: base + k, "aria-current": current === k ? "page" : null },
        l, n != null ? h("span", { class: "count muted" }, n) : null)));
  }
  const flowById = (id) => M.flows.find((f) => f.id === id);
  const runById = (id) => M.runs.find((r) => r.id === id);
  const agentById = (id) => M.agents.find((a) => a.id === id);
  const shortId = (id) => id.slice(0, 8);
  function counts(run) {
    const c = { succeeded: 0, failed: 0, retry_wait: 0, active: 0 };
    run.deliveries.forEach((d) => {
      if (d.status === "succeeded") c.succeeded++;
      else if (d.status === "failed") c.failed++;
      else if (d.status === "retry_wait") c.retry_wait++;
      else c.active++;
    });
    c.attention = c.failed + c.retry_wait;
    return c;
  }

  // ---- Routing -----------------------------------------------------------
  function parse() {
    const parts = location.hash.replace(/^#\/?/, "").split("/").filter(Boolean);
    return { section: parts[0] || "runs", id: parts[1], tab: parts[2], sub: parts[3] };
  }
  const SECTIONS = [
    ["flows", "workflow", "Flows"],
    ["runs", "play", "Runs"],
    ["agents", "server", "Agents"],
    ["audit", "shield-check", "Audit"],
    ["settings", "settings", "Settings"],
  ];

  function renderNav(route) {
    $("nav").replaceChildren(...SECTIONS.map(([key, ic, label]) =>
      h("a", { class: "nav-item", href: "#" + key, "aria-current": route.section === key ? "page" : null }, icon(ic), h("span", {}, label))));
  }

  // ---- Runs --------------------------------------------------------------
  let filter = "all";
  function runsList(current) {
    const visible = M.runs.filter((r) => filter === "all" || (filter === "attention" && ["failed", "partial_failure"].includes(r.status)) || (filter === "running" && r.status === "running"));
    return h(
      "section",
      { class: "list-pane", "aria-label": "Runs" },
      h("div", { class: "pane-head" }, h("h1", { class: "t-headline-sm" }, "Runs"), h("span", { class: "muted t-body-sm" }, M.runs.length + " today and yesterday")),
      h("div", { class: "filters", role: "group", "aria-label": "Filter runs" },
        [["all", "All"], ["attention", "Needs attention"], ["running", "Running"]].map(([k, l]) =>
          h("button", { class: "filter", type: "button", "aria-pressed": String(filter === k), onclick: () => { filter = k; render(); } }, l))),
      h("ul", { class: "list" }, visible.map((r) =>
        h("li", {}, h("a", { class: "list-item", href: "#runs/" + r.id, "aria-current": r.id === current ? "page" : null },
          h("span", { class: "li-icon" }, statusIcon(r.status)),
          h("span", { class: "li-title" }, flowById(r.flow).name),
          h("span", { class: "li-meta" }, r.started),
          h("span", { class: "li-sub" }, STATUS[r.status][2] + " · " + r.date + " · " + r.trigger)))))
    );
  }

  function runItem(run, tab, deliveryId) {
    const flow = flowById(run.flow);
    const c = counts(run);
    const tabs = [["deliveries", "Deliveries", run.deliveries.length], ["overview", "Overview"], ["evidence", "Evidence"], ["activity", "Activity"]];
    const menu = tabBar("Run", "#runs/" + run.id + "/", tabs, tab);
    const head = h("div", { class: "content-head" },
      h("h2", { class: "t-headline-md" }, flow.name), chip(run.status),
      h("div", { class: "actions" },
        c.attention ? h("button", { class: "btn btn-primary", type: "button" }, icon("rotate-cw"), "Retry " + c.failed + " failed") : null,
        h("button", { class: "btn btn-secondary", type: "button" }, icon("download"), "Export evidence")));
    const meta = h("div", { class: "meta-line" },
      h("span", {}, icon("git-commit-horizontal"), "Version " + run.version),
      h("span", {}, icon("calendar-clock"), run.trigger),
      h("span", {}, icon("clock"), run.date + " " + run.started + (run.duration === "running" ? ", running" : ", took " + run.duration)));
    let body;
    if (tab === "overview") body = runOverview(run, flow);
    else if (tab === "evidence") body = runEvidence(run);
    else if (tab === "activity") body = runActivity(run);
    else body = runDeliveries(run, deliveryId, c);
    return h("section", { class: "item", "aria-label": flow.name + " run" }, menu,
      h("div", { class: "content view-enter" }, h("div", { style: "display:grid;gap:8px" }, head, meta), body));
  }

  let lastAttention = null;
  function runDeliveries(run, selected, c) {
    const calm = c.attention === 0;
    const headline = h("div", { class: "headline" + (calm ? " calm" : "") },
      h("span", { class: "t-display-sm", id: "attention-count" }, String(c.attention)),
      h("span", { class: "t-headline-sm" }, calm ? "deliveries need attention" : "of " + run.deliveries.length + " deliveries need attention"));
    const total = run.deliveries.length;
    const seg = (tone, n) => { const s = h("span", { data: { tone } }); s.style.flexGrow = String(n); s.hidden = n === 0; return s; };
    const summary = h("div", { class: "summary" }, headline,
      h("div", { class: "ratio", role: "img", "aria-label": c.succeeded + " succeeded, " + c.retry_wait + " retrying, " + c.failed + " failed, " + c.active + " in progress, of " + total },
        seg("error", c.failed), seg("warning", c.retry_wait), seg("info", c.active), seg("success", c.succeeded)),
      h("div", { class: "legend" },
        h("span", {}, statusIcon("failed"), c.failed + " failed"),
        h("span", {}, statusIcon("retry_wait"), c.retry_wait + " retrying"),
        c.active ? h("span", {}, statusIcon("transferring"), c.active + " in progress") : null,
        h("span", {}, statusIcon("succeeded"), c.succeeded + " succeeded")));
    // What needs attention leads; successes recede below it.
    const order = { failed: 0, retry_wait: 1, transferring: 2, succeeded: 3 };
    const rows = [...run.deliveries].sort((a, b) => order[a.status] - order[b.status]);
    // The file name is a real link to the delivery's address, so it can be
    // read by a screen reader and opened in a new tab. The whole row still
    // opens it on a plain click.
    const row = (d) => {
      const href = "#runs/" + run.id + "/deliveries/" + d.id;
      return h("tr", {
        "aria-selected": String(d.id === selected),
        onclick: (e) => { if (!(e.metaKey || e.ctrlKey || e.shiftKey)) location.hash = href; },
      },
      h("td", {}, chip(d.status, d.changed)),
      h("td", { class: "file" }, h("a", { href, data: { key: d.id }, "aria-label": d.file == null ? "Delivery " + d.id + ", name deleted by retention" : null }, fileName(d.file))),
      h("td", { class: "muted" }, d.from, " → ", d.to),
      h("td", { class: "num muted" }, d.size),
      h("td", {}, evidence(d.evidence, d.changed)),
      h("td", { class: "muted" }, d.error ? h("span", { class: "mono" }, d.error) : null,
        d.progress != null && d.status === "transferring" ? h("div", { class: "progress", id: "progress-" + d.id }, (() => { const s = h("span"); s.style.width = Math.round(d.progress * 100) + "%"; return s; })()) : null));
    };
    const table = h("div", { class: "table-wrap" }, h("table", {},
      h("thead", {}, h("tr", {}, ["Status", "File", "Route", "Size", "Evidence", "Error"].map((t, i) => h("th", { class: "t-label-sm" + (i === 3 ? " num" : "") }, t)))),
      h("tbody", {}, rows.map(row))));
    queueMicrotask(() => tickTo($("attention-count"), lastAttention, c.attention));
    lastAttention = c.attention;
    return h("div", { style: "display:grid;gap:16px" }, summary, table);
  }

  // Counts tick to their new value instead of jumping.
  function tickTo(el, from, to) {
    if (!el || from == null || from === to || document.documentElement.classList.contains("reduce-motion")) return;
    const start = performance.now();
    const step = (now) => {
      const t = Math.min(1, (now - start) / 360);
      el.textContent = String(Math.round(from + (to - from) * (1 - Math.pow(1 - t, 3))));
      if (t < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  }

  function runOverview(run, flow) {
    const agents = [...new Set(run.deliveries.flatMap((d) => [d.from, d.to]))];
    return h("div", { style: "display:grid;gap:24px;max-width:72ch" },
      h("dl", { class: "facts" },
        h("dt", {}, "Flow"), h("dd", {}, h("a", { href: "#flows/" + flow.id }, flow.name + ", version " + run.version)),
        h("dt", {}, "Approved by"), h("dd", {}, flow.approvals.map((a) => a.by + " at " + a.at).join(", ")),
        h("dt", {}, "Started by"), h("dd", {}, run.trigger),
        h("dt", {}, "Agents"), h("dd", {}, agents.join(", ")),
        h("dt", {}, "Run ID"), h("dd", { class: "mono" }, run.id)));
  }
  function runEvidence(run) {
    const v = run.deliveries.filter((d) => d.evidence === "verified").length;
    return h("div", { style: "display:grid;gap:16px;max-width:72ch" },
      h("p", {}, v + " of " + run.deliveries.length + " deliveries are verified: the source signed the manifest and the destination signed a receipt over the same hash."),
      h("div", { class: "callout" },
        h("div", { class: "callout-title" }, icon("shield-check"), "Audit checkpoint 1,482"),
        h("p", { class: "muted" }, "Covers every statement in this run that existed at 06:05. Statements signed later go into the next checkpoint."),
        codeBlock("mmft audit verify --checkpoint 1482")));
  }
  function runActivity() {
    return h("ol", { class: "timeline", style: "max-width:72ch" }, M.timeline.map(timelineItem));
  }
  function timelineItem(e) {
    return h("li", { class: (e.statement ? "signed" : "") + (e.warn ? " warn" : "") + (e.fresh ? " tl-new" : "") },
      h("time", {}, e.at), h("span", { class: "tl-dot", "aria-hidden": "true" }),
      h("div", {}, h("span", { class: "tl-actor" }, e.actor), " ", h("span", { class: "tl-what" }, e.what),
        e.statement ? h("div", { class: "mono muted" }, "Statement " + e.statement) : null));
  }

  // ---- The panel: one level deeper, never a second panel ------------------
  function openPanel(run, d) {
    const panel = $("panel");
    const wasOpen = !panel.hidden;
    panel.classList.remove("closing");
    panel.hidden = false;
    $("shell").classList.add("panel-open");
    if (wasOpen) panel.style.animation = "none";
    else panel.style.animation = "";
    const back = "#runs/" + run.id + "/deliveries";
    panel.replaceChildren(
      h("div", { class: "panel-head" },
        h("div", { class: "row" }, h("span", { class: "t-label-sm muted grow" }, "Delivery " + d.id),
          h("a", { class: "icon-button", href: back, "aria-label": "Close the panel" }, icon("x"))),
        h("div", { class: "row" }, h("h2", { class: "t-headline-sm grow" }, fileName(d.file))),
        h("div", { class: "row" }, chip(d.status), evidence(d.evidence))),
      h("div", { class: "panel-body" },
        d.next ? h("div", { class: "callout" }, h("div", { class: "callout-title" }, statusIcon(d.status), d.error ? h("span", { class: "mono" }, d.error) : "Next step"), h("p", { class: "muted" }, d.next)) : null,
        h("dl", { class: "facts" },
          h("dt", {}, "Route"), h("dd", {}, d.from + " → " + d.to),
          h("dt", {}, "Size"), h("dd", {}, d.size),
          h("dt", {}, "Sealed SHA-256"), h("dd", { class: "mono" }, d.evidence === "none" ? "Not sealed yet" : "9f2c4e81b07d3a65c2f1e04b98d7a3c6e15f0b2d4a8c9e7f3b1d6a0c5e2f4b81"),
          h("dt", {}, "Manifest"), h("dd", {}, d.evidence === "none" ? h("span", { class: "muted" }, "Not signed") : h("span", { class: "mono" }, "4e1a…b7c2")),
          h("dt", {}, "Receipt"), h("dd", {}, d.evidence === "verified" ? h("span", { class: "mono" }, "c93d…10fa") : h("span", { class: "muted" }, "Not signed"))),
        h("div", { style: "display:grid;gap:8px" }, h("h3", { class: "t-label-sm muted" }, "Timeline"), h("ol", { class: "timeline" }, M.timeline.map(timelineItem)))),
      h("div", { class: "panel-actions" },
        h("a", { class: "btn btn-secondary", href: back }, "Close"),
        h("button", { class: "btn btn-ghost", type: "button" }, icon("external-link"), "Open full page")));
  }
  function closePanel() {
    const panel = $("panel");
    if (panel.hidden) return;
    const reduced = document.documentElement.classList.contains("reduce-motion");
    const finish = () => { panel.hidden = true; panel.classList.remove("closing"); $("shell").classList.remove("panel-open"); };
    if (reduced || window.matchMedia("(min-width: 1600px)").matches) return finish();
    panel.classList.add("closing");
    setTimeout(finish, 130);
  }

  // ---- Flows -------------------------------------------------------------
  function flowsList(current) {
    return h("section", { class: "list-pane", "aria-label": "Flows" },
      h("div", { class: "pane-head" }, h("h1", { class: "t-headline-sm" }, "Flows"), h("span", { class: "muted t-body-sm" }, M.flows.length + " flows")),
      h("ul", { class: "list" }, M.flows.map((f) =>
        h("li", {}, h("a", { class: "list-item", href: "#flows/" + f.id, "aria-current": f.id === current ? "page" : null },
          h("span", { class: "li-icon" }, statusIcon(f.status === "approved" ? "approved" : "draft")),
          h("span", { class: "li-title" }, f.name),
          h("span", { class: "li-meta" }, "v" + f.version),
          h("span", { class: "li-sub" }, (f.draft && f.status === "approved" ? "Draft v" + f.draft.version + " waits for approval · " : "") + (f.lastRun ? "Last run " + STATUS[f.lastRun][2].toLowerCase() : "Never run")))))));
  }
  function flowItem(flow, tab) {
    tab = tab || "overview";
    const tabs = [["overview", "Overview"], ["canvas", "Canvas"], ["versions", "Versions"], ["runs", "Runs"]];
    const menu = tabBar("Flow", "#flows/" + flow.id + "/", tabs, tab);
    const head = h("div", { class: "content-head" }, h("h2", { class: "t-headline-md" }, flow.name), chip(flow.status === "approved" ? "approved" : "draft", false, "Version " + flow.version + (flow.status === "approved" ? " approved" : " draft")),
      h("div", { class: "actions" }, h("button", { class: "btn btn-primary", type: "button" }, icon("play"), "Start a run")));
    let body;
    if (tab === "canvas" && flow.tree) body = canvas(flow.tree);
    else if (tab === "canvas") body = h("div", { class: "empty" }, icon("workflow"), h("p", {}, "This flow's canvas isn't in the prototype."));
    else body = flowOverview(flow);
    return h("section", { class: "item", "aria-label": flow.name }, menu, h("div", { class: "content view-enter" }, head, body));
  }
  function flowOverview(flow) {
    const parts = [];
    if (flow.draft) {
      // The console shows what waits for approval, never an approve button.
      parts.push(h("div", { class: "callout" },
        h("div", { class: "callout-title" }, statusIcon("pending"), "Draft version " + flow.draft.version + " waits for approval, " + flow.draft.have + " of " + flow.draft.need),
        h("p", { class: "muted" }, flow.draft.change + "." + (flow.draft.approvedBy.length ? " Approved so far by " + flow.draft.approvedBy.join(", ") + "." : "")),
        h("p", {}, "Approval happens in the signed CLI. An administrator runs:"),
        codeBlock("mmft flow approve " + flow.name + " --version " + flow.draft.version)));
    }
    if (flow.status === "approved") {
      parts.push(h("dl", { class: "facts", style: "max-width:72ch" },
        h("dt", {}, "Running version"), h("dd", {}, String(flow.version)),
        h("dt", {}, "Approved by"), h("dd", {}, flow.approvals.map((a) => a.by + " at " + a.at).join(", ")),
        h("dt", {}, "Last run"), h("dd", {}, flow.lastRun ? chip(flow.lastRun) : "Never run")));
    }
    return h("div", { style: "display:grid;gap:24px" }, parts);
  }
  function card(kind, ic, title, detail, extra) {
    return h("div", { class: "card" + (kind === "On failure" ? " failure" : ""), tabindex: "0" },
      h("span", { class: "card-kind t-label-sm" }, icon(ic), kind), h("span", { class: "card-title" }, title), detail ? h("span", { class: "card-detail" }, detail) : null, extra || null);
  }
  function canvas(t) {
    return h("div", { class: "canvas", role: "group", "aria-label": "Flow tree" },
      h("div", { class: "spine" },
        card("Trigger", "calendar-clock", t.trigger.title, t.trigger.detail),
        card("Source", "folder-output", t.source.title, t.source.detail, h("span", { class: "mono muted" }, t.source.match))),
      h("div", { class: "paths" }, t.paths.map((p, i) =>
        h("div", { class: "path" },
          h("div", { class: "path-rule" }, h("span", { class: "t-label-sm muted" }, "Path " + (i + 1)), h("span", { class: "t-body-md-strong" }, p.label), h("code", {}, p.when)),
          h("div", { class: "path-cards" },
            p.destinations.map((d) => card("Destination", "folder-input", d.title, d.detail, h("span", { class: "card-detail" }, "One delivery per file"))),
            p.outcome ? card("Outcome", "archive", p.outcome) : null,
            p.failure ? card("On failure", "triangle-alert", p.failure) : null)))),
      h("p", { class: "muted", style: "grid-column:1/-1" }, t.unmatched));
  }

  // ---- Agents ------------------------------------------------------------
  function agentsList(current) {
    return h("section", { class: "list-pane", "aria-label": "Agents" },
      h("div", { class: "pane-head" }, h("h1", { class: "t-headline-sm" }, "Agents"), h("span", { class: "muted t-body-sm" }, M.agents.length + " agents")),
      h("ul", { class: "list" }, M.agents.map((a) =>
        h("li", {}, h("a", { class: "list-item", href: "#agents/" + a.id, "aria-current": a.id === current ? "page" : null },
          h("span", { class: "li-icon" }, statusIcon(a.status)),
          h("span", { class: "li-title" }, a.name),
          h("span", { class: "li-meta" }, a.version),
          h("span", { class: "li-sub" }, STATUS[a.status][2] + " · seen " + a.seen))))));
  }
  function agentItem(agent, tab) {
    tab = tab || "overview";
    const tabs = [["overview", "Overview"], ["deliveries", "Deliveries"], ["identity", "Identity"], ["activity", "Activity"]];
    const menu = tabBar("Agent", "#agents/" + agent.id + "/", tabs, tab);
    const parts = [];
    if (agent.status === "pending") {
      parts.push(h("div", { class: "callout" },
        h("div", { class: "callout-title" }, statusIcon("pending"), "This agent waits for approval"),
        h("p", { class: "muted" }, "Compare its fingerprint with the one collected from its host, then approve it in the signed CLI:"),
        codeBlock("mmft agent approve --fingerprints collected.json")));
    }
    parts.push(h("dl", { class: "facts", style: "max-width:72ch" },
      h("dt", {}, "Status"), h("dd", {}, chip(agent.status)),
      h("dt", {}, "Version"), h("dd", {}, agent.version),
      h("dt", {}, "Last seen"), h("dd", {}, agent.seen),
      h("dt", {}, "Identity expires"), h("dd", {}, agent.expires || h("span", { class: "muted" }, "No identity yet")),
      h("dt", {}, "Fingerprint"), h("dd", { class: "mono" }, agent.fingerprint)));
    return h("section", { class: "item", "aria-label": agent.name }, menu,
      h("div", { class: "content view-enter" }, h("div", { class: "content-head" }, h("h2", { class: "t-headline-md" }, agent.name), chip(agent.status)), parts));
  }

  // ---- Component sheet ---------------------------------------------------
  function sheet() {
    const steps = [["Base", "surface-base"], ["Recessed", "surface-recessed"], ["Card", "surface-card"], ["Hover", "surface-hover"], ["Selected", "surface-selected"], ["Floating", "surface-floating"]];
    const section = (title, ...kids) => h("section", {}, h("h2", { class: "t-headline-sm" }, title), ...kids);
    return h("div", { class: "sheet view-enter" },
      h("h1", { class: "t-headline-md" }, "Component sheet"),
      h("p", { class: "muted", style: "max-width:72ch" }, "Every part of the console, built only from design/DESIGN.md's tokens. Change a token there, run tokens.sh, and this page follows."),
      section("Surface ladder", h("div", { class: "ladder" }, steps.map(([l, t], i) => { const d = h("div", {}, h("span", { class: "t-body-md-strong" }, i + " · " + l), h("small", { class: "mono" }, "--color-" + t)); d.style.background = "var(--color-" + t + ")"; return d; }))),
      section("Buttons", h("div", { class: "row" },
        h("button", { class: "btn btn-primary", type: "button" }, icon("play"), "Primary, once per screen"),
        h("button", { class: "btn btn-secondary", type: "button" }, "Secondary"),
        h("button", { class: "btn btn-ghost", type: "button" }, icon("external-link"), "Ghost"),
        h("button", { class: "btn", type: "button", disabled: true }, "Disabled"))),
      section("Status", h("div", { class: "row" }, ["succeeded", "failed", "retry_wait", "partial_failure", "transferring", "pending", "cancelled"].map((s) => chip(s)))),
      section("Evidence", h("div", { class: "row", style: "gap:24px" }, evidence("verified"), evidence("source_only"), evidence("none"))),
      section("Type", h("div", { style: "display:grid;gap:6px" },
        h("span", { class: "t-label-sm muted" }, "label-sm · 11 px"), h("span", { class: "t-body-sm" }, "body-sm · 12 px metadata"),
        h("span", { class: "t-body-md" }, "body-md · 13 px interface and table text"), h("span", { class: "t-headline-sm" }, "headline-sm · 16 px section"),
        h("span", { class: "t-headline-md" }, "headline-md · 20 px page"), h("span", { class: "t-display-sm" }, "display-sm · 24 px 1,482"),
        h("span", { class: "t-code-md" }, "code-md · 0190f9c3-41aa-7c55 9f2c4e81…4b81"))),
      section("Fields", h("div", { class: "row", style: "align-items:start;gap:24px" },
        h("label", { class: "field" }, h("span", {}, "Flow name"), h("input", { class: "input", id: "sheet-name", value: "invoices-daily" }), h("small", {}, "Letters, digits, dots, and hyphens.")),
        h("label", { class: "field invalid" }, h("span", {}, "Schedule"), h("input", { class: "input", id: "sheet-cron", value: "every day at 25:00" }), h("small", {}, "25:00 isn't a time of day. Use 00:00 to 23:59.")))),
      section("Code block", h("div", { style: "max-width:72ch" }, codeBlock("mmft flow approve invoices-daily --version 5"))),
      section("Tooltip and empty state", h("div", { class: "row", style: "align-items:start;gap:24px" },
        h("span", { class: "tooltip" }, "Manifest and receipt signed"),
        h("div", { class: "empty", style: "width:360px" }, icon("inbox"), h("span", { class: "t-body-md-strong" }, "No runs yet"), h("span", { class: "muted" }, "Runs appear here when a flow's trigger fires, or when you start one.")))));
  }

  function simple(title, text) {
    return h("div", { class: "sheet view-enter" }, h("h1", { class: "t-headline-md" }, title), h("div", { class: "empty" }, icon("construction"), h("p", { class: "muted" }, text)));
  }

  // ---- Render --------------------------------------------------------------
  function render() {
    const r = parse();
    renderNav(r);
    let view;
    let panelFor = null;
    if (r.section === "runs") {
      const run = runById(r.id) || M.runs[0];
      const tab = r.tab || "deliveries";
      view = h("div", { class: "master" }, runsList(run.id), runItem(run, tab, r.sub));
      const d = r.sub && run.deliveries.find((x) => x.id === r.sub);
      if (d) panelFor = [run, d];
    } else if (r.section === "flows") {
      const flow = flowById(r.id) || M.flows[0];
      view = h("div", { class: "master" }, flowsList(flow.id), flowItem(flow, r.tab));
    } else if (r.section === "agents") {
      const agent = agentById(r.id) || M.agents[0];
      view = h("div", { class: "master" }, agentsList(agent.id), agentItem(agent, r.tab));
    } else if (r.section === "components") {
      view = sheet();
    } else if (r.section === "audit") {
      view = simple("Audit", "Checkpoints and the audit trail export come with M2.");
    } else {
      view = simple("Settings", "Users, roles, and API tokens come with M3. Reduce motion is in the account menu.");
    }
    const focusedKey = document.activeElement && document.activeElement.dataset && document.activeElement.dataset.key;
    $("view").replaceChildren(view);
    if (focusedKey) { const again = $("view").querySelector('[data-key="' + focusedKey + '"]'); if (again) again.focus(); }
    if (panelFor) openPanel(...panelFor); else closePanel();
    // Changed marks animate once, then settle.
    M.runs.forEach((run) => run.deliveries.forEach((d) => { d.changed = false; }));
  }

  // ---- Live parts: what just changed ---------------------------------------
  function live() {
    const run = M.runs[0];
    const d06 = run.deliveries.find((d) => d.id === "d06");
    let left = 4;
    const countdown = setInterval(() => {
      left--;
      d06.next = left > 0 ? "Next attempt in " + left + " s, attempt 2 of 5" : "Attempt 2 of 5 started";
      if (left <= 0) {
        clearInterval(countdown);
        setTimeout(() => {
          d06.status = "succeeded"; d06.evidence = "verified"; d06.error = null; d06.next = null; d06.changed = true;
          M.timeline.push({ at: "06:08:11.204", actor: "archive-03", what: "Resumed, checked the hash, placed the file, and signed the receipt", statement: "c93d…10fa", fresh: true });
          render();
        }, 1500);
      }
    }, 1000);
    const payroll = M.runs[1].deliveries[0];
    const grow = setInterval(() => {
      payroll.progress = Math.min(1, payroll.progress + 0.07);
      const bar = document.querySelector("#progress-" + payroll.id + " span");
      if (bar) bar.style.width = Math.round(payroll.progress * 100) + "%";
      if (payroll.progress >= 1) {
        clearInterval(grow);
        payroll.status = "succeeded"; payroll.evidence = "verified"; payroll.changed = true;
        M.runs[1].status = "succeeded"; M.runs[1].duration = "6 min 12 s";
        render();
      }
    }, 1500);
  }

  // ---- Chrome: workspace, connections, alerts, user menu, palette ----------
  function chrome() {
    document.querySelector(".workspace-name").textContent = M.workspace;
    $("conn").replaceChildren(
      h("span", { title: "Orchestrator connected" }, h("span", { class: "dot" }), "Orchestrator"),
      h("span", { title: "Relay connected" }, h("span", { class: "dot" }), "Relay"));
    $("alert-count").textContent = String(M.alerts);
    $("alerts").setAttribute("aria-label", M.alerts + " alerts");

    const menu = $("user-menu");
    const btn = $("user-button");
    const toggleMenu = (open) => { menu.hidden = !open; btn.setAttribute("aria-expanded", String(open)); };
    btn.addEventListener("click", (e) => { e.stopPropagation(); toggleMenu(menu.hidden); });
    document.addEventListener("click", (e) => { if (!menu.hidden && !menu.contains(e.target)) toggleMenu(false); });

    // Reduce motion follows the operating system unless the user chose.
    const box = $("reduce-motion");
    let stored = null;
    try { stored = localStorage.getItem("mmft-reduce-motion"); } catch (e) {}
    const reduced = stored == null ? window.matchMedia("(prefers-reduced-motion: reduce)").matches : stored === "1";
    document.documentElement.classList.toggle("reduce-motion", reduced);
    box.checked = reduced;
    box.addEventListener("change", () => {
      document.documentElement.classList.toggle("reduce-motion", box.checked);
      try { localStorage.setItem("mmft-reduce-motion", box.checked ? "1" : "0"); } catch (e) {}
    });

    // The command palette jumps to any flow, run, agent, or delivery.
    const items = [
      ...M.flows.map((f) => [f.name, "Flow", "#flows/" + f.id]),
      ...M.runs.map((r) => [flowById(r.flow).name + " " + shortId(r.id), "Run", "#runs/" + r.id]),
      ...M.agents.map((a) => [a.name, "Agent", "#agents/" + a.id]),
      ...M.runs.flatMap((r) => r.deliveries.map((d) => [(d.file || "Delivery " + d.id) + " → " + d.to, "Delivery", "#runs/" + r.id + "/deliveries/" + d.id])),
    ];
    const palette = $("palette");
    const input = $("palette-input");
    const results = $("palette-results");
    let sel = 0;
    let shown = [];
    const draw = () => {
      const q = input.value.trim().toLowerCase();
      shown = items.filter(([t, k]) => !q || t.toLowerCase().includes(q) || k.toLowerCase().includes(q)).slice(0, 12);
      sel = Math.min(sel, Math.max(0, shown.length - 1));
      results.replaceChildren(...shown.map(([t, k, href], i) =>
        h("li", { role: "option" }, h("a", { href, "aria-selected": String(i === sel), onclick: () => close() }, h("span", {}, t), h("small", {}, k)))));
    };
    const open = () => { palette.hidden = false; input.value = ""; sel = 0; draw(); input.focus(); };
    const close = () => { palette.hidden = true; };
    if (/Mac|iPhone|iPad/.test(navigator.platform)) $("palette-key").textContent = "⌘ K";
    $("open-palette").addEventListener("click", open);
    palette.addEventListener("click", (e) => { if (e.target === palette) close(); });
    input.addEventListener("input", () => { sel = 0; draw(); });
    input.addEventListener("keydown", (e) => {
      if (e.key === "ArrowDown") { sel = Math.min(sel + 1, shown.length - 1); draw(); e.preventDefault(); }
      if (e.key === "ArrowUp") { sel = Math.max(sel - 1, 0); draw(); e.preventDefault(); }
      if (e.key === "Enter" && shown[sel]) { location.hash = shown[sel][2]; close(); }
    });
    document.addEventListener("keydown", (e) => {
      if ((e.metaKey || e.ctrlKey) && e.key.toLowerCase() === "k") { e.preventDefault(); palette.hidden ? open() : close(); }
      if (e.key === "Escape") {
        if (!palette.hidden) close();
        else if (!menu.hidden) toggleMenu(false);
        else if (!$("panel").hidden) { const r = parse(); location.hash = "#runs/" + r.id + "/deliveries"; }
      }
    });
  }

  chrome();
  if (window.lucide) window.lucide.createIcons();
  window.addEventListener("hashchange", render);
  render();
  live();
})();
