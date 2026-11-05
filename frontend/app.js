/* VULNIGO Lite command centre. Talks only to the backend (REST + SSE); never to a model. */
(function () {
  const $ = (s) => document.querySelector(s);
  const S = { runId: null, kind: null, mode: null, side: null, snap: null, candidates: [], es: null, count: 0, reportShown: false };
  let scene = null;

  // ------------------------------------------------------------ helpers
  function el(tag, attrs = {}, ...kids) {
    const n = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "class") n.className = v;
      else if (k.startsWith("on")) n.addEventListener(k.slice(2), v);
      else if (v !== null && v !== undefined && v !== false) n.setAttribute(k, v === true ? "" : v);
    }
    for (const k of kids.flat()) if (k !== null && k !== undefined && k !== false) n.append(k.nodeType ? k : String(k));
    return n;
  }
  // replaceChildren() renders null as the text "null"; drop empty slots first.
  const kidsOf = (...k) => k.flat().filter((x) => x !== null && x !== undefined && x !== false);
  async function api(method, path, body) {
    const r = await fetch(path, { method, headers: { "Content-Type": "application/json" }, body: body ? JSON.stringify(body) : undefined });
    const data = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(data.detail ? (typeof data.detail === "string" ? data.detail : JSON.stringify(data.detail)) : r.statusText);
    return data;
  }
  const base = () => (S.kind === "check" ? "/repo-checks/" : "/battles/") + S.runId;
  function diffView(diff) {
    const pre = el("pre", { class: "diff" });
    for (const line of (diff || "").split("\n")) {
      const cls = line.startsWith("+") && !line.startsWith("+++") ? "add" : line.startsWith("-") && !line.startsWith("---") ? "del" : line.startsWith("@@") ? "hunk" : null;
      pre.append(cls ? el("span", { class: cls }, line) : line + "\n");
    }
    return pre;
  }

  // ------------------------------------------------------------ start screen
  async function loadConfig() {
    try {
      const h = await api("GET", "/health");
      const sb = $("#chip-sandbox"), lm = $("#chip-llm");
      sb.textContent = h.sandbox ? "SANDBOX READY" : "SANDBOX OFFLINE"; sb.className = "chip " + (h.sandbox ? "ok" : "bad");
      lm.textContent = h.llm ? "VULTR INFERENCE" : "FALLBACK AGENTS"; lm.className = "chip " + (h.llm ? "ok" : "bad");
      lm.title = h.llm ? "Agents use Vultr Serverless Inference" : "No inference key: agents run a clearly labelled deterministic fallback";
    } catch (e) { /* backend down */ }
  }
  document.querySelectorAll("input[name=repo]").forEach((r) => r.addEventListener("change", () => {
    $("#repo-url").disabled = document.querySelector("input[name=repo]:checked").value !== "url";
  }));
  document.querySelectorAll(".mode").forEach((b) => b.addEventListener("click", () => start(b.dataset.mode)));

  async function start(choice) {
    $("#start-error").textContent = "";
    const useUrl = document.querySelector("input[name=repo]:checked").value === "url";
    const repo_url = useUrl ? $("#repo-url").value.trim() : null;
    if (useUrl && !repo_url) { $("#start-error").textContent = "Enter a GitHub URL or pick the demo repo."; return; }
    try {
      if (choice === "check") {
        S.kind = "check"; S.mode = "repo_check"; S.side = null;
        S.runId = (await api("POST", "/repo-checks", { repo_url })).id;
      } else {
        S.kind = "battle"; S.mode = choice === "spectator" ? "spectator" : "participate";
        S.side = choice === "spectator" ? null : choice;
        S.runId = (await api("POST", "/battles", { repo_url, mode: S.mode, side: S.side })).id;
      }
    } catch (e) { $("#start-error").textContent = e.message; return; }
    history.replaceState(null, "", "#" + S.kind + ":" + S.runId);
    enterArena();
  }

  function enterArena() {
    $("#start").hidden = true; $("#arena").hidden = false; $("#btn-new").hidden = false;
    if (!scene) scene = new window.VG.Scene($("#stage"), $("#bubbles"));
    $("#btn-backup").hidden = S.mode !== "participate";
    $("#chat-card").hidden = S.kind === "check";
    $("#chat-input").placeholder = S.side ? `Suggest something to the ${S.side.toUpperCase()} Agent...` : "Comment (spectators observe; teams act)";
    if (S.kind === "check") { scene.agents.red.tx = -40; scene.agents.blue.tx = 520; }
    connect();
    refresh();
  }
  $("#btn-new").addEventListener("click", () => { history.replaceState(null, "", "/"); location.reload(); });

  // ------------------------------------------------------------ live events
  function connect() {
    if (S.es) S.es.close();
    S.es = new EventSource(base() + "/events");
    S.es.onmessage = (m) => handle(JSON.parse(m.data));
  }
  let refreshTimer = null;
  function refreshSoon() { clearTimeout(refreshTimer); refreshTimer = setTimeout(refresh, 250); }
  async function refresh() {
    try { S.snap = await api("GET", base()); } catch (e) { return; }
    renderMeta(); renderPointers();
    if (S.snap.report && !S.reportShown && S.snap.status && isTerminal(S.snap.status)) showReport(S.snap.report);
  }
  const TERMINAL = ["FAILED", "ATTACK_INCONCLUSIVE", "NO_CONFIRMED_FINDING", "DEFENSE_INCONCLUSIVE", "PATCH_REJECTED",
    "PATCH_FAILED", "COMPLETED", "UNRESOLVED", "INCONCLUSIVE", "CHECK_COMPLETED", "CHECK_INCONCLUSIVE"];
  const isTerminal = (s) => TERMINAL.includes(s);

  function handle(e) {
    const d = e.data || {};
    if (e.state) { $("#chip-state").textContent = e.state.replaceAll("_", " "); }
    if (e.round) setRound(e.round, e.state);
    switch (e.type) {
      case "agent_status":
        scene.setStatus(e.agent, d.status);
        if (/sandbox|proof|regression|retest/i.test(e.message) && d.status === "running") scene.sandbox("running");
        return; // statuses are not shown in the feed
      case "state":
        refreshSoon(); break;
      case "test":
        scene.sandbox(e.ok ? "idle" : "idle");
        scene.verdict = { text: e.message.split(":")[1] ? e.message.split(":")[1].split("[")[0].trim().slice(0, 22).toUpperCase() : "", color: e.ok ? "#7be0aa" : "#f2c464" };
        if (d.checks) renderContainment(d);
        scene.say(e.agent === "human" ? (S.side || "manager") : e.agent, e.message);
        refreshSoon(); break;
      case "claim": case "chat": case "backup": case "info": case "finding": case "patch": case "error":
        if (e.agent === "backup") scene.addBackup(d.side || S.side);
        if (e.agent !== "human") scene.say(e.agent, e.message);
        if (d.candidates) S.candidates = d.candidates;
        if (e.type === "finding" || e.type === "patch") refreshSoon();
        break;
      case "human_turn":
        renderTurn(d.what, e.message); break;
      case "approval_request":
        renderApproval(d.patch_id, d.diff); scene.say("manager", "Patch ready. Nothing changes until you approve."); break;
      case "approval":
        $("#approval").hidden = true; break;
      case "pointer": case "pointer_decision":
        refreshSoon(); break;
      case "report":
        refresh().then(() => S.snap && S.snap.report && showReport(S.snap.report)); break;
      case "done":
        $("#turn").hidden = true; $("#approval").hidden = true; scene.sandbox("idle"); break;
    }
    addFeed(e);
  }

  function addFeed(e) {
    const d = e.data || {};
    const label = d.label ? el("span", { class: "label" + (/FALLBACK/.test(d.label) ? " fallback" : "") }, d.label) : null;
    const li = el("li", { class: `${e.agent} ${e.type === "state" ? "state" : ""} ${e.ok === 1 ? "ok-1" : e.ok === 0 ? "ok-0" : ""}` },
      el("span", { class: "who" }, (e.agent || "").toUpperCase()), e.message, label);
    if (d.next_step) li.append(el("div", { class: "muted small" }, "Next: " + d.next_step));
    if (d.output && e.type === "test") {
      const det = el("details", {}, el("summary", { class: "muted small" }, "output"), el("pre", { class: "code" }, d.output));
      li.append(det);
    }
    const feed = $("#feed");
    feed.append(li); feed.scrollTop = feed.scrollHeight;
    $("#feed-count").textContent = ++S.count + " events";
  }

  function setRound(r, state) {
    const order = ["setup", "attack", "defense", "report"];
    const i = order.indexOf(r);
    document.querySelectorAll("#round-bar span").forEach((s) => {
      const j = order.indexOf(s.dataset.r);
      s.className = j === i ? "on" : j < i ? "done" : "";
    });
  }

  // ------------------------------------------------------------ panels
  function renderMeta() {
    const s = S.snap; if (!s) return;
    const dl = el("dl", {},
      el("dt", {}, "Run"), el("dd", {}, s.id),
      el("dt", {}, "Repo"), el("dd", {}, s.repo_label || "-"),
      el("dt", {}, "Commit"), el("dd", {}, s.commit_hash || "pending"),
      el("dt", {}, "Mode"), el("dd", {}, s.mode + (s.side ? ` (${s.side.toUpperCase()} team)` : "")),
      el("dt", {}, "State"), el("dd", {}, s.status),
      el("dt", {}, "Findings"), el("dd", {}, s.findings.map((f) => `${f.status} @ ${f.file}:${f.line_start}`).join(", ") || "none yet"),
      el("dt", {}, "Backup"), el("dd", {}, s.backup.length ? s.backup.join(", ") + " team" : "-"));
    $("#meta").replaceChildren(el("div", { class: "card-head" }, el("h3", {}, S.kind === "check" ? "Repo Check" : "Battle")), dl);
  }

  function renderPointers() {
    const pts = (S.snap && S.snap.pointers) || [];
    $("#pointers-card").hidden = !pts.length;
    $("#pointers").replaceChildren(...pts.map((p) => el("li", { class: p.decision },
      p.text, el("div", { class: "muted small" }, "evidence: " + (p.evidence_ref || "-")),
      p.decision === "pending" ? el("div", { class: "row" },
        el("button", { class: "btn green small", onclick: () => decidePointer(p.id, "approved") }, "Approve"),
        el("button", { class: "btn ghost small", onclick: () => decidePointer(p.id, "dismissed") }, "Dismiss"))
        : el("div", { class: "muted small" }, p.decision))));
  }
  async function decidePointer(id, decision) {
    try { await api("POST", `${base()}/pointers/${id}`, { decision }); refresh(); } catch (e) { alert(e.message); }
  }

  function renderContainment(d) {
    const box = $("#containment"); box.hidden = false;
    const rows = d.checks.map((c) => el("tr", {}, el("td", {}, c.check),
      el("td", { class: c.blocked ? "blocked" : "open" }, c.blocked ? "BLOCKED" : "ALLOWED"),
      el("td", { class: "muted small" }, c.detail)));
    box.replaceChildren(el("h2", {}, "Containment moment"),
      el("p", { class: "muted small" }, "Before any repo code runs, a probe inside the sandbox tries to escape. Every attempt below happened for real."),
      el("table", {}, ...rows));
  }

  function renderTurn(what, prompt) {
    const box = $("#turn"); box.hidden = false; box.className = "card " + (S.side || "");
    const done = async (payload) => {
      try { await api("POST", `${base()}/actions`, payload); box.hidden = true; } catch (e) { alert(e.message); }
    };
    if (what === "red_attack") {
      const sel = el("select", { class: "input" }, ...S.candidates.map((c) => el("option", { value: c.i }, `[${c.i}] ${c.file}:${c.line} ${c.function}() - ${c.flow}`)));
      const hyp = el("input", { class: "input", placeholder: "Your hypothesis (optional)", maxlength: 500 });
      const pay = el("input", { class: "input", placeholder: "Payload, e.g.  x; echo PWNED > /tmp/vulnigo_proof #", maxlength: 300 });
      box.replaceChildren(el("h2", {}, "Your move - Red team"), el("p", { class: "muted" }, prompt),
        el("div", { class: "form-grid" }, el("label", { class: "small muted" }, "Target candidate"), sel, hyp, pay,
          el("p", { class: "hint" }, "Your payload runs inside the no-network sandbox. It counts only if it makes the target write to /tmp/vulnigo_proof.")),
        el("div", { class: "btn-row" },
          el("button", { class: "btn red", onclick: () => done({ candidate_index: +sel.value, hypothesis: hyp.value || null, payload: pay.value || null }) }, "Run my attack"),
          el("button", { class: "btn ghost", onclick: () => done({ proceed: true }) }, "Let Red Agent proceed")));
    } else if (what === "red_retest") {
      const pay = el("input", { class: "input", placeholder: "Try another payload against the patched copy", maxlength: 300 });
      box.replaceChildren(el("h2", {}, "Retest - Red team"), el("p", { class: "muted" }, prompt), pay,
        el("div", { class: "btn-row" },
          el("button", { class: "btn red", onclick: () => done({ payload: pay.value || null }) }, "Retry attack"),
          el("button", { class: "btn ghost", onclick: () => done({ proceed: true }) }, "Skip")));
    } else if (what === "blue_patch") {
      const f = (S.snap && S.snap.findings || [])[0];
      const snippet = f && f.data ? f.data.snippet : "";
      const first = f && f.data ? f.data.fn_line : 1;
      const lines = snippet.split("\n");
      const numbered = lines.map((l, i) => String(first + i).padStart(4) + " | " + l).join("\n");
      const ls = el("input", { class: "input", type: "number", value: f ? f.line_start : "" });
      const le = el("input", { class: "input", type: "number", value: f ? f.line_end : "" });
      const pre = f ? lines.slice(f.line_start - first, f.line_end - first + 1).join("\n") : "";
      const rep = el("textarea", {}, pre);
      const sug = el("input", { class: "input", placeholder: "Or just suggest an approach to the Blue Agent", maxlength: 500 });
      box.replaceChildren(el("h2", {}, "Your move - Blue team"), el("p", { class: "muted" }, prompt),
        f ? el("p", { class: "small" }, `Confirmed: ${f.hypothesis}`) : null,
        el("pre", { class: "code" }, numbered),
        el("div", { class: "form-grid" }, el("label", { class: "small muted" }, "Replace lines (inclusive)"),
          el("div", { style: "display:flex;gap:8px" }, ls, le), rep, sug),
        el("div", { class: "btn-row" },
          el("button", { class: "btn", onclick: () => done({ line_start: +ls.value, line_end: +le.value, replacement: rep.value, suggestion: sug.value || null }) }, "Submit my patch"),
          el("button", { class: "btn ghost", onclick: () => done({ suggestion: sug.value || null, proceed: true }) }, "Let Blue Agent propose")));
    }
    box.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  function renderApproval(patchId, diff) {
    const box = $("#approval"); box.hidden = false;
    const note = el("input", { class: "input", placeholder: "Decision note (optional)", maxlength: 500 });
    const send = async (decision) => {
      try { await api("POST", `${base()}/approvals`, { patch_id: patchId, decision, note: note.value }); box.hidden = true; }
      catch (e) { alert(e.message); }
    };
    box.replaceChildren(el("h2", {}, "Approval gate - patch " + patchId),
      el("p", { class: "muted small" }, "Review the diff. It is applied to the sandbox working copy only, and only after you approve. Then the original attack is re-run."),
      diffView(diff), note,
      el("div", { class: "btn-row" },
        el("button", { class: "btn green", onclick: () => send("approved") }, "Approve & retest"),
        el("button", { class: "btn warn", onclick: () => send("changes_requested") }, "Request changes"),
        el("button", { class: "btn red", onclick: () => send("rejected") }, "Reject")));
    box.scrollIntoView({ behavior: "smooth", block: "nearest" });
  }

  // ------------------------------------------------------------ chat & backup
  $("#chat-form").addEventListener("submit", async (ev) => {
    ev.preventDefault();
    const t = $("#chat-input").value.trim(); if (!t) return;
    $("#chat-input").value = "";
    try { await api("POST", `${base()}/messages`, { text: t }); } catch (e) { alert(e.message); }
  });
  $("#btn-backup").addEventListener("click", async () => {
    try { await api("POST", `${base()}/backup`); scene.addBackup(S.side); } catch (e) { alert(e.message); }
  });

  // ------------------------------------------------------------ report
  function showReport(r) {
    S.reportShown = true;
    if (r.scores) scene.score = { red: r.scores.red.total, blue: r.scores.blue.total };
    const body = $("#report");
    const close = el("button", { class: "btn ghost small", onclick: () => ($("#report-modal").hidden = true) }, "Close");
    if (r.kind === "repo_check") {
      const items = [...r.malicious, ...r.vulnerabilities];
      body.replaceChildren(...kidsOf(el("div", { class: "card-head" }, el("h2", {}, "Repo Check report"), close),
        el("p", {}, `${r.repository} @ ${r.commit_hash}`),
        el("div", { class: "outcome " + (items.length ? "meh" : "good") }, r.verdict),
        r.manager_summary ? el("p", {}, r.manager_summary) : null,
        el("p", { class: "muted small" }, `${r.files_scanned} files scanned. Code executed: no.`),
        items.length ? el("table", { class: "tbl" }, el("tr", {}, ...["Grade", "Kind", "Location", "Why", "Snippet"].map((h) => el("th", {}, h))),
          ...items.map((f) => el("tr", {}, el("td", {}, f.grade), el("td", {}, `${f.kind} (${f.severity})`),
            el("td", {}, `${f.file}:${f.line_start}`), el("td", {}, f.explanation + (f.assessment ? " - " + f.assessment : "")),
            el("td", {}, el("code", {}, f.snippet))))) : null,
        el("p", { class: "disclaimer" }, r.disclaimer)));
    } else {
      const cls = r.final_state === "COMPLETED" ? "good" : ["UNRESOLVED", "FAILED", "PATCH_FAILED"].includes(r.final_state) ? "bad" : "meh";
      const scoreBox = (team) => el("div", { class: "score " + team }, el("h3", {}, team.toUpperCase() + " TEAM"),
        el("div", { class: "big" }, r.scores[team].total),
        el("ul", {}, ...r.scores[team].lines.map((l) => el("li", {}, `${l.points > 0 ? "+" : ""}${l.points} ${l.why} `, el("span", { class: "muted" }, `[${l.evidence || "-"}]`)))));
      body.replaceChildren(...kidsOf(el("div", { class: "card-head" }, el("h2", {}, "Battle report"), close),
        el("p", {}, `${r.repository} @ ${r.commit_hash || "-"}`),
        el("div", { class: "outcome " + cls }, r.outcome),
        r.manager_summary && r.manager_summary.text ? el("p", {}, r.manager_summary.text, el("span", { class: "label" + (/FALLBACK/.test(r.manager_summary.label) ? " fallback" : "") }, r.manager_summary.label)) : null,
        el("div", { class: "scores" }, scoreBox("red"), scoreBox("blue")),
        el("h3", { style: "margin-top:16px" }, "Findings"),
        el("table", { class: "tbl" }, el("tr", {}, ...["Status", "Location", "Hypothesis", "Evidence"].map((h) => el("th", {}, h))),
          ...r.findings.map((f) => el("tr", {}, el("td", {}, f.status), el("td", {}, `${f.file}:${f.lines.join("-")}`),
            el("td", {}, f.hypothesis), el("td", {}, f.evidence)))),
        ...r.patches.map((p) => el("div", {}, el("h3", {}, `Patch ${p.id} by ${p.author} - ${p.approval}`), diffView(p.diff))),
        el("h3", {}, "Test runs"),
        el("table", { class: "tbl" }, el("tr", {}, ...["Id", "Test", "Outcome", "Where"].map((h) => el("th", {}, h))),
          ...r.test_runs.map((t) => el("tr", {}, el("td", {}, t.id), el("td", {}, t.label || t.kind),
            el("td", {}, el("span", { class: "pill " + t.outcome }, t.outcome)),
            el("td", {}, t.sandboxed ? `sandbox ${t.env}` : t.env === "UNSANDBOXED-DEV" ? "UNSANDBOXED DEV" : "not run")))),
        r.unresolved.length ? el("div", {}, el("h3", {}, "Unresolved"), el("ul", {}, ...r.unresolved.map((u) => el("li", {}, u)))) : null,
        el("p", { class: "disclaimer" }, r.disclaimer)));
    }
    $("#report-modal").hidden = false;
  }

  // ------------------------------------------------------------ boot
  loadConfig();
  const m = location.hash.match(/^#(battle|check):(\w+)$/);
  if (m) { S.kind = m[1]; S.runId = m[2]; api("GET", base()).then((s) => { S.mode = s.mode; S.side = s.side; enterArena(); }).catch(() => {}); }
})();
