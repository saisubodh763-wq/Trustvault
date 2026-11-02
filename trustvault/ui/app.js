"use strict";
// All rendering uses textContent / createElement, never innerHTML: file names,
// categories and e-mail addresses are attacker-controlled strings.
(function () {
  const app = document.getElementById("app");
  let me = null, csrf = null;

  function h(tag, attrs, ...kids) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (k === "on") for (const [ev, fn] of Object.entries(v)) el.addEventListener(ev, fn);
      else if (k === "class") el.className = v;
      else if (v === true) el.setAttribute(k, "");
      else if (v !== false && v != null) el.setAttribute(k, v);
    }
    for (const kid of kids.flat()) if (kid != null && kid !== false) el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
    return el;
  }
  function toast(msg) {
    const t = document.getElementById("toast");
    t.textContent = msg; t.classList.add("show");
    setTimeout(() => t.classList.remove("show"), 3500);
  }
  async function api(method, url, body, isForm) {
    const opts = { method, headers: {}, credentials: "same-origin" };
    if (csrf && method !== "GET") opts.headers["X-CSRF-Token"] = csrf;
    if (body && !isForm) { opts.headers["Content-Type"] = "application/json"; opts.body = JSON.stringify(body); }
    if (body && isForm) opts.body = body;
    const res = await fetch(url, opts);
    let data = null;
    try { data = await res.json(); } catch (_) { /* not JSON */ }
    if (res.status === 401 && me) { me = null; csrf = null; render(); throw new Error("Signed out"); }
    if (!res.ok) throw new Error((data && data.error) || ("Error " + res.status));
    return data;
  }
  const act = (fn) => async (...a) => { try { await fn(...a); } catch (e) { toast(e.message); } };
  const qs = (o) => new URLSearchParams(Object.entries(o).filter(([, v]) => v)).toString();
  const when = (s) => (s ? s.replace("T", " ").replace("Z", " UTC") : "—");

  // ------------------------------------------------------------ chrome
  function chrome(active) {
    const bar = document.getElementById("bar"), nav = document.getElementById("nav");
    bar.hidden = !me; nav.replaceChildren();
    if (!me) return;
    const tabs = me.role === "admin"
      ? [["alerts", "Alerts"], ["audit", "Audit"], ["users", "Users"], ["admindocs", "Documents"]]
      : [["docs", "Documents"], ...(me.role === "owner" ? [["upload", "Upload"], ["trash", "Trash"]] : [])];
    for (const [id, label] of tabs)
      nav.append(h("button", { "aria-current": active === id ? "page" : null, on: { click: () => go(id) } }, label));
    document.getElementById("who").replaceChildren(me.email + " ", h("span", { class: "tag" }, me.role), " ",
      h("button", { on: { click: act(async () => { await api("POST", "/api/auth/logout"); me = csrf = null; render(); }) } }, "Sign out"));
  }
  function go(view, arg) { chrome(view); (views[view] || views.docs)(arg); }

  // ------------------------------------------------------------ login
  function loginView() {
    const email = h("input", { type: "email", required: true, autocomplete: "username" });
    const pw = h("input", { type: "password", required: true, autocomplete: "current-password" });
    app.replaceChildren(h("div", { class: "card", style: null },
      h("h1", {}, "Sign in to TrustVault"),
      h("form", { on: { submit: act(async (e) => {
        e.preventDefault();
        const r = await api("POST", "/api/auth/login", { email: email.value, password: pw.value });
        me = r.user; csrf = r.csrf; render();
      }) } },
        h("label", {}, "Email", email), h("label", {}, "Password", pw),
        h("button", { class: "primary" }, "Sign in"))));
  }
  function changePwView() {
    const cur = h("input", { type: "password", required: true, autocomplete: "current-password" });
    const nw = h("input", { type: "password", required: true, minlength: 12, autocomplete: "new-password" });
    app.replaceChildren(h("div", { class: "card" }, h("h1", {}, "Choose a new password"),
      h("p", { class: "muted" }, "Your account is locked to this step until you set your own password (12+ characters)."),
      h("form", { on: { submit: act(async (e) => {
        e.preventDefault();
        await api("POST", "/api/auth/change-password", { current: cur.value, new: nw.value });
        me.must_change_pw = false; toast("Password changed"); render();
      }) } }, h("label", {}, "Current (temporary) password", cur), h("label", {}, "New password", nw),
        h("button", { class: "primary" }, "Change password"))));
  }

  // ------------------------------------------------------------ documents
  const views = {};
  views.docs = async function (_arg, filters) {
    filters = filters || {};
    const f = {
      q: h("input", { placeholder: "name contains…", value: filters.q || "" }),
      owner: h("input", { placeholder: "owner e-mail or name", value: filters.owner || "" }),
      category: h("select", {}, h("option", { value: "" }, "any category")),
      from: h("input", { type: "date", value: filters.from || "" }),
      to: h("input", { type: "date", value: filters.to || "" }),
    };
    const cats = await api("GET", "/api/categories");
    for (const c of cats.items) f.category.append(h("option", { value: c, selected: c === filters.category }, c));
    const results = h("div");
    const run = act(async (e) => {
      if (e) e.preventDefault();
      const cur = Object.fromEntries(Object.entries(f).map(([k, el]) => [k, el.value]));
      const r = await api("GET", "/api/documents?" + qs(cur));
      const rows = r.items.map((d) => h("tr", { class: "click", on: { click: () => go("detail", d.id) } },
        h("td", {}, d.name), h("td", {}, d.category), h("td", {}, d.owner_name), h("td", {}, when(d.created_at)),
        h("td", {}, h("span", { class: "tag" }, d.my_access))));
      results.replaceChildren(h("p", { class: "muted small" }, r.total + " document(s)"),
        h("table", {}, h("thead", {}, h("tr", {}, ["Name", "Category", "Owner", "Created", "Your access"].map((t) => h("th", {}, t)))),
          h("tbody", {}, rows)));
    });
    app.replaceChildren(h("div", { class: "card" }, h("h2", {}, "Documents"),
      h("form", { class: "row", on: { submit: run } },
        h("label", {}, "Name", f.q), h("label", {}, "Owner", f.owner), h("label", {}, "Category", f.category),
        h("label", {}, "Created from", f.from), h("label", {}, "to", f.to), h("button", { class: "primary" }, "Search")),
      results));
    run();
  };

  views.upload = function () {
    const file = h("input", { type: "file", required: true });
    const name = h("input", { maxlength: 200 }), cat = h("input", { value: "General", maxlength: 50 });
    const desc = h("textarea", { rows: 3, maxlength: 1000 });
    app.replaceChildren(h("div", { class: "card" }, h("h2", {}, "Upload a document"),
      h("p", { class: "muted small" }, "Allowed: pdf, png, jpg, txt, csv, docx, xlsx, pptx — up to 20 MB. New documents are private to you."),
      h("form", { on: { submit: act(async (e) => {
        e.preventDefault();
        const fd = new FormData();
        fd.append("file", file.files[0]); fd.append("category", cat.value); fd.append("description", desc.value);
        if (name.value) fd.append("name", name.value);
        const r = await api("POST", "/api/documents", fd, true);
        toast("Uploaded"); go("detail", r.id);
      }) } }, h("label", {}, "File", file), h("label", {}, "Display name (optional)", name),
        h("label", {}, "Category", cat), h("label", {}, "Description", desc), h("button", { class: "primary" }, "Upload"))));
  };

  views.trash = async function () {
    const r = await api("GET", "/api/trash");
    app.replaceChildren(h("div", { class: "card" }, h("h2", {}, "Deleted documents"),
      h("p", { class: "muted small" }, "Recoverable for " + r.purge_after_days + " days, then destroyed permanently."),
      r.items.length ? h("table", {}, h("tbody", {}, r.items.map((d) => h("tr", {},
        h("td", {}, d.name), h("td", {}, "deleted " + when(d.deleted_at)),
        h("td", {}, h("button", { on: { click: act(async () => { await api("POST", "/api/documents/" + d.id + "/restore"); toast("Restored"); go("trash"); }) } }, "Restore")))))) : h("p", {}, "Nothing here.")));
  };

  views.detail = async function (id) {
    const d = await api("GET", "/api/documents/" + id);
    const canEdit = d.my_access === "edit" || d.my_access === "owner", isOwner = d.my_access === "owner";
    const box = h("div");
    const meta = h("div", { class: "card" }, h("h2", {}, d.name),
      h("p", { class: "muted" }, d.category + " · owner " + d.owner_name + " · you have ", h("span", { class: "tag" }, d.my_access)),
      d.description ? h("p", {}, d.description) : null,
      h("table", {}, h("thead", {}, h("tr", {}, ["Version", "File", "Size", "Uploaded", ""].map((t) => h("th", {}, t)))),
        h("tbody", {}, d.versions.map((v) => h("tr", {}, h("td", {}, "v" + v.version), h("td", {}, v.original_filename),
          h("td", {}, v.size + " B"), h("td", {}, when(v.created_at) + " by " + v.uploaded_by),
          h("td", {}, h("a", { class: "btn", href: "/api/documents/" + id + "/download?version=" + v.version }, "Download")))))));
    box.append(meta);
    if (canEdit) {
      const nm = h("input", { value: d.name }), ct = h("input", { value: d.category }), ds = h("textarea", { rows: 2 }, d.description);
      const nv = h("input", { type: "file" });
      box.append(h("div", { class: "card" }, h("h3", {}, "Edit"),
        h("form", { class: "row", on: { submit: act(async (e) => { e.preventDefault();
          await api("PATCH", "/api/documents/" + id, { name: nm.value, category: ct.value, description: ds.value }); toast("Saved"); go("detail", id); }) } },
          h("label", {}, "Name", nm), h("label", {}, "Category", ct), h("label", {}, "Description", ds), h("button", {}, "Save")),
        h("form", { class: "row", on: { submit: act(async (e) => { e.preventDefault();
          const fd = new FormData(); fd.append("file", nv.files[0]);
          await api("POST", "/api/documents/" + id + "/versions", fd, true); toast("New version added"); go("detail", id); }) } },
          h("label", {}, "Upload a new version", nv), h("button", {}, "Add version"))));
    }
    if (isOwner) { box.append(await sharePanel(id)); box.append(await auditPanel(id));
      box.append(h("div", { class: "card" }, h("button", { class: "danger", on: { click: act(async () => {
        if (!confirm("Delete this document? It stays recoverable for a while, but nobody else can open it.")) return;
        await api("DELETE", "/api/documents/" + id); toast("Deleted"); go("docs"); }) } }, "Delete document"))); }
    app.replaceChildren(h("p", {}, h("button", { on: { click: () => go("docs") } }, "← Back")), box);
  };

  async function sharePanel(id) {
    const g = await api("GET", "/api/documents/" + id + "/grants");
    const email = h("input", { type: "email", required: true, placeholder: "colleague@company.com" });
    const level = h("select", {}, h("option", { value: "read" }, "can read"), h("option", { value: "edit" }, "can edit"));
    const exp = h("input", { type: "date" });
    const sug = h("div");
    const card = h("div", { class: "card" }, h("h3", {}, "Who has access"),
      g.items.length ? h("table", {}, h("tbody", {}, g.items.map((x) => h("tr", {},
        h("td", {}, x.email), h("td", {}, h("span", { class: "tag" }, x.level)),
        h("td", { class: "muted small" }, x.expires_at ? (x.expired ? "expired " : "until ") + when(x.expires_at) : "no expiry"),
        h("td", {}, h("button", { class: "danger", on: { click: act(async () => { await api("DELETE", "/api/documents/" + id + "/grants/" + x.user_id); toast("Access removed"); go("detail", id); }) } }, "Remove")))))) : h("p", { class: "muted" }, "Only you."),
      h("form", { class: "row", on: { submit: act(async (e) => { e.preventDefault();
        await api("POST", "/api/documents/" + id + "/grants", { email: email.value, level: level.value, expires_at: exp.value || undefined });
        toast("Access granted"); go("detail", id); }) } },
        h("label", {}, "Person", email), h("label", {}, "Access", level), h("label", {}, "Expires (optional)", exp), h("button", { class: "primary" }, "Grant")),
      h("p", {}, h("button", { on: { click: act(async () => {
        const r = await api("POST", "/api/documents/" + id + "/suggestions");
        sug.replaceChildren(h("p", { class: "muted small" }, "Suggestions from " + r.provider + ". They change nothing until you press Grant."),
          r.items.length ? r.items.map((s) => h("div", { class: "row" }, h("span", {}, s.email + " — " + s.reason),
            h("button", { on: { click: act(async () => { await api("POST", "/api/documents/" + id + "/grants", { email: s.email, level: "read", suggestion_id: s.id }); toast("Granted (read)"); go("detail", id); }) } }, "Grant read"),
            h("button", { on: { click: act(async () => { await api("POST", "/api/documents/" + id + "/suggestions/" + s.id + "/dismiss"); toast("Dismissed"); go("detail", id); }) } }, "Dismiss")))
            : h("p", { class: "muted" }, "No suggestions."));
      }) } }, "Suggest who might need access")), sug);
    return card;
  }
  async function auditPanel(id) {
    const r = await api("GET", "/api/documents/" + id + "/audit");
    return h("div", { class: "card" }, h("h3", {}, "Who touched this document"),
      h("table", {}, h("thead", {}, h("tr", {}, ["When", "Who", "What", "Result"].map((t) => h("th", {}, t)))),
        h("tbody", {}, r.items.slice(0, 50).map((i) => h("tr", {}, h("td", {}, when(i.ts)), h("td", {}, i.actor_email || "system"),
          h("td", {}, i.action), h("td", { class: i.outcome }, i.outcome))))));
  }

  // ------------------------------------------------------------ admin
  views.alerts = async function () {
    const r = await api("GET", "/api/admin/alerts");
    const v = await api("GET", "/api/admin/audit/verify");
    app.replaceChildren(h("div", { class: "card" }, h("h2", {}, "Worth noticing"),
      h("p", { class: v.ok ? "allowed" : "critical" }, v.ok ? "Audit trail verified: " + v.records_checked + " records, chain intact." : "AUDIT TRAIL FAILED VERIFICATION at record " + v.first_bad_seq),
      r.items.length ? h("table", {}, h("tbody", {}, r.items.map((a) => h("tr", {}, h("td", { class: a.severity }, a.severity), h("td", {}, a.summary))))) : h("p", { class: "muted" }, "Nothing unusual in the last 24 hours.")));
  };
  views.audit = async function (_a, filters) {
    filters = filters || {};
    const f = { actor: h("input", { value: filters.actor || "", placeholder: "actor e-mail" }),
      action: h("input", { value: filters.action || "", placeholder: "e.g. document.download" }),
      outcome: h("select", {}, ["", "allowed", "denied"].map((o) => h("option", { value: o, selected: o === filters.outcome }, o || "any result"))),
      doc_id: h("input", { value: filters.doc_id || "", placeholder: "document id" }) };
    const out = h("div");
    const run = act(async (e) => { if (e) e.preventDefault();
      const cur = Object.fromEntries(Object.entries(f).map(([k, el]) => [k, el.value]));
      const r = await api("GET", "/api/admin/audit?" + qs(cur));
      out.replaceChildren(h("p", { class: "muted small" }, r.total + " record(s), newest first"),
        h("table", {}, h("thead", {}, h("tr", {}, ["#", "When", "Who", "Action", "Result", "Document", "Detail", "IP"].map((t) => h("th", {}, t)))),
          h("tbody", {}, r.items.map((i) => h("tr", {}, h("td", {}, i.seq), h("td", {}, when(i.ts)), h("td", {}, i.actor_email || "system"),
            h("td", {}, i.action), h("td", { class: i.outcome }, i.outcome), h("td", {}, h("code", {}, (i.doc_id || "").slice(0, 8))),
            h("td", { class: "small" }, JSON.stringify(i.detail)), h("td", {}, i.ip || ""))))));
    });
    app.replaceChildren(h("div", { class: "card" }, h("h2", {}, "Audit trail"),
      h("form", { class: "row", on: { submit: run } }, h("label", {}, "Actor", f.actor), h("label", {}, "Action", f.action),
        h("label", {}, "Result", f.outcome), h("label", {}, "Document", f.doc_id), h("button", { class: "primary" }, "Filter")), out));
    run();
  };
  views.admindocs = async function () {
    const r = await api("GET", "/api/admin/documents");
    app.replaceChildren(h("div", { class: "card" }, h("h2", {}, "Document activity"),
      h("p", { class: "muted small" }, "Metadata only. Administrators cannot open documents."),
      h("table", {}, h("thead", {}, h("tr", {}, ["Name", "Category", "Owner", "Shared with", "Downloads", "Refused", "State"].map((t) => h("th", {}, t)))),
        h("tbody", {}, r.items.map((d) => h("tr", { class: "click", on: { click: () => go("audit", { doc_id: d.id }) } },
          h("td", {}, d.name), h("td", {}, d.category), h("td", {}, d.owner_email), h("td", {}, d.grant_count), h("td", {}, d.downloads),
          h("td", { class: d.refused ? "denied" : "" }, d.refused), h("td", {}, d.purged_at ? "purged" : d.deleted_at ? "deleted" : "live")))))));
  };
  views.users = async function () {
    const r = await api("GET", "/api/admin/users");
    const em = h("input", { type: "email", required: true }), nm = h("input", { required: true });
    const role = h("select", {}, ["viewer", "owner", "admin"].map((x) => h("option", { value: x }, x)));
    const note = h("p", { class: "small" });
    app.replaceChildren(h("div", { class: "card" }, h("h2", {}, "Users"),
      h("table", {}, h("thead", {}, h("tr", {}, ["Email", "Name", "Role", "Status", ""].map((t) => h("th", {}, t)))),
        h("tbody", {}, r.items.map((u) => h("tr", {}, h("td", {}, u.email), h("td", {}, u.name),
          h("td", {}, h("span", { class: "tag" }, u.role)), h("td", {}, u.active ? (u.must_change_pw ? "must change password" : "active") : "disabled"),
          h("td", {}, u.id === me.id ? "" : [
            h("button", { class: u.active ? "danger" : "", on: { click: act(async () => { await api("PATCH", "/api/admin/users/" + u.id, { active: !u.active }); go("users"); }) } }, u.active ? "Disable" : "Enable"), " ",
            h("button", { on: { click: act(async () => { const x = await api("POST", "/api/admin/users/" + u.id + "/reset-password"); note.textContent = "Temporary password for " + u.email + " (shown once): " + x.temporary_password; }) } }, "Reset password"), " ",
            h("button", { on: { click: act(async () => { const x = await api("POST", "/api/admin/users/" + u.id + "/revoke-sessions"); toast(x.revoked + " session(s) ended"); }) } }, "End sessions")]))))),
      note),
      h("div", { class: "card" }, h("h3", {}, "Add a user"),
        h("form", { class: "row", on: { submit: act(async (e) => { e.preventDefault();
          const x = await api("POST", "/api/admin/users", { email: em.value, name: nm.value, role: role.value });
          toast("Created. Temporary password: " + x.temporary_password); go("users"); }) } },
          h("label", {}, "Email", em), h("label", {}, "Name", nm), h("label", {}, "Role", role), h("button", { class: "primary" }, "Create"))));
  };

  // ------------------------------------------------------------ boot
  async function render() {
    if (!me) { try { const r = await api("GET", "/api/auth/me"); me = r.user; csrf = r.csrf; } catch (_) { /* signed out */ } }
    if (!me) { chrome(null); return loginView(); }
    if (me.must_change_pw) { chrome(null); return changePwView(); }
    go(me.role === "admin" ? "alerts" : "docs");
  }
  render();
})();
