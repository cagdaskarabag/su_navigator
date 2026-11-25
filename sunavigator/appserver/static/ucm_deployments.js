/*
 * ucm_common.js is requested from the same static directory as ucm.css, which the dashboard
 * XML loads under /static/@<build>.<push>-<app build>/... and so carries the app build.
 * A relative module id ("../app/sunavigator/ucm_common") or splunk.util.make_url (which
 * always writes app build 0) would leave it cached for a year across upgrades.
 */
var ucmCommonUrl = (function () {
    var links = document.querySelectorAll('link[href*="/app/sunavigator/ucm.css"]');
    return links.length ? links[0].href.replace(/ucm\.css([?#].*)?$/, "ucm_common.js") : "../app/sunavigator/ucm_common";
}());

require(["jquery", ucmCommonUrl, "splunkjs/mvc/simplexml/ready!"], ucmViewMain);

function ucmViewMain($, ucm) {
    "use strict";
    var el = ucm.el;
    var root = document.getElementById("ucm-deployments");
    var params = ucm.queryParams();
    var state = { state: params.state || "", live: params.live || "", drift: params.drift || "", offset: parseInt(params.offset || "0", 10) || 0 };
    var COUNT = 50;
    var STATES = ["draft", "pending_approval", "approved", "rejected", "deployed", "failed", "retired"];
    var LIVE = ["enabled", "disabled", "missing", "unmanaged", "absent"];
    var LIVE_KIND = { enabled: "ok", disabled: "info", missing: "error", unmanaged: "error", absent: "neutral" };
    var STATE_KIND = { draft: "neutral", pending_approval: "warn", approved: "info", rejected: "high",
        deployed: "ok", failed: "error", retired: "neutral" };
    var HEALTH_KIND = { operational: "ok", no_runs: "warn", unhealthy: "error", failing_dispatch: "error", disabled: "info", unknown: "neutral" };
    var HEALTH_LABEL = { operational: "ran without error", failing_dispatch: "failing at dispatch" };
    var HEALTH_HELP = { operational: "The last scheduled run finished with status success. This is not a statement about data: " +
        "a search that sees no events also reports success.",
        failing_dispatch: "The scheduler tried to start the search and Splunk refused it before it ran (for example an unknown " +
        "command, a missing capability or an index the account cannot search). It never ran, so it never reports a status." };

    function card(label, value, active, onclick) {
        return el("div", { "class": "ucm-card ucm-card-link" + (active ? " ucm-card-active" : ""), onclick: onclick },
            el("div", { "class": "ucm-sub", text: label }), el("div", { "class": "ucm-big", text: String(value) }));
    }

    function select(options, value, onchange, emptyLabel) {
        var s = el("select", { "class": "ucm-input", onchange: function () { onchange(s.value); } },
            el("option", { value: "", text: emptyLabel }), options.map(function (o) { return el("option", { value: o, text: o.replace("_", " ") }); }));
        s.value = value;
        return s;
    }

    function load() {
        ucm.setQueryParams({ state: state.state, live: state.live, drift: state.drift, offset: state.offset || "" });
        var q = { summary: "1", offset: state.offset, count: COUNT };
        if (state.state) { q.state = state.state; }
        if (state.live) { q.live = state.live; }
        if (state.drift) { q.drift = "1"; }
        ucm.get("deployments", q).done(render).fail(function (err) {
            ucm.clear(root).appendChild(ucm.stateBox("error", "Could not load deployments.", err.message));
        });
    }

    function download(filename, text, mime) {
        var url = URL.createObjectURL(new Blob([text], { type: mime }));
        var a = el("a", { href: url, text: filename });
        a.setAttribute("download", filename);
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    }

    function exportBox() {
        var status = el("div", { "class": "ucm-sub" });
        var button = el("button", { "class": "btn", text: "Export deployed revisions", onclick: function () {
            button.disabled = true;
            ucm.get("deployments/export").done(function (bundle) {
                download("savedsearches.conf", bundle.content, "text/plain");
                download("savedsearches.manifest.json", JSON.stringify(bundle.manifest, null, 2) + "\n", "application/json");
                status.textContent = "Exported " + bundle.count + " deployed revision(s)" +
                    (bundle.skipped ? ", " + bundle.skipped + " skipped (see manifest)" : "") +
                    ". savedsearches.conf SHA-256 " + bundle.sha256 + ". Same records always give the same file.";
            }).fail(function (err) {
                status.textContent = "Export failed: " + (err && err.message ? err.message : "unknown error");
            }).always(function () { button.disabled = false; });
        } });
        return el("div", { "class": "ucm-toolbar" }, button, status);
    }

    function render(data) {
        var s = data.summary || { by_state: {}, by_live: {}, total: 0, drifted: 0 };
        ucm.clear(root);
        root.appendChild(el("div", { "class": "ucm-header" }, el("h2", { text: "Deployments" }),
            el("div", { "class": "ucm-sub", text: "Searches are written disabled. Enable them from the use case page after review. Drift is checked by the background worker and on demand." })));
        root.appendChild(exportBox());
        root.appendChild(el("div", { "class": "ucm-cards" },
            card("All deployments", s.total, !state.state && !state.live && !state.drift, function () { state = { state: "", live: "", drift: "", offset: 0 }; load(); }),
            card("Pending approval", s.by_state.pending_approval || 0, state.state === "pending_approval", function () { state = { state: "pending_approval", live: "", drift: "", offset: 0 }; load(); }),
            card("Enabled searches", s.by_live.enabled || 0, state.live === "enabled", function () { state = { state: "", live: "enabled", drift: "", offset: 0 }; load(); }),
            card("Disabled searches", s.by_live.disabled || 0, state.live === "disabled", function () { state = { state: "", live: "disabled", drift: "", offset: 0 }; load(); }),
            card("Failed", s.by_state.failed || 0, state.state === "failed", function () { state = { state: "failed", live: "", drift: "", offset: 0 }; load(); }),
            card("Drift or missing", s.drifted || 0, !!state.drift, function () { state = { state: "", live: "", drift: "1", offset: 0 }; load(); })));
        root.appendChild(el("div", { "class": "ucm-toolbar" },
            select(STATES, state.state, function (v) { state.state = v; state.offset = 0; load(); }, "Any workflow state"),
            select(LIVE, state.live, function (v) { state.live = v; state.offset = 0; load(); }, "Any saved-search status")));
        var items = data.items || [];
        if (!items.length) {
            root.appendChild(ucm.stateBox("empty", "No deployments match.", "Open a use case and prepare a deployment from its Deployment card."));
            return;
        }
        var head = el("tr", {});
        ["Use case", "Workflow", "Saved search", "Runs (24 h)", "Revision", "Updated (UTC)", "Last error"].forEach(function (h) { head.appendChild(el("th", { text: h })); });
        var body = el("tbody", {});
        var healthCells = {};
        items.forEach(function (d) {
            var healthCell = el("td", { "class": "ucm-sub", text: d.deployed_revision ? "…" : "" });
            healthCells[d.content_id] = healthCell;
            var live = (d.live && d.live.status) || "absent";
            var drift = (d.live && d.live.drift) || [];
            body.appendChild(el("tr", {},
                el("td", { "class": "ucm-title" }, el("a", { href: "ucm_usecase?id=" + encodeURIComponent(d.content_id), text: d.title || d.content_id }),
                    el("div", { "class": "ucm-sub ucm-mono", text: (d.saved_search && d.saved_search.name) || "" }), ucm.criticalityBadge(d.criticality)),
                el("td", {}, ucm.badge(d.state.replace("_", " "), STATE_KIND[d.state] || "neutral")),
                el("td", {}, ucm.badge(live, LIVE_KIND[live] || "neutral"), drift.length ? ucm.badge("drift: " + drift.map(function (x) { return x.field; }).join(", "), "warn") : null),
                healthCell,
                el("td", { text: "latest " + d.revision + (d.deployed_revision ? ", deployed " + d.deployed_revision : "") }),
                el("td", { text: (d.updated_at || "") + " by " + (d.updated_by || "") }),
                el("td", { "class": "ucm-sub", text: d.last_error || "" })));
        });
        root.appendChild(el("table", { "class": "ucm-table" }, el("thead", {}, head), body));
        ucm.get("operations", { hours: 24 }).done(function (ops) {
            var byId = {};
            (ops.items || []).forEach(function (i) { byId[i.content_id] = i; });
            Object.keys(healthCells).forEach(function (id) {
                var cell = ucm.clear(healthCells[id]);
                var i = byId[id];
                if (!ops.available) { cell.textContent = byId[id] ? "unavailable" : ""; return; }
                if (i) {
                    var b = ucm.badge((HEALTH_LABEL[i.health] || i.health.replace("_", " ")) + (i.runs ? " (" + i.runs + ")" : ""), HEALTH_KIND[i.health] || "neutral");
                    if (HEALTH_HELP[i.health]) { b.setAttribute("title", HEALTH_HELP[i.health]); }
                    cell.appendChild(b);
                    (i.advisories || []).forEach(function (f) {
                        cell.appendChild(el("div", { "class": "ucm-sub", title: f.code, text: f.message }));
                    });
                }
            });
        }).fail(function () {
            Object.keys(healthCells).forEach(function (id) { ucm.clear(healthCells[id]); });
        });
        if (state.offset || data.has_more) {
            root.appendChild(ucm.pager(state.offset, COUNT, null, data.has_more, function (o) { state.offset = o; load(); }));
        }
    }

    load();
}
