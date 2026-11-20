require([
    "jquery",
    "../app/splunk_use_case_manager/ucm_common",
    "splunkjs/mvc/simplexml/ready!"
], function ($, ucm) {
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

    function render(data) {
        var s = data.summary || { by_state: {}, by_live: {}, total: 0, drifted: 0 };
        ucm.clear(root);
        root.appendChild(el("div", { "class": "ucm-header" }, el("h2", { text: "Deployments" }),
            el("div", { "class": "ucm-sub", text: "Searches are written disabled. Enable them from the use case page after review. Drift is checked by the background worker and on demand." })));
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
        ["Use case", "Workflow", "Saved search", "Revision", "Updated (UTC)", "Last error"].forEach(function (h) { head.appendChild(el("th", { text: h })); });
        var body = el("tbody", {});
        items.forEach(function (d) {
            var live = (d.live && d.live.status) || "absent";
            var drift = (d.live && d.live.drift) || [];
            body.appendChild(el("tr", {},
                el("td", { "class": "ucm-title" }, el("a", { href: "ucm_usecase?id=" + encodeURIComponent(d.content_id), text: d.title || d.content_id }),
                    el("div", { "class": "ucm-sub ucm-mono", text: (d.saved_search && d.saved_search.name) || "" }), ucm.criticalityBadge(d.criticality)),
                el("td", {}, ucm.badge(d.state.replace("_", " "), STATE_KIND[d.state] || "neutral")),
                el("td", {}, ucm.badge(live, LIVE_KIND[live] || "neutral"), drift.length ? ucm.badge("drift: " + drift.map(function (x) { return x.field; }).join(", "), "warn") : null),
                el("td", { text: "latest " + d.revision + (d.deployed_revision ? ", deployed " + d.deployed_revision : "") }),
                el("td", { text: (d.updated_at || "") + " by " + (d.updated_by || "") }),
                el("td", { "class": "ucm-sub", text: d.last_error || "" })));
        });
        root.appendChild(el("table", { "class": "ucm-table" }, el("thead", {}, head), body));
        if (state.offset || data.has_more) {
            root.appendChild(ucm.pager(state.offset, COUNT, null, data.has_more, function (o) { state.offset = o; load(); }));
        }
    }

    load();
});
