require([
    "jquery",
    "../app/splunk_use_case_manager/ucm_common",
    "splunkjs/mvc/simplexml/ready!"
], function ($, ucm) {
    "use strict";
    var el = ucm.el;
    var root = document.getElementById("ucm-readiness");
    var PAGE = 25;
    var params = ucm.queryParams();
    var state = { state: params.state || "", domain: params.domain || "", criticality: params.criticality || "",
        q: params.q || "", sort: params.sort || "score", offset: parseInt(params.offset || "0", 10) || 0 };
    var pollTimer = null;

    function scoreCell(item) {
        if (item.score === null || item.score === undefined) { return el("span", { "class": "ucm-sub", text: "–" }); }
        return el("span", { "class": "ucm-score" }, String(item.score),
            el("span", { "class": "ucm-score-bar" }, el("span", { style: "width:" + Math.max(0, Math.min(100, item.score)) + "%" })));
    }

    function renderSummary(data) {
        var s = data.state || {};
        var cards = el("div", { "class": "ucm-cards" });
        ucm.READINESS_STATES.forEach(function (st) {
            var n = (data.by_state || {})[st] || 0;
            cards.appendChild(el("a", { "class": "ucm-card ucm-card-link" + (state.state === st ? " ucm-card-active" : ""),
                href: "#", onclick: function (e) {
                    e.preventDefault();
                    state.state = state.state === st ? "" : st;
                    state.offset = 0;
                    render(data);
                    loadTable();
                } },
                el("div", {}, ucm.readinessBadge(st)),
                el("div", { "class": "ucm-big", text: String(n) })));
        });
        var running = (data.jobs || []).some(function (j) { return j.status === "queued" || j.status === "running"; });
        var info = el("div", { "class": "ucm-card" },
            el("h3", { text: "Assessment" }),
            el("dl", { "class": "ucm-kv" },
                el("dt", { text: "Last assessment (UTC)" }), el("dd", { text: s.last_success_at || "never" }),
                el("dt", { text: "Based on discovery (UTC)" }), el("dd", { text: s.discovery_at || "–" }),
                el("dt", { text: "Latest discovery (UTC)" }), el("dd", { text: data.discovery_completed_at || "never" }),
                el("dt", { text: "Thresholds" }), el("dd", { text: "ready ≥ " + data.settings.scoring.ready_threshold +
                    ", partial ≥ " + data.settings.scoring.partial_threshold + ", min coverage " +
                    Math.round(data.settings.scoring.min_coverage * 100) + "%" })),
            el("div", { "class": "ucm-actions" },
                el("button", { "class": "btn btn-primary", type: "button", disabled: running || !data.discovery_completed_at ? "disabled" : null,
                    onclick: function () {
                        this.disabled = true;
                        ucm.post("readiness").done(poll).fail(function (err) { window.alert(err.message); });
                    } }, running ? "Assessment running…" : "Re-assess all"),
                data.discovery_completed_at ? null : el("span", { "class": "ucm-sub", text: "Run discovery on the Data Inventory page first." })),
            s.discovery_at && data.discovery_completed_at && s.discovery_at !== data.discovery_completed_at
                ? ucm.stateBox("info", "Results are older than the latest discovery.", "A re-assessment is queued automatically by the background worker unless auto_assess is disabled.")
                : null);
        var gaps = el("div", { "class": "ucm-card" }, el("h3", { text: "Most common unmet requirements" }));
        var list = (data.top_blockers || []).map(function (g) { return { g: g, critical: true }; })
            .concat((data.top_gaps || []).map(function (g) { return { g: g, critical: false }; })).slice(0, 12);
        if (!list.length) {
            gaps.appendChild(el("div", { "class": "ucm-sub", text: "None." }));
        } else {
            gaps.appendChild(el("table", { "class": "ucm-table" }, el("tbody", {}, list.map(function (x) {
                return el("tr", {},
                    el("td", { "class": "ucm-mono", text: x.g.requirement }),
                    el("td", {}, x.critical ? ucm.badge("critical", "critical") : ucm.badge("required", "high")),
                    el("td", { text: x.g.use_cases + " use cases" }));
            }))));
        }
        return el("div", {}, cards, el("div", { "class": "ucm-cards" }, info, gaps));
    }

    function renderTable(data) {
        if (!data.items.length) {
            return ucm.stateBox("empty", "No assessed use cases match.", "Assessment runs after discovery; clear filters or re-assess.");
        }
        var head = el("tr", {});
        ["Use case", "Criticality", "State", "Score", "Coverage", "Unmet", "Unverified"].forEach(function (h) {
            head.appendChild(el("th", { text: h }));
        });
        var body = el("tbody", {});
        data.items.forEach(function (it) {
            var unmet = (it.blockers || []).concat(it.gaps || []);
            body.appendChild(el("tr", {},
                el("td", { "class": "ucm-title" },
                    el("a", { href: "ucm_usecase?id=" + encodeURIComponent(it.content_id), text: it.title }),
                    el("div", { "class": "ucm-sub ucm-mono", text: it.content_id })),
                el("td", {}, ucm.criticalityBadge(it.criticality)),
                el("td", {}, ucm.readinessBadge(it.state)),
                el("td", {}, scoreCell(it)),
                el("td", { text: Math.round((it.coverage || 0) * 100) + "%" }),
                el("td", { "class": "ucm-sub" }, unmet.slice(0, 3).map(function (u) {
                    return el("div", { "class": "ucm-mono", text: u.type + ": " + u.value });
                }), unmet.length > 3 ? el("span", { "class": "ucm-more", text: "+" + (unmet.length - 3) }) : null),
                el("td", { text: it.unverified || 0 })));
        });
        return el("div", {},
            el("div", { "class": "ucm-summary-line", text: data.total + " use cases" }),
            el("table", { "class": "ucm-table" }, el("thead", {}, head), body),
            ucm.pager(data.offset, data.count, data.total, data.has_more, function (offset) {
                state.offset = offset;
                loadTable();
            }));
    }

    function select(id, label, values, current) {
        return el("div", { "class": "ucm-field" }, el("label", { text: label }),
            el("select", { id: id }, [el("option", { value: "", text: "All" })].concat(values.map(function (v) {
                return el("option", { value: v, text: v, selected: current === v ? "selected" : null });
            }))));
    }

    function toolbar() {
        return el("div", { "class": "ucm-toolbar" },
            el("div", { "class": "ucm-field" }, el("label", { text: "Search" }),
                el("input", { "class": "ucm-search", id: "rd-q", type: "search", value: state.q, placeholder: "id or title" })),
            select("rd-state", "State", ucm.READINESS_STATES, state.state),
            select("rd-domain", "Domain", ucm.DOMAINS, state.domain),
            select("rd-crit", "Criticality", ucm.CRITICALITY, state.criticality),
            el("div", { "class": "ucm-field" }, el("label", { text: "Sort" }),
                el("select", { id: "rd-sort" }, [["score", "Score (high first)"], ["score_asc", "Score (low first)"],
                    ["criticality", "Criticality"], ["title", "Title"]].map(function (o) {
                    return el("option", { value: o[0], text: o[1], selected: state.sort === o[0] ? "selected" : null });
                }))));
    }

    function bindToolbar() {
        $("#rd-q").on("input", ucm.debounce(function () { state.q = $("#rd-q").val(); state.offset = 0; loadTable(); }, 300));
        $("#rd-state, #rd-domain, #rd-crit, #rd-sort").on("change", function () {
            state.state = $("#rd-state").val();
            state.domain = $("#rd-domain").val();
            state.criticality = $("#rd-crit").val();
            state.sort = $("#rd-sort").val();
            state.offset = 0;
            loadTable();
        });
    }

    function loadTable() {
        var p = { sort: state.sort, offset: state.offset, count: PAGE };
        ["state", "domain", "criticality", "q"].forEach(function (k) { if (state[k]) { p[k] = state[k]; } });
        ucm.setQueryParams(state);
        var box = document.getElementById("rd-table");
        ucm.get("readiness", p).done(function (data) {
            ucm.clear(box).appendChild(renderTable(data));
        }).fail(function (err) {
            ucm.clear(box).appendChild(ucm.stateBox("error", "Could not load readiness.", err.message));
        });
    }

    function render(summary) {
        ucm.clear(root).appendChild(el("div", {},
            el("div", { id: "rd-summary" }, renderSummary(summary)),
            toolbar(),
            el("div", { id: "rd-table" }, el("div", { "class": "ucm-loading", text: "Loading…" }))));
        bindToolbar();
    }

    function poll() {
        clearTimeout(pollTimer);
        ucm.get("readiness/summary").done(function (summary) {
            render(summary);
            loadTable();
            var running = (summary.jobs || []).some(function (j) { return j.status === "queued" || j.status === "running"; });
            if (running) { pollTimer = setTimeout(poll, 5000); }
        }).fail(function (err) {
            ucm.clear(root).appendChild(ucm.stateBox("error", "Could not load readiness.", err.message));
        });
    }

    poll();
});
