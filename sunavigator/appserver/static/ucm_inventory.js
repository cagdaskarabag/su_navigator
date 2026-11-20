require([
    "jquery",
    "../app/sunavigator/ucm_common",
    "splunkjs/mvc/simplexml/ready!"
], function ($, ucm) {
    "use strict";
    var el = ucm.el;
    var root = document.getElementById("ucm-inventory");
    var PAGE = 25;
    var state = { kind: "pair", status: "active", q: "", index: "", stale_hours: "", sort: "count", offset: 0 };
    var pollTimer = null;

    function ageLabel(seconds) {
        if (seconds === null || seconds === undefined) { return "unknown"; }
        if (seconds < 3600) { return Math.round(seconds / 60) + " min"; }
        if (seconds < 86400) { return (seconds / 3600).toFixed(1) + " h"; }
        return (seconds / 86400).toFixed(1) + " d";
    }

    function renderCoverage(cov) {
        var wrap = el("div", { "class": "ucm-cards", id: "ucm-coverage" });
        ["sourcetype", "index", "datamodel", "addon"].forEach(function (k) {
            var c = cov[k] || { wanted: 0, found: 0, missing: 0 };
            wrap.appendChild(el("div", { "class": "ucm-card" },
                el("h3", { text: k }),
                el("div", { text: c.found + " of " + c.wanted + " catalogue values present" }),
                el("div", { "class": "ucm-sub", text: c.missing ? ("Missing (first 8): " + (c.missing_values || []).slice(0, 8).join(", ")) : "None missing from the imported catalogue." })));
        });
        return wrap;
    }

    function renderJobs(data) {
        var s = data.state || {};
        var jobs = data.jobs || [];
        var box = el("div", { "class": "ucm-card" },
            el("h3", { text: "Discovery" }),
            el("dl", { "class": "ucm-kv" },
                el("dt", { text: "Last success (UTC)" }), el("dd", { text: s.last_success_at || "never" }),
                el("dt", { text: "Last attempt" }), el("dd", { text: (s.last_attempt_at || "never") + " " + (s.last_attempt_status || "") }),
                el("dt", { text: "Window" }), el("dd", { text: (s.earliest || data.settings.earliest) + " → " + (s.latest || data.settings.latest) }),
                el("dt", { text: "Include internal indexes" }), el("dd", { text: String(!!s.include_internal) })),
            el("div", { "class": "ucm-actions" },
                el("label", {}, el("input", { type: "checkbox", id: "ucm-inc-int" }), " Include internal indexes"),
                el("button", { "class": "btn btn-primary", type: "button", id: "ucm-run-disc", text: "Run discovery" })),
            el("div", { "class": "ucm-sub", text: "Discovery runs a constructed tstats over indexes listed by the management API. Imported SPL is never searched." }));
        if (jobs.length) {
            var head = el("tr", {});
            ["Requested", "Status", "Pairs", "Indexes", "Missing", "Errors"].forEach(function (h) {
                head.appendChild(el("th", { text: h }));
            });
            var body = el("tbody", {});
            jobs.slice(0, 8).forEach(function (j) {
                var t = j.totals || {};
                body.appendChild(el("tr", {},
                    el("td", { text: j.requested_at }),
                    el("td", {}, ucm.badge(j.status, j.status === "succeeded" ? "ok" : (j.status === "failed" ? "error" : "info"))),
                    el("td", { text: t.pairs === undefined ? "" : t.pairs }),
                    el("td", { text: t.indexes_eligible === undefined ? "" : t.indexes_eligible }),
                    el("td", { text: t.missing === undefined ? "" : t.missing }),
                    el("td", { "class": "ucm-sub", text: (j.errors || []).map(function (e) { return e.message; }).slice(0, 2).join("; ") })));
            });
            box.appendChild(el("table", { "class": "ucm-table" }, el("thead", {}, head), body));
        }
        return box;
    }

    function renderTable(data) {
        if (!data.items.length) {
            return ucm.stateBox("empty", "No sources in this view.",
                "Run discovery from this page. Internal indexes are excluded unless you opt in.");
        }
        var head = el("tr", {});
        var cols = state.kind === "pair"
            ? ["Index", "Sourcetype", "Events in window", "Data age", "Status"]
            : ["Name", "Detail", "Events in window", "Data age", "Status"];
        cols.forEach(function (h) { head.appendChild(el("th", { text: h })); });
        var body = el("tbody", {});
        data.items.forEach(function (row) {
            var stale = row.age_seconds !== undefined && row.age_seconds !== null && row.age_seconds > 7 * 86400;
            var cells;
            if (state.kind === "pair") {
                cells = [el("td", { "class": "ucm-mono", text: row.index }),
                    el("td", { "class": "ucm-mono", text: row.sourcetype })];
            } else {
                cells = [el("td", { text: row.name }),
                    el("td", { "class": "ucm-sub", text: row.label || row.display_name || row.datatype ||
                        (row.app ? row.app + (row.sharing ? " (" + row.sharing + ")" : "") : "") })];
            }
            body.appendChild(el("tr", {}, cells,
                el("td", { text: row.window_count === undefined ? "" : row.window_count }),
                el("td", {}, ucm.badge(ageLabel(row.age_seconds), stale ? "warn" : "neutral")),
                el("td", {}, ucm.badge(row.status, row.status === "active" ? "ok" : "warn"))));
        });
        return el("div", {},
            el("div", { "class": "ucm-summary-line", text: (data.total || data.items.length) + " sources" }),
            el("table", { "class": "ucm-table" }, el("thead", {}, head), body),
            ucm.pager(data.offset, data.count, data.total, data.has_more, function (offset) {
                state.offset = offset;
                loadTable();
            }));
    }

    function renderMappings(data) {
        var box = el("div", { "class": "ucm-section" }, el("h3", { text: "Source mappings" }),
            el("div", { "class": "ucm-sub", text: "Local mappings are never overwritten by discovery. Auto matches are labelled medium or low confidence and are not readiness evidence." }));
        var form = el("div", { "class": "ucm-toolbar" },
            el("div", { "class": "ucm-field" }, el("label", { text: "Kind" }),
                el("select", { id: "map-kind" }, ["sourcetype", "index", "datamodel", "addon"].map(function (k) {
                    return el("option", { value: k, text: k });
                }))),
            el("div", { "class": "ucm-field" }, el("label", { text: "Discovered value" }),
                el("input", { id: "map-value", type: "text" })),
            el("div", { "class": "ucm-field" }, el("label", { text: "Canonical value" }),
                el("input", { id: "map-canon", type: "text" })),
            el("div", { "class": "ucm-field" }, el("label", { text: "Notes" }),
                el("input", { id: "map-notes", type: "text" })),
            el("button", { "class": "btn btn-primary", type: "button", id: "map-save", text: "Save local mapping" }));
        box.appendChild(form);
        if (!data.items.length) {
            box.appendChild(ucm.stateBox("empty", "No mappings yet.", "They appear after a discovery run if catalogue values match."));
            return box;
        }
        var head = el("tr", {});
        ["Kind", "Value", "Canonical", "Origin", "Confidence", "Catalogue uses", ""].forEach(function (h) {
            head.appendChild(el("th", { text: h }));
        });
        var body = el("tbody", {});
        data.items.forEach(function (m) {
            var del = m.origin === "local"
                ? el("button", { "class": "btn", type: "button", text: "Delete", onclick: function () {
                    ucm.post("mappings/delete", { kind: m.kind, value: m.value }).done(loadAll);
                } })
                : null;
            body.appendChild(el("tr", {},
                el("td", { text: m.kind }),
                el("td", { "class": "ucm-mono", text: m.value }),
                el("td", { "class": "ucm-mono", text: m.canonical_value }),
                el("td", {}, ucm.badge(m.origin, m.origin === "local" ? "ok" : "info")),
                el("td", { text: m.confidence }),
                el("td", { text: m.catalog_count }),
                el("td", {}, del)));
        });
        box.appendChild(el("table", { "class": "ucm-table" }, el("thead", {}, head), body));
        return box;
    }

    function toolbar() {
        return el("div", { "class": "ucm-toolbar" },
            el("div", { "class": "ucm-field" }, el("label", { text: "Search" }),
                el("input", { "class": "ucm-search", type: "search", value: state.q, id: "inv-q" })),
            el("div", { "class": "ucm-field" }, el("label", { text: "Kind" }),
                el("select", { id: "inv-kind" },
                    ["pair", "index", "app", "datamodel", "macro", "lookup", "eventtype"].map(function (k) {
                        return el("option", { value: k, text: k, selected: state.kind === k ? "selected" : null });
                    }))),
            el("div", { "class": "ucm-field" }, el("label", { text: "Status" }),
                el("select", { id: "inv-status" },
                    ["active", "missing", "any"].map(function (k) {
                        return el("option", { value: k, text: k, selected: state.status === k ? "selected" : null });
                    }))),
            el("div", { "class": "ucm-field" }, el("label", { text: "Sort" }),
                el("select", { id: "inv-sort" },
                    ["count", "age", "name", "index"].map(function (k) {
                        return el("option", { value: k, text: k, selected: state.sort === k ? "selected" : null });
                    }))));
    }

    function bindToolbar() {
        $("#inv-q").off("input").on("input", ucm.debounce(function () {
            state.q = $("#inv-q").val(); state.offset = 0; loadTable();
        }, 300));
        ["inv-kind", "inv-status", "inv-sort"].forEach(function (id) {
            $("#" + id).off("change").on("change", function () {
                state.kind = $("#inv-kind").val();
                state.status = $("#inv-status").val();
                state.sort = $("#inv-sort").val();
                state.offset = 0;
                loadTable();
            });
        });
    }

    function bindDiscovery() {
        $("#ucm-run-disc").off("click").on("click", function () {
            var btn = this;
            btn.disabled = true;
            ucm.post("discovery", { include_internal: $("#ucm-inc-int").prop("checked") }).done(function () {
                poll();
            }).fail(function (err) {
                btn.disabled = false;
                window.alert(err.message);
            });
        });
    }

    function bindMap() {
        $("#map-save").off("click").on("click", function () {
            ucm.post("mappings", {
                kind: $("#map-kind").val(),
                value: $("#map-value").val(),
                canonical_value: $("#map-canon").val() || $("#map-value").val(),
                notes: $("#map-notes").val()
            }).done(function () { loadMappings(); }).fail(function (err) { window.alert(err.message); });
        });
    }

    function poll() {
        clearTimeout(pollTimer);
        ucm.get("discovery").done(function (data) {
            var running = (data.jobs || []).some(function (j) { return j.status === "queued" || j.status === "running"; });
            var node = document.getElementById("ucm-disc-wrap");
            if (node) {
                ucm.clear(node).appendChild(renderJobs(data));
                bindDiscovery();
            }
            if (running) {
                pollTimer = setTimeout(poll, 4000);
            } else {
                loadTable();
                loadCoverage();
                loadMappings();
            }
        });
    }

    function loadTable() {
        var params = { kind: state.kind, status: state.status, sort: state.sort, offset: state.offset, count: PAGE };
        if (state.q) { params.q = state.q; }
        ucm.get("inventory", params).done(function (data) {
            var node = document.getElementById("ucm-table-wrap");
            if (node) { ucm.clear(node).appendChild(renderTable(data)); }
        }).fail(function (err) {
            var node = document.getElementById("ucm-table-wrap");
            if (node) { ucm.clear(node).appendChild(ucm.stateBox("error", "Could not load inventory.", err.message)); }
        });
    }

    function loadCoverage() {
        ucm.get("inventory/coverage").done(function (cov) {
            var node = document.getElementById("ucm-cov-wrap");
            if (node) { ucm.clear(node).appendChild(renderCoverage(cov)); }
        });
    }

    function loadMappings() {
        ucm.get("mappings", { count: 100 }).done(function (data) {
            var node = document.getElementById("ucm-map-wrap");
            if (node) { ucm.clear(node).appendChild(renderMappings(data)); bindMap(); }
        });
    }

    function loadAll() {
        ucm.clear(root).appendChild(el("div", {},
            el("div", { "class": "ucm-header" }, el("h2", { text: "Data Inventory" })),
            el("div", { id: "ucm-disc-wrap" }, el("div", { "class": "ucm-loading", text: "Loading discovery status…" })),
            el("div", { id: "ucm-cov-wrap" }),
            toolbar(),
            el("div", { id: "ucm-table-wrap" }, el("div", { "class": "ucm-loading", text: "Loading sources…" })),
            el("div", { id: "ucm-map-wrap" })));
        bindToolbar();
        poll();
        loadCoverage();
        loadTable();
        loadMappings();
    }

    loadAll();
});
