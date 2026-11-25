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
    var root = document.getElementById("ucm-inventory");
    var PAGE = 25;
    var state = { kind: "pair", status: "active", q: "", index: "", stale_hours: "", sort: "count", offset: 0 };
    var pollTimer = null;
    var extState = "proposed";

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

    var SUMMARY_TEXT = { not_accelerated: ["not accelerated", "neutral"], no_data: ["accelerated, no events", "info"],
        summary_unverified: ["accelerated, summary not checked", "info"], summary_not_built: ["summary not built", "error"],
        summary_partial: ["summary partly built", "warn"], summary_built: ["summary built", "ok"] };

    function listCard(title, help, block, row) {
        var card = el("div", { "class": "ucm-card" }, el("h3", { text: title + " (" + block.total + ")" }),
            el("div", { "class": "ucm-sub", text: help }));
        if (!block.total) {
            card.appendChild(el("div", { "class": "ucm-sub", text: "None." }));
            return card;
        }
        card.appendChild(el("table", { "class": "ucm-table" }, el("tbody", {}, block.items.slice(0, 12).map(row))));
        if (block.total > 12) { card.appendChild(el("div", { "class": "ucm-sub", text: "First 12 of " + block.total + " shown." })); }
        return card;
    }

    function renderHealth(h) {
        if (!h.discovered) { return ucm.stateBox("info", "Environment health", "Run discovery to see the environment health panel."); }
        var models = h.datamodels.items.filter(function (m) { return m.app === "Splunk_SA_CIM" || m.accelerated; });
        var fresh = h.freshness || {};
        return el("div", { "class": "ucm-section" },
            el("h3", { text: "Environment health (from discovery " + (h.discovery_at || "") + " UTC)" }),
            el("div", { "class": "ucm-cards" },
                el("div", { "class": "ucm-card" }, el("h3", { text: "CIM add-on" }),
                    h.cim.installed ? ucm.badge("installed " + h.cim.version, "ok") : ucm.badge("not installed", "error"),
                    el("div", { "class": "ucm-sub", text: h.cim.installed ? h.cim.accelerated + " of " + h.cim.models + " CIM data models accelerated." :
                        "Searches that use CIM data models need the Splunk Common Information Model add-on." })),
                listCard("Data model summaries", "What a summariesonly=t search would see over the last 24 h. \"Summary not built\" means " +
                    "the model has events but its acceleration summary is empty, so such searches return nothing.",
                    { total: models.length, items: models }, function (m) {
                        var s = SUMMARY_TEXT[m.summary_state] || [m.summary_state, "neutral"];
                        return el("tr", {}, el("td", { "class": "ucm-mono", text: m.name }), el("td", {}, ucm.badge(s[0], s[1])),
                            el("td", { "class": "ucm-sub", text: m.accelerated && m.acceleration_earliest ? "range " + m.acceleration_earliest : "" }));
                    }),
                listCard("CIM index macros", "cim_<model>_indexes macros. An empty definition searches every index the account may read, " +
                    "which is slower; constrain it to the indexes that hold the model's data.", h.cim_index_macros, function (m) {
                        return el("tr", {}, el("td", { "class": "ucm-mono", text: m.name }),
                            el("td", { "class": "ucm-mono", text: m.definition || "(empty)" }),
                            el("td", {}, m.constrained ? ucm.badge("constrained", "ok") : ucm.badge("all indexes", "warn")));
                    })),
            el("div", { "class": "ucm-cards" },
                listCard("Indexes without data", "Enabled event indexes with no events in the discovery window" +
                    (fresh.enabled ? " or the last " + fresh.days + " days." : "."), h.indexes_without_data, function (i) {
                        return el("tr", {}, el("td", { "class": "ucm-mono", text: i.name }),
                            el("td", { "class": "ucm-sub", text: i.max_time ? "newest event " + i.max_time : "never had events" }));
                    }),
                listCard("Stopped before the window", fresh.enabled ? "Seen in the last " + fresh.days + " days but not in the discovery " +
                    "window. Readiness reads them as stale, not as missing." : "Switched off ([discovery] freshness_days = 0).",
                    fresh.stale_from_start || { total: 0, items: [] }, function (p) {
                        return el("tr", {}, el("td", { "class": "ucm-mono", text: p.index + " / " + p.sourcetype }),
                            el("td", { text: (p.volume_30d || 0) + " events" }), el("td", { "class": "ucm-sub", text: ageLabel(p.age_seconds) + " old" }));
                    }),
                listCard("Future time stamps", "Events stamped more than five minutes ahead. Usually a time zone or parsing problem; " +
                    "searches over recent time miss them.", fresh.future_dated || { total: 0, items: [] }, function (p) {
                        return el("tr", {}, el("td", { "class": "ucm-mono", text: p.index + " / " + p.sourcetype }),
                            el("td", { text: p.future_count + " events" }));
                    }),
                listCard("Sourcetypes no use case names", "Active sourcetypes that no catalogue requirement and no mapping refers to. " +
                    "Map them on this page if they carry data a use case expects.", h.unmapped_sourcetypes, function (st) {
                        return el("tr", {}, el("td", { "class": "ucm-mono", text: st }));
                    })));
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
            el("div", { "class": "ucm-sub", text: "Discovery runs a constructed tstats over indexes listed by the management API. Imported SPL is never searched." }),
            el("div", { "class": "ucm-sub", text: "Internal indexes (_internal, _audit, _introspection, ...) are scanned only when Include internal indexes is ticked " +
                "(default [discovery] include_internal = false). Without it they are listed with no counts, and readiness shows a requirement on an internal index " +
                "as not verified, never as present or missing. Tick it if you deploy use cases that search internal indexes." }));
        if ((s.totals || {}).truncated) {
            box.appendChild(ucm.stateBox("warn", "The last discovery hit its result limit.",
                "Some index/sourcetype pairs may be missing from the inventory, and none were marked missing in that run. Raise max_pairs in [discovery] or narrow the indexes searched."));
        }
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
                    el("td", { text: t.pairs === undefined ? "" : t.pairs + (t.truncated ? " (truncated)" : "") }),
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

    var BASIS = { spl_hash: ["same search text", "ok"], title_mitre: ["same title and technique", "info"],
        title: ["same title only", "warn"] };

    function renderExternal(data) {
        var box = el("div", { "class": "ucm-card", id: "ucm-ext" },
            el("h3", { text: "Detections already running here" }),
            el("div", { "class": "ucm-sub", text: "Searches in other apps that look like catalogue use cases. Only names are kept; the search text is hashed and never stored. " +
                "Accepting a match marks the use case as enabled elsewhere in coverage. It does not count as deployed by SUNavigator." }));
        var counts = data.counts || {};
        box.appendChild(el("div", { "class": "ucm-toolbar" },
            el("div", { "class": "ucm-field" }, el("label", { text: "Show" }),
                el("select", { id: "ext-state" }, ["proposed", "accepted", "rejected"].map(function (s) {
                    return el("option", { value: s, text: s + " (" + (counts[s] || 0) + ")", selected: extState === s ? "selected" : null });
                })))));
        if (!data.items.length) {
            box.appendChild(ucm.stateBox("empty", "Nothing here.", extState === "proposed"
                ? "Run discovery to look for matches, or there are none to review." : "No " + extState + " matches."));
            return box;
        }
        var head = el("tr", {});
        ["Search", "App", "State", "Matches catalogue use case", ""].forEach(function (h) { head.appendChild(el("th", { text: h })); });
        var body = el("tbody", {});
        data.items.forEach(function (m) {
            var cands = (m.candidates || []).map(function (c) {
                var b = BASIS[c.basis] || [c.basis, "neutral"];
                var line = el("div", {}, el("a", { href: "ucm_usecase?id=" + encodeURIComponent(c.content_key), text: c.title || c.content_id }),
                    " ", ucm.badge(b[0], b[1]));
                if (m.state !== "accepted") {
                    line.appendChild(el("button", { "class": "btn btn-link ext-accept", type: "button", text: "Accept",
                        onclick: function () { decide(m, "accept", c.content_key); } }));
                } else if (m.content_key === c.content_key) {
                    line.appendChild(ucm.badge("accepted", "ok"));
                }
                return line;
            });
            var actions = [];
            if (m.state === "proposed") {
                actions.push(el("button", { "class": "btn ext-reject", type: "button", text: "Reject",
                    onclick: function () { decide(m, "reject"); } }));
            } else {
                actions.push(el("button", { "class": "btn ext-reset", type: "button", text: "Reset",
                    onclick: function () { decide(m, "reset"); } }));
            }
            body.appendChild(el("tr", {},
                el("td", {}, m.name, m.previous_state ? el("div", { "class": "ucm-sub", text: "Search text changed since you " + m.previous_state + " it." }) : null),
                el("td", { "class": "ucm-mono", text: m.app }),
                el("td", {}, ucm.badge(m.enabled ? "enabled" : "disabled", m.enabled ? "ok" : "neutral"),
                    m.status === "missing" ? ucm.badge("no longer found", "warn") : null),
                el("td", {}, cands),
                el("td", {}, actions)));
        });
        box.appendChild(el("table", { "class": "ucm-table" }, el("thead", {}, head), body));
        if (data.has_more) { box.appendChild(el("div", { "class": "ucm-sub", text: "First " + data.items.length + " shown." })); }
        return box;
    }

    function decide(m, decision, contentKey) {
        ucm.post("external", { id: m._key, decision: decision, content_key: contentKey || "" }).done(loadExternal)
            .fail(function (err) { ucm.notify(err.message); });
    }

    function loadExternal() {
        ucm.get("external", { state: extState, count: 50 }).done(function (data) {
            var node = document.getElementById("ucm-ext-wrap");
            if (!node) { return; }
            ucm.clear(node).appendChild(renderExternal(data));
            $("#ext-state").off("change").on("change", function () { extState = $("#ext-state").val(); loadExternal(); });
        }).fail(function () {
            var node = document.getElementById("ucm-ext-wrap");
            if (node) { ucm.clear(node); }
        });
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
                ucm.notify(err.message);
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
            }).done(function () { loadMappings(); }).fail(function (err) { ucm.notify(err.message); });
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
                loadExternal();
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

    function loadHealth() {
        ucm.get("environment/health").done(function (h) {
            var node = document.getElementById("ucm-health-wrap");
            if (node) { ucm.clear(node).appendChild(renderHealth(h)); }
        }).fail(function (err) {
            var node = document.getElementById("ucm-health-wrap");
            if (node) { ucm.clear(node).appendChild(ucm.stateBox("error", "Could not load environment health.", err.message)); }
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
            el("div", { id: "ucm-health-wrap" }),
            toolbar(),
            el("div", { id: "ucm-table-wrap" }, el("div", { "class": "ucm-loading", text: "Loading sources…" })),
            el("div", { id: "ucm-map-wrap" }),
            el("div", { id: "ucm-ext-wrap" })));
        bindToolbar();
        poll();
        loadCoverage();
        loadHealth();
        loadTable();
        loadMappings();
        loadExternal();
    }

    loadAll();
}
