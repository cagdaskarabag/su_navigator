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
    var root = document.getElementById("ucm-coverage");
    var params = ucm.queryParams();
    var state = {
        framework_id: params.framework_id || "mitre_attack_enterprise", version: params.version || "",
        domain: params.domain || "", operational: params.operational || "", hours: params.hours || "24",
        technique: params.technique || "", framework: params.framework || "",
        clause: params.clause || "", gaps: params.gaps || ""
    };
    var LEVEL_LABEL = { catalogue: "In catalogue", ready: "Data ready", deployed: "Deployed", enabled: "Enabled",
        operational: "Ran without error (not a statement about data)" };
    var LEVEL_HOW = {
        catalogue: "Techniques mapped by at least one active use case in the catalogue, whether or not it can run here.",
        ready: "Techniques with at least one use case that is ready, or already deployed or enabled (levels are cumulative).",
        deployed: "Techniques with at least one use case that has a deployed saved search, enabled or not, or a running one.",
        enabled: "Techniques with at least one use case whose saved search is enabled in Splunk.",
        operational: "Techniques with an enabled saved search whose last run in the chosen window finished with status success. " +
            "This says the search ran without error. It is not a statement about data: a search that sees no events also succeeds."
    };
    var HEALTH_KIND = { operational: "ok", no_runs: "warn", unhealthy: "error", failing_dispatch: "error", disabled: "info", unknown: "neutral" };

    function select(options, value, onchange, emptyLabel) {
        var s = el("select", { "class": "ucm-input", onchange: function () { onchange(s.value); } },
            emptyLabel ? el("option", { value: "", text: emptyLabel }) : null,
            options.map(function (o) { return el("option", { value: o.value, text: o.label }); }));
        s.value = value;
        return s;
    }

    function persist() {
        ucm.setQueryParams({ framework_id: state.framework_id, version: state.version, domain: state.domain,
            operational: state.operational, hours: state.operational ? state.hours : "",
            technique: state.technique, framework: state.framework, clause: state.clause, gaps: state.gaps });
    }

    function query(extra) {
        var q = $.extend({}, extra || {});
        if (state.domain) { q.domain = state.domain; }
        if (state.operational) { q.operational = "1"; q.hours = state.hours; }
        return q;
    }

    function failBox(target, title) {
        return function (err) { ucm.clear(target).appendChild(ucm.stateBox("error", title, err.message)); };
    }

    function legend(levels) {
        return el("div", { "class": "ucm-legend" }, el("span", { "class": "ucm-matrix-cell", text: "No use case" }),
            levels.map(function (l) { return el("span", { "class": "ucm-matrix-cell lvl-" + l, text: LEVEL_LABEL[l] || l }); }));
    }

    function cellTitle(t) {
        var c = t.counts || {};
        return t.id + " " + t.name + "\nUse cases: " + (c.catalogue || 0) + " in catalogue, " + (c.ready || 0) + " ready, " +
            (c.deployed || 0) + " deployed, " + (c.enabled || 0) + " enabled" +
            (c.operational ? ", " + c.operational + " ran without error" : "");
    }

    function cell(t, sub) {
        var n = (t.counts && t.counts.catalogue) || 0;
        return el("a", {
            "class": "ucm-matrix-cell" + (t.level ? " lvl-" + t.level : "") + (sub ? " ucm-matrix-sub" : "") +
                (state.technique === t.id ? " ucm-matrix-selected" : ""),
            title: cellTitle(t), href: "#",
            onclick: function (e) { e.preventDefault(); state.technique = t.id; persist(); load(); }
        }, el("span", { "class": "ucm-mono", text: t.id }), " ", t.name, n ? el("b", { text: " (" + n + ")" }) : null);
    }

    function renderMatrix(target, m) {
        ucm.clear(target);
        var tot = m.totals || { techniques: 0, covered: {} };
        var pct = function (n) {
            if (!tot.techniques) { return "0%"; }
            var p = 100 * n / tot.techniques;
            return (p > 0 && p < 10 ? p.toFixed(1) : Math.round(p)) + "%";
        };
        target.appendChild(el("div", { "class": "ucm-cards ucm-kpis" }, ["catalogue", "ready", "deployed", "enabled"]
            .concat(m.operational && m.operational.available ? ["operational"] : []).map(function (l) {
                var n = tot.covered[l] || 0;
                return ucm.kpiCard({ label: LEVEL_LABEL[l], value: pct(n), detail: n + " of " + tot.techniques + " techniques",
                    how: LEVEL_HOW[l] + " Percentage = techniques at this level ÷ techniques in the framework." });
            })));
        if (m.operational && !m.operational.available) {
            target.appendChild(ucm.stateBox("info", "Run status is not available.", m.operational.reason ||
                "Your role cannot search the scheduler logs in index=_internal, so the Ran without error level is not shown."));
        }
        target.appendChild(el("div", { "class": "ucm-toolbar" }, legend(m.levels || []),
            el("button", { "class": "btn", text: "Export ATT&CK Navigator layer", onclick: function () {
                ucm.get("frameworks/navigator", query({ framework_id: state.framework_id, version: state.version })).done(function (data) {
                    download(data.filename, JSON.stringify(data.layer, null, 2), "application/json");
                }).fail(function (err) { ucm.notify(err.message, "Could not build the layer"); });
            } })));
        target.appendChild(el("div", { "class": "ucm-matrix" }, (m.tactics || []).map(function (tac) {
            return el("div", { "class": "ucm-matrix-col" },
                el("h4", { title: tac.id, text: tac.name }),
                el("div", { "class": "ucm-sub", text: tac.covered + " / " + tac.techniques.length + " covered" }),
                tac.techniques.map(function (t) {
                    return el("div", {}, cell(t, false), (t.subs || []).filter(function (s) { return s.level; })
                        .map(function (s) { return cell(s, true); }));
                }));
        })));
        target.appendChild(el("div", { "class": "ucm-sub", text: m.name + " " + m.version + ". Techniques are counted once per use case and sub-technique mappings also count towards their parent. Only active, non-deprecated techniques are shown." }));
        if (m.attribution) { target.appendChild(el("div", { "class": "ucm-sub", text: m.attribution })); }
        if ((m.remapped || []).length || (m.unresolved || []).length) {
            var rows = el("tbody", {});
            (m.remapped || []).forEach(function (r) {
                rows.appendChild(el("tr", {}, el("td", { "class": "ucm-mono", text: r.from }),
                    el("td", {}, ucm.badge("revoked, counted as " + r.to, "info")), el("td", { text: String(r.count) }),
                    el("td", { "class": "ucm-sub", text: r.use_cases.join(", ") })));
            });
            (m.unresolved || []).forEach(function (r) {
                rows.appendChild(el("tr", {}, el("td", { "class": "ucm-mono", text: r.id }),
                    el("td", {}, ucm.badge(r.reason === "deprecated" ? "deprecated, not counted" : "unknown in this version", "warn")),
                    el("td", { text: String(r.count) }), el("td", { "class": "ucm-sub", text: r.use_cases.join(", ") })));
            });
            target.appendChild(el("h3", { text: "Mappings that need review" }));
            target.appendChild(el("table", { "class": "ucm-table" }, el("thead", {}, el("tr", {},
                el("th", { text: "Technique id" }), el("th", { text: "Status" }), el("th", { text: "Use cases" }),
                el("th", { text: "Examples" }))), rows));
        }
    }

    function renderTechnique(target) {
        ucm.clear(target);
        if (!state.technique) { return; }
        target.appendChild(el("div", { "class": "ucm-loading", text: "Loading use cases for " + state.technique + "…" }));
        ucm.get("frameworks/technique", query({ framework_id: state.framework_id, version: state.version, id: state.technique }))
            .done(function (data) {
                ucm.clear(target);
                target.appendChild(el("h3", {}, "Use cases for ", el("span", { "class": "ucm-mono", text: data.id }),
                    el("a", { href: "#", "class": "ucm-sub", text: "  close", onclick: function (e) {
                        e.preventDefault(); state.technique = ""; persist(); ucm.clear(target);
                    } })));
                if (!data.use_cases.length) {
                    target.appendChild(ucm.stateBox("empty", "No use case maps to this technique.", "Coverage gaps like this are candidates for new content."));
                    return;
                }
                var body = el("tbody", {});
                data.use_cases.forEach(function (u) {
                    body.appendChild(el("tr", {},
                        el("td", { "class": "ucm-title" }, el("a", { href: "ucm_usecase?id=" + encodeURIComponent(u.content_id), text: u.title || u.content_id })),
                        el("td", {}, ucm.criticalityBadge(u.criticality)),
                        el("td", {}, el("span", { "class": "ucm-matrix-cell lvl-" + u.level, text: LEVEL_LABEL[u.level] || u.level })),
                        el("td", { "class": "ucm-mono", text: (u.via || []).join(", ") })));
                });
                target.appendChild(el("table", { "class": "ucm-table" }, el("thead", {}, el("tr", {},
                    el("th", { text: "Use case" }), el("th", { text: "Criticality" }), el("th", { text: "Level" }),
                    el("th", { text: "Mapped via" }))), body));
            }).fail(failBox(target, "Could not load use cases for this technique."));
    }

    function renderFrameworks(target, data) {
        ucm.clear(target);
        target.appendChild(el("h3", { text: "Other frameworks and regulations" }));
        var items = (data.coverage || []).filter(function (f) { return f.kind !== "attack"; });
        if (!items.length) {
            target.appendChild(ucm.stateBox("empty", "No regulation mappings in the catalogue.", ""));
            return;
        }
        var body = el("tbody", {});
        items.forEach(function (f) {
            var c = f.counts;
            body.appendChild(el("tr", { "class": state.framework === f.framework ? "ucm-row-active" : "" },
                el("td", { "class": "ucm-title" }, el("a", { href: "#", text: f.framework.replace(/^regulation:/, ""), onclick: function (e) {
                    e.preventDefault(); state.framework = f.framework; state.clause = ""; persist(); renderControls(controlsBox);
                } })),
                el("td", { text: String(f.controls) }),
                ["catalogue", "ready", "deployed", "enabled"].map(function (l) { return el("td", { text: String(c[l] || 0) }); })));
        });
        target.appendChild(el("table", { "class": "ucm-table" }, el("thead", {}, el("tr", {},
            ["Framework", "Controls mapped", "Use cases", "Data ready", "Deployed", "Enabled"].map(function (h) { return el("th", { text: h }); }))), body));
        var controlsBox = el("div", {});
        target.appendChild(controlsBox);
        renderControls(controlsBox);
    }

    function download(filename, text, mime) {
        var url = URL.createObjectURL(new Blob([text], { type: mime }));
        var a = el("a", { href: "#", text: filename });
        a.setAttribute("href", url);
        a.setAttribute("download", filename);
        document.body.appendChild(a);
        a.click();
        document.body.removeChild(a);
        setTimeout(function () { URL.revokeObjectURL(url); }, 1000);
    }

    function exportEvidence(target, format) {
        var note = el("div", { "class": "ucm-loading", text: "Building evidence pack…" });
        ucm.clear(target).appendChild(note);
        ucm.get("frameworks/evidence", query({ framework: state.framework, format: format })).done(function (pack) {
            download(pack.filename, pack.content, format === "csv" ? "text/csv" : "application/json");
            ucm.clear(target).appendChild(ucm.stateBox("info", "Downloaded " + pack.filename,
                pack.meta.rows + " rows, " + pack.meta.clauses + " clauses, " + pack.meta.gaps + " without a ready use case. SHA-256 " +
                pack.sha256 + ". The same catalogue, readiness and deployment state always produces the same file."));
        }).fail(failBox(target, "Could not build the evidence pack."));
    }

    function levelCell(level) {
        return level ? el("span", { "class": "ucm-matrix-cell lvl-" + level, text: LEVEL_LABEL[level] || level }) : null;
    }

    function renderClause(target) {
        ucm.clear(target);
        if (!state.framework || !state.clause) { return; }
        target.appendChild(el("div", { "class": "ucm-loading", text: "Loading clause " + state.clause + "…" }));
        ucm.get("frameworks/clause", query({ framework: state.framework, clause: state.clause })).done(function (data) {
            ucm.clear(target);
            target.appendChild(el("h4", {}, "Use cases for clause ", el("span", { "class": "ucm-mono", text: data.clause }),
                el("a", { href: "#", "class": "ucm-sub", text: "  close", onclick: function (e) {
                    e.preventDefault(); state.clause = ""; persist(); ucm.clear(target);
                } })));
            var body = el("tbody", {});
            data.use_cases.forEach(function (u) {
                var dep = u.deployment_state ? u.deployment_state + (u.live_status ? " / " + u.live_status : "") : "not deployed";
                body.appendChild(el("tr", {},
                    el("td", { "class": "ucm-title" }, el("a", { href: "ucm_usecase?id=" + encodeURIComponent(u.content_id), text: u.title || u.content_id }),
                        el("div", { "class": "ucm-sub ucm-mono", text: u.content_id + (u.framework_version ? " · " + u.framework_version : "") })),
                    el("td", {}, levelCell(u.level)),
                    el("td", {}, ucm.readinessBadge(u.readiness_state), u.readiness_stale ? ucm.badge("stale", "warn") : null),
                    el("td", {}, el("div", { text: dep }), u.saved_search ? el("div", { "class": "ucm-sub ucm-mono", text: u.saved_search }) : null,
                        u.live_drift ? ucm.badge("drift", "warn") : null),
                    el("td", {}, el("div", { text: [u.mode, u.assurance].filter(Boolean).join(", ") }),
                        u.requires_sme_review ? ucm.badge("SME review required", "warn") : null),
                    el("td", { "class": "ucm-sub" }, el("details", { "class": "ucm-details" },
                        el("summary", { text: "Objective and evidence" }),
                        el("div", {}, el("strong", { text: "Control objective: " }), u.control_objective || "—"),
                        el("div", {}, el("strong", { text: "Evidence artifact: " }), u.evidence_artifact || "—"),
                        el("div", {}, el("strong", { text: "Assurance rationale: " }), u.assurance_rationale || "—"),
                        u.clause_url ? el("a", { href: u.clause_url, target: "_blank", rel: "noopener noreferrer", text: "Clause text" }) : null))));
            });
            target.appendChild(el("table", { "class": "ucm-table" }, el("thead", {}, el("tr", {},
                ["Use case", "Level", "Readiness", "Deployment", "Mapping", "Evidence"].map(function (h) { return el("th", { text: h }); }))), body));
        }).fail(failBox(target, "Could not load the clause."));
    }

    function renderControls(target) {
        ucm.clear(target);
        if (!state.framework) { return; }
        ucm.get("frameworks/controls", query({ framework: state.framework })).done(function (data) {
            ucm.clear(target);
            var gaps = data.controls.filter(function (c) { return c.gap; }).length;
            var exportBox = el("div", {});
            var clauseBox = el("div", {});
            target.appendChild(el("h4", { text: "Clauses in " + data.framework.replace(/^regulation:/, "") }));
            target.appendChild(el("div", { "class": "ucm-toolbar" },
                el("span", { "class": "ucm-sub", text: data.controls.length + " clauses mapped, " + gaps + " without a ready, deployed or enabled use case" }),
                el("label", { "class": "ucm-sub" }, el("input", {
                    type: "checkbox", checked: state.gaps ? "checked" : null,
                    onchange: function (e) { state.gaps = e.target.checked ? "1" : ""; persist(); renderControls(target); }
                }), " Gaps only"),
                el("button", { "class": "btn", text: "Export evidence (CSV)", onclick: function () { exportEvidence(exportBox, "csv"); } }),
                el("button", { "class": "btn", text: "Export evidence (JSON)", onclick: function () { exportEvidence(exportBox, "json"); } })));
            target.appendChild(exportBox);
            var body = el("tbody", {});
            data.controls.filter(function (c) { return !state.gaps || c.gap; }).forEach(function (c) {
                body.appendChild(el("tr", { "class": state.clause === c.control ? "ucm-row-active" : "" },
                    el("td", { "class": "ucm-mono" }, el("a", { href: "#", text: c.control, onclick: function (e) {
                        e.preventDefault(); state.clause = c.control; persist(); renderClause(clauseBox);
                    } })),
                    el("td", {}, levelCell(c.level), c.gap ? ucm.badge("gap", "warn") : null),
                    el("td", { text: String(c.counts.catalogue) }),
                    el("td", {}, c.use_cases.slice(0, 10).map(function (id) {
                        return el("a", { "class": "ucm-chip", href: "ucm_usecase?id=" + encodeURIComponent(id), text: id });
                    }))));
            });
            target.appendChild(el("table", { "class": "ucm-table" }, el("thead", {}, el("tr", {},
                ["Clause", "Best level", "Use cases", "Examples"].map(function (h) { return el("th", { text: h }); }))), body));
            target.appendChild(clauseBox);
            renderClause(clauseBox);
        }).fail(failBox(target, "Could not load controls."));
    }

    function renderOperations(target) {
        ucm.clear(target);
        target.appendChild(el("h3", { text: "Run status of deployed searches" }));
        var box = el("div", { "class": "ucm-loading", text: "Reading scheduler logs…" });
        target.appendChild(box);
        ucm.get("operations", { hours: state.hours }).done(function (data) {
            ucm.clear(box).className = "";
            if (!data.available) {
                box.appendChild(ucm.stateBox("info", "Run status is not available.", data.reason));
                return;
            }
            if (!data.items.length) {
                box.appendChild(ucm.stateBox("empty", "No searches are deployed yet.", ""));
                return;
            }
            if (data.truncated) {
                box.appendChild(ucm.stateBox("warn", "The scheduler log result was truncated.",
                    "Searches without a row are shown as unknown, not as never run."));
            }
            var body = el("tbody", {});
            data.items.forEach(function (i) {
                body.appendChild(el("tr", {},
                    el("td", { "class": "ucm-title" }, el("a", { href: "ucm_usecase?id=" + encodeURIComponent(i.content_id), text: i.title || i.content_id }),
                        el("div", { "class": "ucm-sub ucm-mono", text: i.saved_search || "" })),
                    el("td", {}, ucm.badge(i.health === "failing_dispatch" ? "failing at dispatch" : i.health.replace("_", " "), HEALTH_KIND[i.health] || "neutral"),
                        (i.advisories || []).map(function (f) { return el("div", { "class": "ucm-sub", title: f.code, text: f.message }); })),
                    el("td", { text: i.runs + " (" + i.succeeded + " ok, " + i.skipped + " skipped, " + i.other + " other" +
                        (i.dispatch_errors ? ", " + i.dispatch_errors + " failed at dispatch" : "") + ")" }),
                    el("td", { text: String(i.runs_with_results) }),
                    el("td", { text: i.last_run ? new Date(i.last_run * 1000).toISOString().replace("T", " ").substring(0, 19) + " UTC, " + (i.last_status || "") : "" })));
            });
            box.appendChild(el("table", { "class": "ucm-table" }, el("thead", {}, el("tr", {},
                ["Use case", "Health", "Runs in window", "Runs with results", "Last run"].map(function (h) { return el("th", { text: h }); }))), body));
        }).fail(failBox(box, "Could not read run status."));
    }

    function load() {
        persist();
        ucm.clear(root);
        root.appendChild(el("div", { "class": "ucm-header" }, el("h2", { text: "Coverage" }),
            el("div", { "class": "ucm-sub", text: "How far the catalogue covers MITRE ATT&CK and regulatory frameworks: mapped in the catalogue, data ready, deployed, enabled and, optionally, ran without error (not a statement about data)." })));
        var toolbar = el("div", { "class": "ucm-toolbar" });
        var matrixBox = el("div", { "class": "ucm-loading", text: "Loading matrix…" });
        var techniqueBox = el("div", {});
        var frameworksBox = el("div", {});
        var opsBox = el("div", {});
        root.appendChild(toolbar);
        root.appendChild(matrixBox);
        root.appendChild(techniqueBox);
        root.appendChild(frameworksBox);
        root.appendChild(opsBox);
        ucm.get("frameworks", query()).done(function (data) {
            var defs = data.definitions || [];
            var ids = [];
            defs.forEach(function (d) { if (ids.indexOf(d.framework_id) < 0) { ids.push(d.framework_id); } });
            toolbar.appendChild(select(ids.map(function (id) {
                var d = defs.filter(function (x) { return x.framework_id === id; })[0];
                return { value: id, label: d.name };
            }), state.framework_id, function (v) { state.framework_id = v; state.version = ""; state.technique = ""; load(); }));
            toolbar.appendChild(select(defs.filter(function (d) { return d.framework_id === state.framework_id; }).map(function (d) {
                return { value: d.version, label: "Version " + d.version + (d.active ? " (active)" : "") };
            }), state.version, function (v) { state.version = v; load(); }, "Active version"));
            toolbar.appendChild(select(ucm.DOMAINS.map(function (d) { return { value: d, label: d.replace("_", " ") }; }),
                state.domain, function (v) { state.domain = v; load(); }, "All domains"));
            toolbar.appendChild(el("label", { "class": "ucm-sub" }, el("input", {
                type: "checkbox", checked: state.operational ? "checked" : null,
                onchange: function (e) { state.operational = e.target.checked ? "1" : ""; load(); }
            }), " Include run status"));
            if (state.operational) {
                toolbar.appendChild(select([1, 4, 24, 72, 168].map(function (h) { return { value: String(h), label: "Last " + (h < 24 ? h + " h" : h / 24 + " d") }; }),
                    state.hours, function (v) { state.hours = v; load(); }));
            }
            renderFrameworks(frameworksBox, data);
        }).fail(failBox(toolbar, "Could not load frameworks."));
        ucm.get("frameworks/matrix", query({ framework_id: state.framework_id, version: state.version }))
            .done(function (m) { matrixBox.className = ""; renderMatrix(matrixBox, m); })
            .fail(failBox(matrixBox, "Could not load the matrix."));
        renderTechnique(techniqueBox);
        if (state.operational) { renderOperations(opsBox); }
    }

    load();
}
