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
        clause: params.clause || "", gaps: params.gaps || "",
        cat: params.cat || "", catv: params.catv || "", catq: params.catq || "", catu: params.catu || "",
        catg: params.catg || "", catw: params.catw || ""
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
            technique: state.technique, framework: state.framework, clause: state.clause, gaps: state.gaps,
            cat: state.cat, catv: state.catv, catq: state.catq, catu: state.catu, catg: state.catg, catw: state.catw });
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
            (c.operational ? ", " + c.operational + " ran without error" : "") +
            (t.grade ? "\nGrade " + t.grade.toFixed(2) + " (" + ({ direct: "a use case maps to this technique", sub: "through a sub-technique",
                parent: "through the parent technique" }[t.basis] || t.basis) + ")" : "") +
            (t.elsewhere ? "\nEnabled elsewhere: " + t.elsewhere + " use case(s) you matched to a search that runs in another app. Not counted above." : "");
    }

    function gapSection(title, help, rows, columns) {
        if (!rows.length) { return null; }
        return el("details", { "class": "ucm-details" }, el("summary", { text: title + " (" + rows.length + ")" }),
            el("div", { "class": "ucm-sub", text: help }),
            el("table", { "class": "ucm-table" }, el("thead", {}, el("tr", {}, columns.map(function (c) { return el("th", { text: c[0] }); }))),
                el("tbody", {}, rows.map(function (g) {
                    return el("tr", {}, columns.map(function (c) { return c[1](g); }));
                }))));
    }

    function gapColumns(extra) {
        return [["Technique", function (g) {
            return el("td", {}, el("a", { href: "#", "class": "ucm-mono", text: g.id, onclick: function (e) {
                e.preventDefault(); state.technique = g.id; persist(); load();
            } }), " " + g.name, g.elsewhere ? ucm.badge("enabled elsewhere", "info") : null);
        }], ["Tactics", function (g) { return el("td", { "class": "ucm-sub", text: (g.tactics || []).join(", ") }); }]].concat(extra);
    }

    function renderGaps(target, m) {
        var g = m.gaps;
        if (!g) { return; }
        var parts = [
            gapSection("Data is ready, nothing is deployed", "Use cases for these techniques have all the data they need (readiness: ready) and none is deployed. The shortest path to more coverage.",
                g.data_ready, gapColumns([["Ready use cases", function (r) { return el("td", { text: String(r.ready) }); }],
                    ["In catalogue", function (r) { return el("td", { text: String(r.catalogue) }); }]])),
            gapSection("Content exists, data is missing", "The catalogue has use cases for these techniques but none is ready. Open a use case to see which data source is missing.",
                g.content_no_data, gapColumns([["In catalogue", function (r) { return el("td", { text: String(r.catalogue) }); }]])),
            gapSection("No content in the catalogue", "No imported use case maps to these techniques. A sub-technique may still be covered by a use case for its parent (see the grade).",
                g.no_content, gapColumns([]))
        ].filter(Boolean);
        if (!parts.length) { return; }
        target.appendChild(el("h3", { text: "Coverage gaps" }));
        parts.forEach(function (p) { target.appendChild(p); });
        if (g.truncated) { target.appendChild(el("div", { "class": "ucm-sub", text: "Each list shows its first 300 techniques." })); }
    }

    function cell(t, sub) {
        var n = (t.counts && t.counts.catalogue) || 0;
        return el("a", {
            "class": "ucm-matrix-cell" + (t.level ? " lvl-" + t.level : "") + (sub ? " ucm-matrix-sub" : "") + (t.elsewhere ? " ucm-matrix-elsewhere" : "") +
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
        if (tot.grade_avg !== undefined) {
            target.appendChild(el("div", { "class": "ucm-cards ucm-kpis" }, ucm.kpiCard({
                label: "Graded coverage", value: Math.round(100 * tot.grade_avg) + "%", detail: "average over " + tot.techniques + " techniques",
                how: "Each technique gets the best single use case: its level (ready 0.25, deployed 0.5, enabled 0.9, ran without error 1.0) times how directly it maps " +
                    "(this technique 1.0, through a sub-technique 0.6, through the parent technique 0.4). Only a use case that ran without error reaches 1.0." })));
        }
        if (tot.elsewhere) {
            target.appendChild(el("div", { "class": "ucm-cards ucm-kpis" }, ucm.kpiCard({
                label: "Enabled elsewhere", value: String(tot.elsewhere), detail: "techniques with a matched search in another app",
                how: "Techniques with a use case you matched to an enabled search that runs in another app (Data Inventory, Detections already running here). " +
                    "Shown with a dashed border on the matrix. These never count as deployed or enabled by SUNavigator, and do not change the percentages above."
            })));
        }
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
        renderGaps(target, m);
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

    var ASSESSED = ["control", "enhancement", "requirement", "subcategory"];
    var KIND_LABEL = { family: "family", "function": "function", category: "category", control: "control",
        enhancement: "enhancement", requirement: "requirement", subcategory: "subcategory" };

    function catalogueRowVisible(row, filters) {
        var assessed = ASSESSED.indexOf(row.kind) >= 0;
        if (row.withdrawn && !row.mapped && !filters.withdrawn) { return false; }
        if (!filters.q && !filters.unmapped && !filters.gaps) { return true; }
        if (!assessed) { return false; }
        if (filters.unmapped && (row.mapped || row.withdrawn)) { return false; }
        if (filters.gaps && !row.gap) { return false; }
        if (filters.q && (row.id + " " + row.title).toLowerCase().indexOf(filters.q) < 0) { return false; }
        return true;
    }

    var canAssess = false;
    var STATUS_LABEL = { implemented: "Implemented", partially_implemented: "Partially implemented", planned: "Planned",
        not_implemented: "Not implemented", not_applicable: "Not applicable" };
    var STATUS_KIND = { implemented: "ok", partially_implemented: "warn", planned: "warn", not_implemented: "critical", not_applicable: "info" };
    var RESULT_LABEL = { met: "Met", not_met: "Not met", not_applicable: "Not applicable" };
    var POAM_LABEL = { open: "Open", in_progress: "In progress", closed: "Closed", risk_accepted: "Risk accepted" };

    function when(iso) { return iso ? String(iso).replace("T", " ").slice(0, 16) + " UTC" : ""; }

    function assessBadge(a) {
        if (!a || !a.status) { return el("span", { "class": "ucm-sub", text: "Not assessed" }); }
        return el("span", {}, ucm.badge(STATUS_LABEL[a.status] || a.status, STATUS_KIND[a.status] || "neutral"),
            a.complete === false ? ucm.badge("incomplete", "warn") : null,
            a.stale_version ? ucm.badge("older catalogue version", "info") : null);
    }

    function assessSummary(box, assess) {
        ucm.clear(box);
        var s = assess.summary, sc = assess.score;
        var items = [["Assessed", s.assessed + " of " + s.controls, ""], ["Not assessed", s.not_assessed, s.not_assessed ? "warn" : ""]];
        Object.keys(STATUS_LABEL).forEach(function (k) { items.push([STATUS_LABEL[k], (s.by_status || {})[k] || 0, ""]); });
        if (sc) {
            items.push(["Score now", sc.score, sc.blocked_by.length ? "warn" : ""]);
            items.push(["Best possible score", sc.ceiling, ""]);
        }
        box.appendChild(el("h4", { text: "Assessment" }));
        box.appendChild(el("div", { "class": "ucm-cards" }, items.map(function (c) {
            return el("div", { "class": "ucm-card" + (c[2] ? " ucm-card-" + c[2] : "") },
                el("div", { "class": "ucm-card-value", text: String(c[1]) }), el("div", { "class": "ucm-card-label", text: c[0] }));
        })));
        if (sc) {
            box.appendChild(el("div", { "class": "ucm-sub", text: "Score now counts every requirement that is not assessed as not implemented, so it can only go up as " +
                "you assess. Best possible score assumes every requirement not assessed yet will be implemented. " + sc.note +
                " Points lost so far: " + sc.points_lost + "." }));
            if (sc.blocked_by.length) {
                box.appendChild(ucm.stateBox("warn", "A requirement that must be implemented is not: " + sc.blocked_by.join(", "),
                    "The methodology does not let the assessment pass while it is open, whatever the score."));
            }
        }
        if (s.stale_version) {
            box.appendChild(el("div", { "class": "ucm-sub", text: s.stale_version + " assessment(s) were made against another version of this catalogue. Open them to confirm they still apply." }));
        }
        if (s.objectives) { box.appendChild(el("div", { "class": "ucm-sub", text: s.objectives_assessed + " of " + s.objectives + " assessment objectives have a result." })); }
        if ((assess.orphaned || []).length) {
            box.appendChild(el("div", { "class": "ucm-sub", text: assess.orphaned.length + " stored assessment(s) refer to controls this catalogue version no longer has: " +
                assess.orphaned.slice(0, 10).map(function (o) { return o.control_id; }).join(", ") + "." }));
        }
    }

    function historyList(a) {
        if (!a || !(a.history || []).length) { return null; }
        return el("details", { "class": "ucm-details" }, el("summary", { text: "History (" + a.history.length + ")" }),
            el("ul", {}, a.history.slice().reverse().map(function (h) {
                return el("li", { "class": "ucm-sub", text: when(h.at) + " " + h.by + ": " + (STATUS_LABEL[h.status] || h.status || h.action || "") +
                    (h.note ? " (" + h.note + ")" : "") });
            })));
    }

    function openEditor(box, row, data, assess, refresh) {
        ucm.clear(box);
        box.appendChild(el("div", { "class": "ucm-loading", text: "Loading " + row.id + "…" }));
        ucm.get("assessment/control", { framework_id: data.catalogue.framework_id, version: data.catalogue.version, control_id: row.id }).done(function (res) {
            ucm.clear(box);
            var control = res.control, a = res.assessment;
            var error = el("div", { "class": "ucm-modal-error", role: "alert" });
            var note = el("textarea", { "class": "ucm-input", maxlength: 2000, "aria-label": "Why this assessment" });
            note.value = "";
            var statusSel = null;
            var objectiveSel = [];
            var form = el("div", {});
            if (control.objectives && control.objectives.length) {
                form.appendChild(el("div", { "class": "ucm-sub", text: "The status of this requirement comes from its " + control.objectives.length +
                    " assessment objectives: met if every one is met or not applicable, not implemented if any is not met." }));
                var body = el("tbody", {});
                control.objectives.forEach(function (o) {
                    var cur = (a && a.objectives && a.objectives[o.id]) || {};
                    var sel = el("select", { "class": "ucm-input", "aria-label": "Result for " + o.id },
                        el("option", { value: "", text: "Not assessed" }),
                        ["met", "not_met", "not_applicable"].map(function (k) { return el("option", { value: k, text: RESULT_LABEL[k] }); }));
                    sel.value = cur.result || "";
                    var objNote = el("input", { type: "text", "class": "ucm-input", maxlength: 500, placeholder: "Note (needed for not applicable)", "aria-label": "Note for " + o.id });
                    objNote.value = cur.note || "";
                    objectiveSel.push({ id: o.id, sel: sel, note: objNote, was: cur.result || "", wasNote: cur.note || "" });
                    body.appendChild(el("tr", {}, el("td", { "class": "ucm-mono", text: o.id }), el("td", { text: o.text }), el("td", {}, sel), el("td", {}, objNote)));
                });
                form.appendChild(el("table", { "class": "ucm-table" }, el("thead", {}, el("tr", {},
                    ["Objective", "Determination statement", "Result", "Note"].map(function (h) { return el("th", { text: h }); }))), body));
            } else {
                statusSel = el("select", { "class": "ucm-input", "aria-label": "Status" },
                    el("option", { value: "", text: "Choose a status" }),
                    Object.keys(STATUS_LABEL).map(function (k) { return el("option", { value: k, text: STATUS_LABEL[k] }); }));
                statusSel.value = (a && a.status) || "";
                form.appendChild(el("label", { "class": "ucm-sub" }, "Status ", statusSel));
            }
            var save = el("button", { "class": "btn btn-primary", type: "button", text: "Save assessment", onclick: function () {
                var req = { framework_id: data.catalogue.framework_id, version: data.catalogue.version, control_id: control.id, note: note.value.trim() };
                if (statusSel) {
                    req.status = statusSel.value;
                } else {
                    req.objectives = {};
                    objectiveSel.forEach(function (o) {
                        var changed = o.sel.value !== o.was || (o.sel.value && o.note.value !== o.wasNote);
                        if (changed) { req.objectives[o.id] = o.sel.value ? { result: o.sel.value, note: o.note.value.trim() } : { result: "not_assessed" }; }
                    });
                }
                ucm.post("assessment", req).done(function (out) {
                    assess.assessments[control.id] = out.assessment;
                    assess.summary = out.summary;
                    assess.score = out.score;
                    refresh(control.id);
                    openEditor(box, row, data, assess, refresh);
                }).fail(function (err) { error.textContent = err.message; });
            } });
            var buttons = el("div", { "class": "ucm-actions" }, save,
                a ? el("button", { "class": "btn", type: "button", text: "Remove assessment", onclick: function () {
                    ucm.askText("Remove the assessment of " + control.id, "The assessment is removed and the removal is recorded with your reason.",
                        { label: "Reason", minLength: 5, maxLength: 500 }, "Remove", function (reason) {
                            ucm.post("assessment/clear", { framework_id: data.catalogue.framework_id, version: data.catalogue.version, control_id: control.id, note: reason })
                                .done(function (out) {
                                    delete assess.assessments[control.id];
                                    assess.summary = out.summary; assess.score = out.score;
                                    refresh(control.id);
                                    openEditor(box, row, data, assess, refresh);
                                }).fail(function (err) { ucm.notify(err.message); });
                        });
                } }) : null,
                el("button", { "class": "btn", type: "button", text: "Add plan item", onclick: function () { poamForm.prefill(control.id); } }),
                el("button", { "class": "btn", type: "button", text: "Close", onclick: function () { ucm.clear(box); } }));
            box.appendChild(el("div", { "class": "ucm-assess-editor" },
                el("h4", {}, el("span", { "class": "ucm-mono", text: control.id }), " " + control.title),
                a ? el("div", { "class": "ucm-sub", text: "Assessed by " + a.assessed_by + " on " + when(a.assessed_at) +
                    (a.first_assessed_by && a.first_assessed_by !== a.assessed_by ? "; first assessed by " + a.first_assessed_by + " on " + when(a.first_assessed_at) : "") +
                    ". Reason: " + (a.note || "") }) : el("div", { "class": "ucm-sub", text: "Not assessed yet." }),
                form,
                el("label", { "class": "ucm-modal-label" }, el("span", { text: "Why (required, at least 5 characters; at least 10 for not applicable)" }), note),
                error, buttons, historyList(a)));
        }).fail(function (err) { ucm.clear(box).appendChild(ucm.stateBox("error", "Could not load the control.", err.message)); });
    }

    /* Informational (32 CFR 170.21); it never blocks a plan item and is not a CMMC status determination. */
    function eligibilityNote(eligibility) {
        if (!eligibility || eligibility.eligible) { return null; }
        return el("div", { "class": "ucm-sub" }, ucm.badge("may not count toward Conditional status", "warn"),
            el("ul", {}, eligibility.reasons.map(function (r) { return el("li", { text: r }); })),
            el("span", { text: eligibility.basis + ". " + eligibility.notice }));
    }

    function poamDate(item) {
        return el("span", {}, item.due || "", item.overdue ? " " : "", item.overdue ? ucm.badge("overdue", "error") : null);
    }

    function renderPoam(target, data, assess) {
        ucm.clear(target);
        var fw = data.catalogue.framework_id;
        target.appendChild(el("h4", { text: "Plan of action and milestones" }));
        var listBox = el("div", { "class": "ucm-loading", text: "Loading plan items…" });
        var stateSel = el("select", { "class": "ucm-input", "aria-label": "Plan item state", onchange: function () { state.poamState = stateSel.value; load(); } },
            el("option", { value: "", text: "All states" }),
            Object.keys(POAM_LABEL).map(function (k) { return el("option", { value: k, text: POAM_LABEL[k] }); }));
        stateSel.value = state.poamState || "";
        var controlIn = el("input", { type: "text", "class": "ucm-input", placeholder: "Control id", "aria-label": "Control id" });
        var titleIn = el("input", { type: "text", "class": "ucm-input", placeholder: "Title", maxlength: 200, "aria-label": "Title" });
        var weakIn = el("textarea", { "class": "ucm-input", maxlength: 2000, placeholder: "What is weak or missing", "aria-label": "Weakness" });
        var ownerIn = el("input", { type: "text", "class": "ucm-input", placeholder: "Owner", maxlength: 100, "aria-label": "Owner" });
        var dueIn = el("input", { type: "text", "class": "ucm-input", placeholder: "Due YYYY-MM-DD", maxlength: 10, "aria-label": "Due date" });
        var mileIn = el("textarea", { "class": "ucm-input", placeholder: "Milestones, one per line. Start a line with a date (YYYY-MM-DD) to give that milestone a due date.", "aria-label": "Milestones" });
        var formErr = el("div", { "class": "ucm-modal-error", role: "alert" });
        var formBox = el("details", { "class": "ucm-details" }, el("summary", { text: "Add a plan item" }),
            el("div", { "class": "ucm-sub", text: "A plan item records how and when a weakness will be fixed. It does not change the control's status." }),
            controlIn, titleIn, weakIn, ownerIn, dueIn, mileIn, formErr,
            el("div", { "class": "ucm-actions" }, el("button", { "class": "btn btn-primary", type: "button", text: "Add plan item", onclick: function () {
                var milestones = mileIn.value.split("\n").map(function (l) { return l.trim(); }).filter(Boolean).map(function (l) {
                    var m = /^(\d{4}-\d{2}-\d{2})\s+(.*)$/.exec(l);
                    return m ? { text: m[2], due: m[1] } : { text: l, due: "" };
                });
                ucm.post("poam", { framework_id: fw, version: data.catalogue.version, control_id: controlIn.value.trim(), title: titleIn.value.trim(),
                    weakness: weakIn.value.trim(), owner: ownerIn.value.trim(), due: dueIn.value.trim(), milestones: milestones }).done(function () {
                    renderPoam(target, data, assess);
                }).fail(function (err) { formErr.textContent = err.message; });
            } })));
        target.appendChild(el("div", { "class": "ucm-toolbar" }, stateSel));
        target.appendChild(listBox);
        target.appendChild(formBox);
        poamForm.prefill = function (controlId) { controlIn.value = controlId; formBox.setAttribute("open", "open"); };

        function act(label, item, path, extra, minLength, message) {
            return el("button", { "class": "btn", type: "button", text: label, onclick: function () {
                ucm.askText(label + ": " + item.title, message, { label: "Note", minLength: minLength, maxLength: 500 }, label, function (text) {
                    ucm.post(path, $.extend({ id: item.id, note: text }, extra)).done(load).fail(function (err) { ucm.notify(err.message); });
                });
            } });
        }
        function load() {
            ucm.get("poam", { framework_id: fw, version: data.catalogue.version, state: stateSel.value }).done(function (res) {
                listBox.className = "";
                ucm.clear(listBox);
                var prog = res.programme;
                if (prog) {
                    var blocked = prog.can_pass === false;
                    listBox.appendChild(ucm.stateBox(prog.meets_threshold && !blocked ? "info" : "warn",
                        "Score now " + prog.score + " of " + prog.requirements + " (" + prog.ratio.toFixed(2) + "); a plan of action for Conditional Level 2 status needs at least " + prog.threshold.toFixed(2),
                        prog.basis + ". Closeout must be within 180 days of the status date. " +
                        (blocked ? (prog.meets_threshold ? "The score reaches the threshold, but this is not a pass: " : "Not a pass either way: ") +
                            "the system security plan requirement is not implemented yet" +
                            ((prog.blocked_by || []).length ? " (" + prog.blocked_by.join(", ") + ")" : "") + ". " : "") +
                        prog.notice));
                }
                if (!res.items.length) {
                    listBox.appendChild(ucm.stateBox("empty", "No plan items" + (stateSel.value ? " in this state" : " yet") + ".", ""));
                    return;
                }
                listBox.appendChild(el("div", { "class": "ucm-sub", text: res.counts.open + " open, " + res.counts.in_progress + " in progress, " +
                    res.counts.overdue + " overdue, " + res.counts.closed + " closed, " + res.counts.risk_accepted + " risk accepted." }));
                var body = el("tbody", {});
                res.items.forEach(function (item) {
                    var isOpen = item.state === "open" || item.state === "in_progress";
                    body.appendChild(el("tr", {},
                        el("td", { "class": "ucm-mono", text: item.control_id }),
                        el("td", {}, el("div", { "class": "ucm-title", text: item.title }), el("div", { "class": "ucm-sub", text: item.weakness }),
                            (item.milestones || []).length ? el("ul", {}, item.milestones.map(function (m) {
                                return el("li", { "class": "ucm-sub", text: (m.due ? m.due + " " : "") + m.text });
                            })) : null,
                            item.close_note ? el("div", { "class": "ucm-sub", text: "Closed by " + item.closed_by + " on " + when(item.closed_at) + ": " + item.close_note }) : null,
                            eligibilityNote(item.eligibility)),
                        el("td", { text: item.owner }),
                        el("td", {}, poamDate(item)),
                        el("td", {}, ucm.badge(POAM_LABEL[item.state] || item.state, item.state === "closed" ? "ok" : (item.overdue ? "error" : "info")),
                            item.control_status ? el("div", { "class": "ucm-sub", text: "Control: " + (STATUS_LABEL[item.control_status] || item.control_status) }) : null),
                        el("td", {}, isOpen
                            ? [item.state === "open" ? el("button", { "class": "btn", type: "button", text: "Start", onclick: function () {
                                ucm.post("poam/update", { id: item.id, state: "in_progress" }).done(load).fail(function (err) { ucm.notify(err.message); });
                            } }) : null,
                                act("Close", item, "poam/close", { resolution: "closed" }, 5, "Say what was done."),
                                act("Accept risk", item, "poam/close", { resolution: "risk_accepted" }, 10, "Say why the risk is accepted and by whom (at least 10 characters).")]
                            : act("Reopen", item, "poam/reopen", {}, 5, "Say why this item is open again."))));
                });
                listBox.appendChild(el("table", { "class": "ucm-table" }, el("thead", {}, el("tr", {},
                    ["Control", "Plan item", "Owner", "Due", "State", ""].map(function (h) { return el("th", { text: h }); }))), body));
            }).fail(failBox(listBox, "Could not load plan items."));
        }
        load();
    }
    var poamForm = { prefill: function () {} };

    function renderSnapshots(target, data) {
        ucm.clear(target);
        var fw = data.catalogue.framework_id;
        target.appendChild(el("h4", { text: "Evidence snapshots" }));
        target.appendChild(el("div", { "class": "ucm-sub", text: "A snapshot freezes the assessment, the coverage of every control and the plan items as they are now, with the " +
            "SHA-256 of its content. Snapshots cannot be changed or deleted from the app." }));
        var listBox = el("div", { "class": "ucm-loading", text: "Loading snapshots…" });
        var msg = el("div", { "class": "ucm-sub", role: "status" });
        target.appendChild(el("div", { "class": "ucm-actions" }, el("button", { "class": "btn", type: "button", text: "Take a snapshot", onclick: function () {
            ucm.askText("Take a snapshot", "Records the current assessment of " + data.catalogue.name + " (" + data.catalogue.version_label + ").",
                { label: "Label (optional)", maxLength: 100 }, "Take snapshot", function (label) {
                    ucm.post("assessment/snapshot", { framework_id: fw, version: data.catalogue.version, label: label }).done(load)
                        .fail(function (err) { ucm.notify(err.message); });
                });
        } })));
        target.appendChild(msg);
        target.appendChild(listBox);
        function load() {
            ucm.get("assessment/snapshots", { framework_id: fw, version: data.catalogue.version }).done(function (res) {
                listBox.className = "";
                ucm.clear(listBox);
                if (!res.items.length) { listBox.appendChild(ucm.stateBox("empty", "No snapshots yet.", "")); return; }
                var body = el("tbody", {});
                res.items.forEach(function (s) {
                    body.appendChild(el("tr", {}, el("td", { text: when(s.created_at) }), el("td", { text: s.created_by }), el("td", { text: s.label }),
                        el("td", { text: s.version_label }), el("td", { "class": "ucm-mono", title: s.sha256, text: s.sha256.slice(0, 16) + "…" }),
                        el("td", {}, el("button", { "class": "btn", type: "button", text: "Download", onclick: function () {
                            ucm.get("assessment/snapshot", { id: s.id }).done(function (snap) {
                                download(snap.filename, snap.content, "application/json");
                                msg.textContent = snap.integrity.ok
                                    ? "Downloaded " + snap.filename + ". Integrity check passed. SHA-256 " + snap.sha256
                                    : "WARNING: the stored snapshot does not match its recorded SHA-256 (recorded " + snap.integrity.expected + ", actual " + snap.integrity.actual + ").";
                            }).fail(function (err) { ucm.notify(err.message); });
                        } }))));
                });
                listBox.appendChild(el("table", { "class": "ucm-table" }, el("thead", {}, el("tr", {},
                    ["Taken", "By", "Label", "Catalogue version", "SHA-256", ""].map(function (h) { return el("th", { text: h }); }))), body));
            }).fail(failBox(listBox, "Could not load snapshots."));
        }
        load();
    }

    function catalogueTable(rows, depths, data, clauseBox, ctx) {
        var body = el("tbody", {});
        rows.forEach(function (row) {
            var depth = Math.min(depths[row.id] || 0, 3);
            var mapped = row.mapped && row.clauses && row.clauses.length;
            var idCell = mapped
                ? el("a", { href: "#", text: row.id, onclick: function (e) {
                    e.preventDefault();
                    state.framework = "regulation:" + data.regulation_ids[0]; state.clause = row.clauses[0]; persist();
                    renderClause(clauseBox);
                } })
                : el("span", { text: row.id });
            body.appendChild(el("tr", { "class": "ucm-depth-" + depth + (ASSESSED.indexOf(row.kind) < 0 ? " ucm-group-row" : "") },
                el("td", { "class": "ucm-mono ucm-catalogue-id" }, idCell),
                el("td", { "class": "ucm-title" }, el("span", { text: row.title }), " ",
                    el("span", { "class": "ucm-sub", text: KIND_LABEL[row.kind] || row.kind }),
                    row.withdrawn ? ucm.badge("withdrawn", "neutral") : null),
                el("td", {}, ASSESSED.indexOf(row.kind) < 0
                    ? el("span", { "class": "ucm-sub", text: row.below.controls ? row.below.mapped + " of " + row.below.controls + " mapped" : "" })
                    : (row.mapped ? levelCell(row.level) : (row.withdrawn ? null : ucm.badge("no mapped use case", "warn")))),
                el("td", {}, (row.use_cases || []).slice(0, 6).map(function (id) {
                    return el("a", { "class": "ucm-chip", href: "ucm_usecase?id=" + encodeURIComponent(id), text: id });
                }), row.counts && row.counts.catalogue > 6 ? el("span", { "class": "ucm-sub", text: " +" + (row.counts.catalogue - 6) }) : null),
                ctx && ctx.assess ? assessCell(row, ctx) : null));
        });
        return el("table", { "class": "ucm-table ucm-catalogue" }, el("thead", {}, el("tr", {},
            (ctx && ctx.assess ? ["Control", "Title", "Best level", "Use cases", "Assessment"] : ["Control", "Title", "Best level", "Use cases"]).map(function (h) { return el("th", { text: h }); }))), body);
    }

    function assessCell(row, ctx) {
        var td = el("td", {});
        if (ASSESSED.indexOf(row.kind) < 0 || row.withdrawn) { return td; }
        function fill() {
            ucm.clear(td);
            td.appendChild(assessBadge(ctx.assess.assessments[row.id]));
            td.appendChild(document.createTextNode(" "));
            td.appendChild(el("button", { "class": "btn", type: "button", text: ctx.assess.assessments[row.id] ? "Edit" : "Assess",
                "aria-label": "Assess " + row.id, onclick: function () { ctx.open(row); } }));
            if (row.weight !== undefined) { td.appendChild(el("span", { "class": "ucm-sub", text: " " + row.weight + " pt" })); }
        }
        ctx.cells[row.id] = fill;
        fill();
        return td;
    }

    function renderCatalogueBody(target, data, assess) {
        ucm.clear(target);
        var ctx = null;
        var summaryBox = el("div", {});
        var editorBox = el("div", {});
        var planBox = el("div", {});
        var snapBox = el("div", {});
        var t = data.totals;
        var cat = data.catalogue;
        var clauseBox = el("div", {});
        var cards = el("div", { "class": "ucm-cards" });
        [["Controls", t.controls, ""], ["With a mapped use case", t.mapped, ""], ["Without any mapped use case", t.unmapped, "warn"],
            ["Data ready or better", t.ready, ""], ["Deployed or better", t.deployed, ""], ["Enabled", t.enabled, ""]].forEach(function (c) {
            cards.appendChild(el("div", { "class": "ucm-card" + (c[2] ? " ucm-card-" + c[2] : "") },
                el("div", { "class": "ucm-card-value", text: String(c[1]) }), el("div", { "class": "ucm-card-label", text: c[0] })));
        });
        target.appendChild(cards);
        if (assess) {
            ctx = { assess: assess, cells: {}, open: function (row) {
                openEditor(editorBox, row, data, assess, function (id) {
                    if (ctx.cells[id]) { ctx.cells[id](); }
                    assessSummary(summaryBox, assess);
                });
                if (editorBox.scrollIntoView) { editorBox.scrollIntoView(); }
            } };
            assessSummary(summaryBox, assess);
            target.appendChild(summaryBox);
            target.appendChild(editorBox);
        }
        target.appendChild(el("div", { "class": "ucm-sub", text: cat.name + " (" + cat.version_label + ")." +
            (t.withdrawn ? " " + t.withdrawn + " withdrawn controls are not counted." : "") +
            " Mapped means the catalogue provider mapped at least one use case to the control; it says nothing about how well the control is met." }));
        var filters = { q: state.catq.toLowerCase(), unmapped: !!state.catu, gaps: !!state.catg, withdrawn: !!state.catw };
        var active = !!(filters.q || filters.unmapped || filters.gaps);
        var depths = {};
        var byId = {};
        data.controls.forEach(function (r) { byId[r.id] = r; depths[r.id] = r.parent ? (depths[r.parent] || 0) + 1 : 0; });
        var groups = [];
        data.controls.forEach(function (r) {
            if (!r.parent) { groups.push({ top: r, rows: [] }); } else { groups[groups.length - 1].rows.push(r); }
        });
        var shown = 0;
        groups.forEach(function (g) {
            var rows = g.rows.filter(function (r) { return catalogueRowVisible(r, filters); });
            if (active && !rows.length) { return; }
            shown++;
            var inner = el("div", {});
            var filled = false;
            function fill() {
                if (filled) { return; }
                filled = true;
                inner.appendChild(rows.length ? catalogueTable(rows, depths, data, clauseBox, ctx)
                    : el("div", { "class": "ucm-sub", text: "Nothing to show here with the current filters." }));
            }
            var below = g.top.below;
            var details = el("details", { "class": "ucm-details", ontoggle: function (e) { if (e.target && e.target.open !== false) { fill(); } } },
                el("summary", {}, el("span", { "class": "ucm-mono", text: g.top.id }), " " + g.top.title + " ",
                    el("span", { "class": "ucm-sub", text: below.controls
                        ? below.mapped + " of " + below.controls + " mapped, " + below.ready + " data ready or better, " + (below.controls - below.mapped) + " without a use case"
                        : "" })),
                inner);
            if (active) { details.setAttribute("open", "open"); fill(); }
            target.appendChild(details);
        });
        if (!shown) { target.appendChild(ucm.stateBox("empty", "No control matches these filters.", "")); }
        target.appendChild(clauseBox);
        if (state.framework === "regulation:" + data.regulation_ids[0] && state.clause) { renderClause(clauseBox); }
        if (data.unmatched_count) {
            var body = el("tbody", {});
            data.unmatched.forEach(function (u) {
                body.appendChild(el("tr", {}, el("td", { "class": "ucm-mono", text: u.clause }), el("td", {}, levelCell(u.level)),
                    el("td", {}, u.use_cases.slice(0, 6).map(function (id) {
                        return el("a", { "class": "ucm-chip", href: "ucm_usecase?id=" + encodeURIComponent(id), text: id });
                    }))));
            });
            target.appendChild(el("details", { "class": "ucm-details" },
                el("summary", { text: "Mapped clauses that are not in this catalogue (" + data.unmatched_count + ")" }),
                el("div", { "class": "ucm-sub", text: "Use cases map these clauses, but no control here has that identifier: usually another version of the standard, or a spelling this catalogue does not use. They are not counted above." }),
                el("table", { "class": "ucm-table" }, el("thead", {}, el("tr", {},
                    ["Clause as mapped", "Best level", "Use cases"].map(function (h) { return el("th", { text: h }); }))), body)));
        }
        if (assess) {
            target.appendChild(planBox);
            renderPoam(planBox, data, assess);
            target.appendChild(snapBox);
            renderSnapshots(snapBox, data);
        }
        target.appendChild(el("div", { "class": "ucm-sub ucm-attribution" }, cat.attribution + " ",
            cat.source ? el("span", { "class": "ucm-mono", text: cat.source }) : null, cat.modified ? " (content modified " + cat.modified.slice(0, 10) + ")" : ""));
    }

    function renderCatalogues(target, defs) {
        ucm.clear(target);
        var cats = (defs || []).filter(function (d) { return d.kind === "controls"; });
        if (!cats.length) { return; }
        var ids = [];
        cats.forEach(function (d) { if (ids.indexOf(d.framework_id) < 0) { ids.push(d.framework_id); } });
        if (ids.indexOf(state.cat) < 0) { state.cat = ids[0]; state.catv = ""; }
        target.appendChild(el("h3", { text: "Control catalogues" }));
        target.appendChild(el("div", { "class": "ucm-sub", text: "A catalogue lists every control of a standard, so a control that no use case maps to is visible instead of missing. " +
            "Identifiers and titles come from public NIST content; the mapping of use cases to controls comes from the catalogue provider." }));
        var versions = cats.filter(function (d) { return d.framework_id === state.cat; });
        var bodyBox = el("div", { "class": "ucm-loading", text: "Loading catalogue…" });
        function reload() { persist(); renderCatalogues(target, defs); }
        target.appendChild(el("div", { "class": "ucm-toolbar" },
            select(ids.map(function (id) { return { value: id, label: cats.filter(function (d) { return d.framework_id === id; })[0].name }; }),
                state.cat, function (v) { state.cat = v; state.catv = ""; reload(); }),
            select(versions.map(function (d) { return { value: d.version, label: d.version_label + (d.active ? " (active)" : "") }; }),
                state.catv, function (v) { state.catv = v; reload(); }, "Active version"),
            el("input", { type: "search", "class": "ucm-input", placeholder: "Find a control", value: state.catq, onchange: function (e) {
                state.catq = e.target.value.trim(); reload(); } }),
            el("label", { "class": "ucm-sub" }, el("input", { type: "checkbox", checked: state.catu ? "checked" : null,
                onchange: function (e) { state.catu = e.target.checked ? "1" : ""; reload(); } }), " No mapped use case"),
            el("label", { "class": "ucm-sub" }, el("input", { type: "checkbox", checked: state.catg ? "checked" : null,
                onchange: function (e) { state.catg = e.target.checked ? "1" : ""; reload(); } }), " Gaps (below data ready)"),
            el("label", { "class": "ucm-sub" }, el("input", { type: "checkbox", checked: state.catw ? "checked" : null,
                onchange: function (e) { state.catw = e.target.checked ? "1" : ""; reload(); } }), " Show withdrawn")));
        target.appendChild(bodyBox);
        ucm.get("frameworks/catalogue", query({ framework_id: state.cat, version: state.catv })).done(function (data) {
            if (!canAssess) { bodyBox.className = ""; renderCatalogueBody(bodyBox, data, null); return; }
            ucm.get("assessment", { framework_id: data.catalogue.framework_id, version: data.catalogue.version }).done(function (assess) {
                bodyBox.className = "";
                renderCatalogueBody(bodyBox, data, assess);
            }).fail(function () { bodyBox.className = ""; renderCatalogueBody(bodyBox, data, null); });
        }).fail(failBox(bodyBox, "Could not load the catalogue."));
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
        var cataloguesBox = el("div", {});
        var opsBox = el("div", {});
        root.appendChild(toolbar);
        root.appendChild(matrixBox);
        root.appendChild(techniqueBox);
        root.appendChild(frameworksBox);
        root.appendChild(cataloguesBox);
        root.appendChild(opsBox);
        ucm.get("frameworks", query()).done(function (data) {
            var allDefs = data.definitions || [];
            var defs = allDefs.filter(function (d) { return d.kind !== "controls"; });
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
            ucm.rawGet("services/authentication/current-context").done(function (ctxData) {
                var caps = (((ctxData.entry || [])[0] || {}).content || {}).capabilities || [];
                canAssess = caps.indexOf("ucm_assess") >= 0;
            }).always(function () { renderCatalogues(cataloguesBox, allDefs); });
        }).fail(failBox(toolbar, "Could not load frameworks."));
        ucm.get("frameworks/matrix", query({ framework_id: state.framework_id, version: state.version }))
            .done(function (m) { matrixBox.className = ""; renderMatrix(matrixBox, m); })
            .fail(failBox(matrixBox, "Could not load the matrix."));
        renderTechnique(techniqueBox);
        if (state.operational) { renderOperations(opsBox); }
    }

    load();
}
