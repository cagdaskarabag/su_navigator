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
    var root = document.getElementById("ucm-usecase");
    var id = ucm.queryParams().id || "";

    function section(title) {
        var body = Array.prototype.slice.call(arguments, 1);
        return el("div", { "class": "ucm-section" }, el("h3", { text: title }), body);
    }

    function anchored(id, node) { node.setAttribute("id", id); return node; }

    function text(value, empty) {
        return value ? el("div", { "class": "ucm-pre", text: value })
            : el("div", { "class": "ucm-sub", text: empty || "Not provided by the content provider." });
    }

    function kv(pairs) {
        var dl = el("dl", { "class": "ucm-kv" });
        pairs.forEach(function (p) {
            if (p[1] === undefined || p[1] === null || p[1] === "") { return; }
            dl.appendChild(el("dt", { text: p[0] }));
            dl.appendChild(el("dd", {}, p[1] instanceof Node ? p[1] : String(p[1])));
        });
        return dl;
    }

    function spl(title, query) {
        if (!query) { return null; }
        var pre = el("pre", { "class": "ucm-spl", text: query });
        var copy = el("button", { "class": "btn", type: "button", text: "Copy", onclick: function () {
            if (navigator.clipboard) { navigator.clipboard.writeText(query); }
        } });
        return el("div", {}, el("div", { "class": "ucm-actions" }, el("strong", { text: title }), copy), pre);
    }

    function evidenceText(res) {
        var parts = [res.detail || ""];
        if (res.collapsed) {
            parts.unshift("Alternative sourcetype; the group is judged by its best member.");
        }
        if (res.via_mapping) {
            parts.push("Via " + res.via_mapping.origin + " mapping from " + res.via_mapping.value + ".");
        }
        return parts.join(" ");
    }

    function anyOf(r, res) {
        var group = (res && res.any_of) || (r.attributes && r.attributes.any_of);
        return group && group.length ? el("div", { "class": "ucm-sub", text: "any of: " + group.join(", ") }) : null;
    }

    var LEVEL_ORDER = ["critical", "required", "recommended"];
    var STATUS_ORDER = ["not_met", "unknown", "partial", "unverified", "met", "not_applicable"];
    var LEVEL_HELP = "How much the requirement matters. Critical: if checked and not met, the use case is blocked. " +
        "Required: if not met, the use case cannot be ready. Recommended: lowers the score only. Weights in the score are 3, 2 and 1.";
    var SOURCE_HELP = "Where the requirement came from: stated by the content provider, or derived from the SPL.";
    var CONFIDENCE_HELP = "How sure the app is that the requirement is real. Requirements derived from SPL are hypotheses with lower confidence and weight.";

    function requirementRow(r, res) {
        var evidence = res ? evidenceText(res) : (r.notes || "");
        return el("tr", {},
            el("td", { text: r.type }),
            el("td", { "class": "ucm-mono" }, r.value, anyOf(r, res)),
            el("td", {}, ucm.badge(r.level, r.level === "critical" ? "critical" : (r.level === "required" ? "high" : "neutral"))),
            el("td", { text: r.source.replace("_", " ") }),
            el("td", { text: r.confidence }),
            el("td", {}, res ? ucm.statusBadge(res.status) : ucm.badge("not assessed", "neutral")),
            el("td", { "class": "ucm-sub" }, evidence,
                res && res.observed && res.observed.length
                    ? el("details", { "class": "ucm-details" }, el("summary", { text: "Observed (" + res.observed.length + ")" }),
                        el("pre", { "class": "ucm-pre ucm-mono", text: res.observed.map(function (o) {
                            return Object.keys(o).filter(function (k) { return o[k] !== null && o[k] !== undefined && o[k] !== ""; })
                                .map(function (k) { return k + "=" + o[k]; }).join("  ");
                        }).join("\n") }))
                    : null));
    }

    function requirementsHead() {
        var head = el("tr", {});
        head.appendChild(el("th", { text: "Type" }));
        head.appendChild(el("th", { text: "Requirement" }));
        head.appendChild(ucm.helpHeader("Level", LEVEL_HELP));
        head.appendChild(ucm.helpHeader("Source", SOURCE_HELP));
        head.appendChild(ucm.helpHeader("Confidence", CONFIDENCE_HELP));
        head.appendChild(ucm.helpHeader("Status", "Result of checking this requirement against the inventory. Hover a status for its meaning."));
        head.appendChild(el("th", { text: "Evidence" }));
        return el("thead", {}, head);
    }

    /* Order rows so the ones that need attention come first; ties keep the provider's order. */
    function sortRequirements(rows, by) {
        var primary = by === "level" ? LEVEL_ORDER : STATUS_ORDER;
        var secondary = by === "level" ? STATUS_ORDER : LEVEL_ORDER;
        function rank(list, v) { var i = list.indexOf(v); return i < 0 ? list.length : i; }
        function key(row, which) {
            return which === "level" ? row.r.level : (row.res ? row.res.status : "unassessed");
        }
        return rows.map(function (row, i) { row.i = i; return row; }).sort(function (x, y) {
            return rank(primary, key(x, by)) - rank(primary, key(y, by)) ||
                rank(secondary, key(x, by === "level" ? "status" : "level")) - rank(secondary, key(y, by === "level" ? "status" : "level")) ||
                x.i - y.i;
        });
    }

    function groupLabel(by, value) {
        if (by === "level") { return value; }
        return value === "unassessed" ? "not assessed" : ({ not_met: "not met", not_applicable: "n/a", unverified: "not verified" }[value] || value);
    }

    /*
     * Rows for the table: each requirement with its result, plus results that have no requirement of their
     * own (the SPL validity check). Readiness counts cover both, so the table must too.
     */
    function requirementRows(reqs, readiness) {
        var byId = {};
        var results = (readiness && readiness.results) || [];
        results.forEach(function (r) { byId[r.req_id] = r; });
        var known = {};
        var rows = reqs.map(function (r) { known[r.req_id] = true; return { r: r, res: byId[r.req_id] }; });
        var extra = results.filter(function (res) { return !known[res.req_id]; }).map(function (res) {
            return { r: { req_id: res.req_id, type: res.type, value: res.value, level: res.level, source: res.source || "derived_spl",
                confidence: res.confidence || "", notes: "" }, res: res, extra: true };
        });
        return { rows: rows.concat(extra), extra: extra.length };
    }

    function requirementsTable(reqs, readiness) {
        var built = requirementRows(reqs, readiness);
        var rows = built.rows;
        if (!rows.length) { return text("", "No requirements could be derived from this record."); }
        var by = readiness ? "status" : "level";
        var holder = el("div", {});
        var grouping = el("select", { "aria-label": "Group requirements by", onchange: function () { draw(grouping.value); } },
            el("option", { value: "status", text: "status" }), el("option", { value: "level", text: "level" }),
            el("option", { value: "none", text: "no grouping" }));
        grouping.value = by;

        function draw(mode) {
            ucm.clear(holder);
            if (mode === "none") {
                holder.appendChild(el("table", { "class": "ucm-table" }, requirementsHead(),
                    el("tbody", {}, rows.map(function (row) { return requirementRow(row.r, row.res); }))));
                return;
            }
            var sorted = sortRequirements(rows.slice(), mode);
            var groups = [];
            sorted.forEach(function (row) {
                var k = mode === "level" ? row.r.level : (row.res ? row.res.status : "unassessed");
                if (!groups.length || groups[groups.length - 1].key !== k) { groups.push({ key: k, rows: [] }); }
                groups[groups.length - 1].rows.push(row);
            });
            groups.forEach(function (g) {
                holder.appendChild(el("h4", { "class": "ucm-group", text: groupLabel(mode, g.key) + " (" + g.rows.length + ")" }));
                holder.appendChild(el("table", { "class": "ucm-table" }, requirementsHead(),
                    el("tbody", {}, g.rows.map(function (row) { return requirementRow(row.r, row.res); }))));
            });
        }
        draw(by);
        return el("div", {}, el("div", { "class": "ucm-actions" }, el("label", { text: "Group by " }, grouping),
            el("span", { "class": "ucm-sub", text: reqs.length + " requirements" + (built.extra
                ? " and " + built.extra + " additional check" + (built.extra > 1 ? "s" : "") + " (for example whether the SPL has been parsed)" : "") })), holder);
    }

    function readinessBox(uc) {
        var rd = uc.readiness;
        var assessBtn = el("button", { "class": "btn", type: "button", text: rd ? "Re-assess now" : "Assess now",
            onclick: function () {
                this.disabled = true;
                ucm.post("readiness/assess", { id: uc.content_id }).done(function () { load(); })
                    .fail(function (err) { ucm.notify(err.message); });
            } });
        if (!rd) {
            return el("div", {}, ucm.stateBox("info", "Readiness: not assessed",
                "This use case has not been evaluated against this deployment yet. Assessment runs automatically after " +
                "environment discovery."),
                el("div", { "class": "ucm-actions" }, assessBtn));
        }
        var counts = rd.counts || {};
        var box = el("div", { "class": "ucm-card" },
            el("div", { "class": "ucm-readiness-head" },
                el("strong", { text: "Readiness" }), ucm.readinessBadge(rd.state),
                el("span", { "class": "ucm-big", text: rd.score === null || rd.score === undefined ? "–" : rd.score + " / 100" }),
                el("span", { "class": "ucm-sub", text: "coverage " + Math.round((rd.coverage || 0) * 100) + "%" }),
                rd.stale ? ucm.badge("stale: " + rd.stale_reasons.join(", "), "warn") : null,
                assessBtn),
            el("div", { "class": "ucm-sub", text: ucm.resultSummary(counts, rd.unverified) +
                ". Evaluated " + rd.evaluated_at + " UTC against discovery " +
                (rd.discovery_at || "–") + "." }),
            rd.blockers && rd.blockers.length ? el("div", {}, el("strong", { text: "Blocked by critical requirement: " }),
                rd.blockers.map(function (b) { return ucm.badge(b.type + ": " + b.value, "critical"); })) : null,
            rd.gaps && rd.gaps.length ? el("div", {}, el("strong", { text: "Unmet required: " }),
                rd.gaps.map(function (g) { return ucm.badge(g.type + ": " + g.value, "high"); })) : null,
            el("div", { "class": "ucm-sub", text: "Readiness is inventory and validation evidence, not a guarantee that the search returns results." }));
        return box;
    }

    function setIntent(uc, intent) {
        ucm.post("selections", { id: uc.content_id, intent: intent }).done(load).fail(function (err) {
            ucm.notify(err.message);
        });
    }

    function selectionBox(uc) {
        var sel = uc.selection;
        return el("div", { "class": "ucm-card" },
            el("div", { "class": "ucm-readiness-head" },
                el("strong", { text: "Selection" }),
                sel ? ucm.badge(sel.intent, sel.intent === "select" ? "ok" : "info") : ucm.badge("not selected", "neutral")),
            el("div", { "class": "ucm-actions" },
                el("button", { "class": "btn btn-primary", type: "button", text: "Select", onclick: function () { setIntent(uc, "select"); } }),
                el("button", { "class": "btn", type: "button", text: "Bookmark", onclick: function () { setIntent(uc, "bookmark"); } }),
                el("button", { "class": "btn", type: "button", text: "Defer", onclick: function () { setIntent(uc, "defer"); } }),
                el("button", { "class": "btn", type: "button", text: "Reject", onclick: function () { setIntent(uc, "reject"); } }),
                sel ? el("button", { "class": "btn", type: "button", text: "Clear", onclick: function () {
                    ucm.post("selections/delete", { id: uc.content_id }).done(load);
                } }) : null),
            el("div", { "class": "ucm-sub", text: "Your selection is stored per user and is not changed by content sync." }));
    }

    function validationBox(uc) {
        var v = uc.validation;
        var parseLine = v
            ? (v.parse_ok ? "Parsed: " + (v.commands || []).join(", ") : ("Parse failed: " + (v.parse_error || "")))
            : "Not parsed yet.";
        if (v && v.side_effects && v.side_effects.length) {
            parseLine += " Side-effect commands (preview refused): " + v.side_effects.join(", ");
        }
        if (v && v.review_commands && v.review_commands.length) {
            parseLine += " Commands needing review (preview refused, approval needs acknowledgment): " + v.review_commands.join(", ");
        }
        var previewLine = (v && v.preview)
            ? ("Last preview: " + v.preview.event_count + " events (" + v.preview.earliest + " → " + v.preview.latest +
                "). Event payloads are not stored.")
            : "No preview run.";
        return el("div", { "class": "ucm-card" },
            el("div", { "class": "ucm-readiness-head" }, el("strong", { text: "SPL validation" }),
                v ? (v.parse_ok ? ucm.badge("parsed", "ok") : ucm.badge("parse failed", "error")) : ucm.badge("not validated", "neutral")),
            el("div", { "class": "ucm-sub", text: parseLine }),
            v && v.lint === undefined ? el("div", { "class": "ucm-sub", text: "SPL lint has not run for this validation; run Parse and sample fields again to check." }) : null,
            v ? ucm.lintBox(v.lint) : null,
            el("div", { "class": "ucm-sub", text: previewLine }),
            el("div", { "class": "ucm-actions" },
                el("button", { "class": "btn btn-primary", type: "button", text: "Parse and sample fields",
                    onclick: function () {
                        this.disabled = true;
                        ucm.post("validate", { id: uc.content_id, sample: true }).done(load)
                            .fail(function (err) { ucm.notify(err.message); });
                    } }),
                el("button", { "class": "btn", type: "button", text: "Bounded preview",
                    onclick: function () {
                        this.disabled = true;
                        ucm.post("preview", { id: uc.content_id }).done(load)
                            .fail(function (err) { ucm.notify(err.message); });
                    } })),
            el("div", { "class": "ucm-sub", text: "Preview forces a short time window and a result cap. Searches with delete, outputlookup, collect, script or similar commands are refused, and so are searches with map, savedsearch, rest or commands outside SUN's read-only list. Field sampling uses a constructed fieldsummary, not the imported pipeline." }));
    }

    var ACTION_LABELS = { submit: "Submit for approval", approve: "Approve", reject: "Reject", deploy: "Deploy (disabled)",
        enable: "Enable", disable: "Disable", rollback: "Roll back", retire: "Retire", verify: "Verify now",
        controltest: "Run control test" };

    function runAction(uc, dep, action) {
        var body = { id: uc.content_id };
        var settings = dep.settings || {};
        var label = ACTION_LABELS[action] || action;
        var revs = (dep.deployment && dep.deployment.revisions) || [];
        var review = (revs[revs.length - 1] || {}).review_commands || [];
        var needsAck = review.length && (action === "approve" || (action === "submit" && settings.require_approval === false));

        function send() {
            ucm.post("deployment/" + action, body).done(load).fail(function (err) { ucm.notify(err.message); });
        }
        function acknowledgeThenSend() {
            if (!needsAck) { send(); return; }
            ucm.confirmAction("Commands need review",
                "This search runs commands SUN cannot verify as read-only: " + review.join(", ") +
                ". They can run other searches or reach data the SPL does not show. Confirm you reviewed them. " +
                "Your acknowledgment is recorded in the audit trail.", "I reviewed them", function () {
                    body.acknowledge_commands = true;
                    send();
                });
        }

        if (action === "enable") {
            var rd = uc.readiness ? uc.readiness.state : "not_assessed";
            var access = dep.scheduler_access || {};
            var readinessBlocked = (settings.block_enable_states || []).indexOf(rd) >= 0;
            if (readinessBlocked || access.status === "not_met") {
                var why = (readinessBlocked ? "Readiness is " + rd + ". " : "") +
                    (access.status === "not_met" ? access.detail + " " : "") + "The override reason is audited.";
                ucm.askText("Override the enable gate", why,
                    { label: "Override reason", minLength: 10, maxLength: 500, multiline: true }, "Enable",
                    function (reason) { body.override_reason = reason; acknowledgeThenSend(); });
                return;
            }
        } else if (action === "retire") {
            ucm.confirmAction("Retire this deployment?", "The saved search is deleted from Splunk.", "Retire",
                acknowledgeThenSend, true);
            return;
        } else if (action === "approve" || action === "reject" || action === "rollback") {
            ucm.askText(label, "Optional note for the audit trail.", { label: "Note", maxLength: 500, multiline: true },
                label, function (note) { body.note = note; acknowledgeThenSend(); });
            return;
        }
        acknowledgeThenSend();
    }

    var CONTROL_TEST_TEXT = {
        passed: "The deployed search returned rows for the fixture's positive events and none for its negative events.",
        failed: "The deployed search did not behave as the fixture expects.",
        content_error: "The search failed with an error while it ran on the test data. The error belongs to the search or the " +
            "data, not to access or time, so fix the content or the fixture and run the test again.",
        inconclusive: "The test could not finish, so the search is neither confirmed nor refuted.",
        not_runnable: "The search cannot be scoped to the test index, so it was not run against any index.",
        no_fixture: "No control fixture is imported for this use case."
    };
    var CONTROL_TEST_KIND = { passed: "info", failed: "error", content_error: "error" };

    function windowBound(value) {
        var n = /^\d+$/.test(String(value)) ? parseInt(value, 10) : NaN;
        return isNaN(n) ? String(value) : new Date(n * 1000).toISOString().replace(/\.\d+Z$/, "Z");
    }

    function windowText(w) {
        if (!w || !w.earliest) { return ""; }
        return "Search window " + windowBound(w.earliest) + " to " + windowBound(w.latest) +
            (w.derived ? ", derived from the fixture timestamps." : ", the default (the fixture timestamps could not be read).");
    }

    function fieldAssertions(run) {
        var fields = (run && run.fields) || [];
        if (!fields.length) { return null; }
        return el("ul", { "class": "ucm-control-fields" }, fields.map(function (f) {
            return el("li", {}, ucm.badge(f.pass ? "passed" : "failed", f.pass ? "ok" : "error"), " field ",
                el("span", { "class": "ucm-mono", text: f.name }),
                f.pass ? "" : ": " + (f.failures || []).join("; "));
        }));
    }

    function controlTestBox(ct) {
        var parts = [CONTROL_TEST_TEXT[ct.status] || ct.status];
        if (ct.reason) { parts.push(ct.reason + "."); }
        var run = ct.positive || {};
        var win = windowText(run.window);
        if (win) { parts.push(win); }
        if (run.max_count !== undefined && run.rows !== undefined) {
            parts.push("Positive run: " + run.rows + " rows, expected " + run.min_count + " to " + run.max_count + ".");
        }
        if (ct.test_index) { parts.push("Test index " + ct.test_index + "."); }
        parts.push("Revision " + ct.revision + ", run " + (ct.ran_at || "") + " UTC by " + (ct.ran_by || "") + ".");
        var box = ucm.stateBox(CONTROL_TEST_KIND[ct.status] || "warn", "Control test: " + ct.status.replace(/_/g, " "), parts.join(" "));
        var list = fieldAssertions(run);
        if (list) { box.appendChild(list); }
        return box;
    }

    function draftForm(uc, dep, current) {
        var defaults = (dep.settings && dep.settings.defaults) || {};
        var cur = current || {};
        var source = el("select", { "class": "ucm-input" },
            el("option", { value: "primary", text: "Primary SPL" }),
            uc.cim_spl ? el("option", { value: "cim", text: "CIM SPL" }) : null,
            el("option", { value: "custom", text: "Custom (edited copy)" }));
        source.value = cur.spl_source || "primary";
        var custom = el("textarea", { "class": "ucm-input ucm-mono", rows: "6" });
        custom.value = cur.spl_source === "custom" ? cur.spl : (uc.spl || "");
        var customWrap = el("div", { style: source.value === "custom" ? "" : "display:none" }, custom);
        source.addEventListener("change", function () { customWrap.style.display = source.value === "custom" ? "" : "none"; });
        function input(value) { var i = el("input", { "class": "ucm-input", type: "text" }); i.value = value; return i; }
        var cron = input(cur.cron || defaults.cron || "*/15 * * * *");
        var earliest = input(cur.earliest || defaults.earliest || "-20m@m");
        var latest = input(cur.latest || defaults.latest || "-5m@m");
        var windowIn = input(cur.schedule_window || defaults.schedule_window || "auto");
        var suppressPeriod = input(cur.suppress_period || "");
        suppressPeriod.placeholder = "off, or e.g. 1h";
        var suppressFields = input(cur.suppress_fields || "");
        suppressFields.placeholder = "all results, or e.g. user,src";
        var mode = el("select", { "class": "ucm-input" }, el("option", { value: "track", text: "Alert (Triggered Alerts only)" }),
            el("option", { value: "none", text: "Scheduled report" }));
        mode.value = cur.alert_mode || defaults.alert_mode || "track";
        var severity = el("select", { "class": "ucm-input" }, ["info", "low", "medium", "high", "critical"].map(function (s) {
            return el("option", { value: s, text: s });
        }));
        severity.value = cur.severity || (uc.criticality === "critical" ? "critical" : (uc.criticality === "high" ? "high" : "medium"));
        var threshold = input(String(cur.threshold === undefined ? 0 : cur.threshold));
        var notes = input("");
        var save = el("button", { "class": "btn btn-primary", type: "button", text: "Save draft", onclick: function () {
            this.disabled = true;
            ucm.post("deployment/draft", { id: uc.content_id, spl_source: source.value, custom_spl: custom.value,
                cron: cron.value, earliest: earliest.value, latest: latest.value, alert_mode: mode.value,
                schedule_window: windowIn.value, suppress_period: suppressPeriod.value, suppress_fields: suppressFields.value,
                severity: severity.value, threshold: threshold.value, notes: notes.value })
                .done(load).fail(function (err) { save.disabled = false; ucm.notify(err.message); });
        } });
        return el("div", { "class": "ucm-form" }, kv([
            ["Search", source], ["Custom SPL", customWrap], ["Schedule (cron)", cron], ["Earliest", earliest],
            ["Latest", latest], ["Schedule window (auto or minutes)", windowIn], ["Type", mode], ["Severity", severity],
            ["Trigger when results >", threshold], ["Suppress repeats for", suppressPeriod], ["Suppress by fields", suppressFields],
            ["Notes", notes]]),
            el("div", { "class": "ucm-actions" }, save),
            el("div", { "class": "ucm-sub", text: "The draft is parsed by Splunk. Searches with side-effect commands cannot be submitted. No email, webhook or script actions are configured. The default range ends 5 minutes ago so late events are still counted; suppression applies to alerts only." }));
    }

    var LIVE_KIND = { enabled: "ok", disabled: "info", missing: "error", unmanaged: "error", absent: "neutral" };
    var STATE_KIND = { draft: "neutral", pending_approval: "warn", approved: "info", rejected: "high",
        deployed: "ok", failed: "error", retired: "neutral" };

    function deploymentBox(uc) {
        var view = uc.deployment || { deployment: null, allowed_actions: [] };
        var dep = view.deployment;
        var allowed = view.allowed_actions || [];
        var head = el("div", { "class": "ucm-readiness-head" }, el("strong", { text: "Deployment" }),
            dep ? ucm.badge(dep.state.replace("_", " "), STATE_KIND[dep.state] || "neutral") : ucm.badge("not deployed", "neutral"),
            dep ? ucm.badge("saved search: " + ((dep.live && dep.live.status) || "absent"), LIVE_KIND[(dep.live && dep.live.status) || "absent"]) : null,
            dep && dep.content_changed ? ucm.badge("provider content changed since this revision", "warn") : null,
            dep ? ucm.accessBadge(view.scheduler_access) : null);
        var card = el("div", { "class": "ucm-card" }, head);
        if (!dep) {
            if (allowed.indexOf("draft") < 0) {
                card.appendChild(el("div", { "class": "ucm-sub", text: "Not deployed. Preparing a deployment needs the ucm_run_discovery or ucm_deploy capability." }));
                card.appendChild(unavailableActions(view));
                return card;
            }
            card.appendChild(draftForm(uc, view, null));
            card.appendChild(unavailableActions(view));
            return card;
        }
        var revs = dep.revisions || [];
        var latest = revs[revs.length - 1] || {};
        card.appendChild(el("div", { "class": "ucm-sub" }, el("span", { "class": "ucm-mono", text: dep.saved_search.name }),
            " in app " + dep.saved_search.app + (dep.live && dep.live.owner ? ", owner " + dep.live.owner : "") +
            ". Latest revision " + dep.revision + (dep.deployed_revision ? ", deployed revision " + dep.deployed_revision : ", nothing deployed") + "."));
        card.appendChild(el("div", { "class": "ucm-sub", text: "Revision " + latest.rev + ": " + latest.spl_source + " SPL, cron " +
            latest.cron + ", " + latest.earliest + " → " + latest.latest +
            (latest.schedule_window ? ", schedule window " + latest.schedule_window : "") + ", " +
            (latest.alert_mode === "track" ? "alert, severity " + latest.severity + ", results > " + latest.threshold +
                (latest.suppress_period ? ", suppressed for " + latest.suppress_period +
                    (latest.suppress_fields ? " by " + latest.suppress_fields : "") : "") : "scheduled report") + ". " +
            (latest.parse_ok ? "Parsed by Splunk." : "Parse failed: " + (latest.parse_error || "")) +
            (latest.side_effects && latest.side_effects.length ? " Side effects: " + latest.side_effects.join(", ") + "." : "") +
            (latest.review_commands && latest.review_commands.length ? " Needs review: " + latest.review_commands.join(", ") +
                (latest.acknowledged_by ? " (acknowledged by " + latest.acknowledged_by + ")" : "") + "." : "") +
            (latest.submitted_by ? " Submitted by " + latest.submitted_by + "." : "") +
            (latest.approved_by ? " Approved by " + latest.approved_by + "." : "") }));
        if (latest.spl_time_bounds) {
            card.appendChild(ucm.stateBox("warn", "Time range set inside the SPL",
                "The search sets earliest/latest itself, which overrides the schedule's " + latest.earliest + " → " +
                latest.latest + " range. Remove it from the SPL unless the override is intended."));
        }
        var lintNote = ucm.lintBox(latest.lint, "Advisory: submitting is not blocked, and these do not change approval. " +
            "Dismiss hides a finding until the page is reloaded.");
        if (lintNote) { card.appendChild(lintNote); }
        var accessNote = ucm.accessBox(view.scheduler_access);
        if (accessNote) { card.appendChild(accessNote); }
        if (dep.last_error) { card.appendChild(ucm.stateBox("error", "Last error", dep.last_error)); }
        if (dep.control_test) { card.appendChild(controlTestBox(dep.control_test)); }
        var drift = (dep.live && dep.live.drift) || [];
        if (drift.length) {
            card.appendChild(ucm.stateBox("warn", "Drift detected (" + (dep.live.verified_at || "") + " UTC)",
                drift.map(function (d) { return d.field + (d.detail ? ": " + d.detail : (" expected " + d.expected + ", observed " + d.observed)); }).join("; ")));
        }
        card.appendChild(el("div", { "class": "ucm-actions" }, allowed.filter(function (a) { return a !== "draft"; }).map(function (a) {
            return el("button", { "class": "btn" + (a === "deploy" || a === "approve" || a === "submit" ? " btn-primary" : ""),
                type: "button", text: ACTION_LABELS[a] || a, onclick: function () { runAction(uc, view, a); } });
        })));
        card.appendChild(unavailableActions(view));
        if (allowed.indexOf("draft") >= 0) {
            card.appendChild(el("details", { "class": "ucm-details" }, el("summary", { text: dep.state === "draft" ? "Edit draft" : "Start a new revision" }),
                draftForm(uc, view, latest)));
        }
        var spl = latest.spl ? el("details", { "class": "ucm-details" }, el("summary", { text: "Revision " + latest.rev + " SPL" }),
            el("pre", { "class": "ucm-spl", text: latest.spl })) : null;
        var hist = el("tbody", {});
        (dep.history || []).slice(-10).reverse().forEach(function (h) {
            hist.appendChild(el("tr", {}, el("td", { text: h.at }), el("td", { text: h.actor }), el("td", { text: h.action }),
                el("td", { text: (h.from || "–") + " → " + h.to }), el("td", { text: h.revision === null ? "" : String(h.revision) }),
                el("td", { "class": "ucm-sub", text: h.note || "" })));
        });
        card.appendChild(spl);
        card.appendChild(el("details", { "class": "ucm-details" }, el("summary", { text: "History" }),
            el("table", { "class": "ucm-table" }, el("thead", {}, el("tr", {}, ["Time (UTC)", "Actor", "Action", "State", "Rev", "Note"].map(function (t) {
                return el("th", { text: t });
            }))), hist)));
        card.appendChild(el("div", { "class": "ucm-sub", text: "Every deploy and rollback writes the saved search disabled. Enabling is a separate, audited step. The search runs as its owner. To see it in Settings > Searches, reports, and alerts, set Owner to All: that page lists only your own searches by default." }));
        return card;
    }

    var ACTION_ORDER = ["draft", "submit", "approve", "reject", "deploy", "enable", "disable", "rollback", "retire", "verify", "controltest"];

    /* Why an action is not offered, from the documented workflow (deployment/service.py allowed_actions). */
    function whyNot(action, dep, view) {
        var state = dep ? dep.state : null;
        var live = dep && dep.live && dep.live.status ? dep.live.status : "absent";
        var settings = view.settings || {};
        var shown = state ? state.replace("_", " ") : "";
        var deployed = !!(dep && dep.deployed_revision);
        var capability = "Needs the ucm_deploy capability.";
        switch (action) {
        case "draft": return "Needs the ucm_run_discovery or ucm_deploy capability.";
        case "submit":
            if (!dep) { return "Save a draft first."; }
            if (state !== "draft") { return "Only a draft can be submitted; this deployment is " + shown + ". Save a new revision to start a draft."; }
            return "Needs the ucm_run_discovery or ucm_deploy capability.";
        case "approve":
        case "reject":
            if (state !== "pending_approval") { return "Nothing is waiting for approval" + (dep ? " (state: " + shown + ")." : "."); }
            return action === "approve" && !settings.allow_self_approval
                ? "Needs the ucm_deploy capability and a person other than the one who submitted it (self-approval is off)."
                : capability;
        case "deploy":
            if (!dep) { return "Nothing to deploy yet: save a draft, submit it and have it approved."; }
            if (state !== "approved" && state !== "failed") { return "Needs an approved revision (state: " + shown + ")."; }
            return capability;
        case "enable":
        case "disable":
            if (!deployed) { return "Nothing is deployed yet."; }
            if (live !== "enabled" && live !== "disabled") { return "The saved search is " + live + ", so it cannot be switched."; }
            if (action === "enable" && live === "enabled") { return "Already enabled."; }
            if (action === "disable" && live === "disabled") { return "Already disabled."; }
            return capability;
        case "rollback":
            return deployed ? "Needs an earlier deployed revision to return to, and the ucm_deploy capability." : "Nothing is deployed yet.";
        case "retire":
            if (!dep) { return "Nothing to retire."; }
            return state === "retired" ? "Already retired." : capability;
        case "verify":
            return deployed ? capability : "Nothing is deployed yet.";
        case "controltest":
            return deployed ? "Needs the ucm_deploy capability, and control tests must be available on this server." : "Nothing is deployed yet.";
        default: return "Not available in the current state.";
        }
    }

    function unavailableActions(view) {
        var allowed = view.allowed_actions || [];
        var dep = view.deployment;
        var missing = ACTION_ORDER.filter(function (a) { return allowed.indexOf(a) < 0; });
        if (!missing.length) { return null; }
        return el("details", { "class": "ucm-details ucm-unavailable" },
            el("summary", { text: "Actions not available to you right now (" + missing.length + ")" }),
            el("dl", { "class": "ucm-kv" }, missing.map(function (a) {
                return [el("dt", { text: a === "draft" ? "Save draft" : (ACTION_LABELS[a] || a) }), el("dd", { text: whyNot(a, dep, view) })];
            })));
    }

    var PLAN_ANCHORS = ["ucm-sec-selection", "ucm-sec-deployment"];
    var plan = { open: false, toggle: null, panel: null };

    function setPlan(open) {
        plan.open = open;
        if (!plan.toggle || !plan.panel) { return; }
        plan.toggle.setAttribute("aria-expanded", open ? "true" : "false");
        plan.toggle.textContent = open ? "Hide deployment plan" : "Plan deployment";
        if (open) { plan.panel.removeAttribute("hidden"); } else { plan.panel.setAttribute("hidden", "hidden"); }
    }

    function jump(id, label) {
        return el("a", { href: "#" + id, text: label, onclick: function (ev) {
            if (ev && ev.preventDefault) { ev.preventDefault(); }
            if (PLAN_ANCHORS.indexOf(id) >= 0) { setPlan(true); }
            var target = document.getElementById(id);
            if (target && target.scrollIntoView) { target.scrollIntoView(); }
        } });
    }

    function tile(title, anchor, nodes) {
        return el("div", { "class": "ucm-card ucm-tile" }, el("div", { "class": "ucm-sub", text: title }),
            nodes, el("div", {}, jump(anchor, "Details")));
    }

    /* Requirements -> readiness -> deployment, then the user's own decision. */
    function summaryStrip(uc) {
        var rd = uc.readiness;
        var counts = (rd && rd.counts) || {};
        var reqs = uc.requirements || [];
        var byLevel = {};
        reqs.forEach(function (r) { byLevel[r.level] = (byLevel[r.level] || 0) + 1; });
        var levels = LEVEL_ORDER.filter(function (l) { return byLevel[l]; }).map(function (l) { return byLevel[l] + " " + l; }).join(", ");
        var reqTile = tile("Requirements", "ucm-sec-requirements", [
            el("div", { "class": "ucm-big", text: String(reqs.length) }),
            el("div", { "class": "ucm-sub", text: levels || "none derived" }),
            requirementRows(reqs, rd).extra ? el("div", { "class": "ucm-sub", text: "plus " + requirementRows(reqs, rd).extra + " additional check" + (requirementRows(reqs, rd).extra > 1 ? "s" : "") }) : null,
            rd ? el("div", { "class": "ucm-sub", text: "results: " + ucm.resultSummary(counts, rd.unverified) })
                : el("div", { "class": "ucm-sub", text: "not checked yet" })]);
        var rdTile = tile("Readiness", "ucm-sec-requirements", [
            el("div", {}, rd ? ucm.readinessBadge(rd.state) : ucm.badge("not assessed", "neutral"), rd && rd.stale ? ucm.badge("stale", "warn") : null),
            el("div", { "class": "ucm-big", text: rd && rd.score !== null && rd.score !== undefined ? rd.score + " / 100" : "–" }),
            el("div", { "class": "ucm-sub", text: rd ? "coverage " + Math.round((rd.coverage || 0) * 100) + "%" : "from the requirement results" })]);
        var view = uc.deployment || {};
        var dep = view.deployment;
        var depTile = tile("Deployment", "ucm-sec-deployment", [
            el("div", {}, dep ? ucm.badge(dep.state.replace("_", " "), STATE_KIND[dep.state] || "neutral") : ucm.badge("not deployed", "neutral")),
            el("div", { "class": "ucm-sub", text: dep ? "saved search: " + ((dep.live && dep.live.status) || "absent") : "no draft yet" }),
            (view.settings && (view.settings.block_enable_states || []).length)
                ? el("div", { "class": "ucm-sub", text: "Enabling is blocked while readiness is " + view.settings.block_enable_states.join(", ") + " (an override is audited)." })
                : null]);
        var sel = uc.selection;
        var selTile = tile("Your selection", "ucm-sec-selection", [
            el("div", {}, sel ? ucm.badge(sel.intent, sel.intent === "select" ? "ok" : "info") : ucm.badge("not selected", "neutral")),
            el("div", { "class": "ucm-sub", text: "private to you" })]);
        return el("div", { "class": "ucm-flow" }, reqTile, el("span", { "class": "ucm-arrow", text: "→" }), rdTile,
            el("span", { "class": "ucm-arrow", text: "→" }), depTile, selTile);
    }

    /* ---- Interactive search (D-058): SearchManager under the user's own permissions ---- */

    var SEARCH_RANGES = [["-15m", "Last 15 minutes"], ["-1h", "Last hour"], ["-4h", "Last 4 hours"], ["-24h", "Last 24 hours"], ["-7d", "Last 7 days"]];
    var SEARCH_ROW_CAP = 100;
    var SEARCH_MAX_SECONDS = 120;
    var CELL_CAP = 500;

    function cellText(value) {
        var t = Array.isArray(value) ? value.join(", ") : (value === null || value === undefined ? "" : String(value));
        return t.length > CELL_CAP ? t.slice(0, CELL_CAP) + "…" : t;
    }

    function visibleFields(fields) {
        return (fields || []).filter(function (f) { return f === "_time" || f === "_raw" || f.charAt(0) !== "_"; });
    }

    function renderResults(box, fields, rows, total) {
        ucm.clear(box);
        var names = visibleFields(fields);
        if (!rows.length) { box.appendChild(ucm.stateBox("empty", "The search returned no results.", "That is a result of the search, not an error.")); return; }
        var shown = rows.slice(0, SEARCH_ROW_CAP);
        var index = names.map(function (n) { return fields.indexOf(n); });
        box.appendChild(el("div", { "class": "ucm-sub", text: "Showing " + shown.length + (total && total > shown.length ? " of " + total : "") +
            " results (display limit " + SEARCH_ROW_CAP + "). The results are shown here only; SUNavigator does not store or export them." }));
        box.appendChild(el("div", { "class": "ucm-scroll" }, el("table", { "class": "ucm-table" },
            el("thead", {}, el("tr", {}, names.map(function (n) { return el("th", { text: n }); }))),
            el("tbody", {}, shown.map(function (row) {
                return el("tr", {}, index.map(function (i) { return el("td", { "class": "ucm-mono", text: cellText(row[i]) }); }));
            })))));
    }

    function searchBox(uc, sources) {
        var searchable = sources.filter(function (x) { return x.spl; });
        if (!searchable.length) { return null; }
        if (uc.interactive_search && uc.interactive_search.enabled === false) {
            return el("div", { "class": "ucm-card ucm-search" },
                el("strong", { text: "Run this search" }),
                ucm.stateBox("info", "Not available on this server.",
                    "An administrator has turned the interactive search off. Use the bounded preview above, or copy the SPL into Search."));
        }
        var which = el("select", { "aria-label": "Search to run" }, searchable.map(function (x, i) { return el("option", { value: String(i), text: x.label }); }));
        var range = el("select", { "aria-label": "Time range" }, SEARCH_RANGES.map(function (r) { return el("option", { value: r[0], text: r[1] }); }));
        range.value = "-24h";
        var runBtn = el("button", { "class": "btn btn-primary", type: "button", text: "Run search" });
        var stopBtn = el("button", { "class": "btn", type: "button", text: "Cancel", disabled: "disabled" });
        var reason = el("div", { "class": "ucm-sub ucm-search-reason" });
        var status = el("div", { "class": "ucm-sub", "aria-live": "polite" });
        var out = el("div", {});
        var canSearch = null;
        var active = null;

        function current() { return searchable[parseInt(which.value, 10) || 0]; }

        function refreshGuard() {
            var src = current();
            var guard = ucm.searchGuard(src.spl, uc.validation, uc.provenance.source_hash, src.primary);
            var why = guard.reason;
            var ok = guard.ok;
            if (ok && canSearch === false) { ok = false; why = "Your Splunk role does not have the search capability, so Splunk would refuse this search."; }
            if (ok && active) { ok = false; why = "A search is running. Cancel it first."; }
            runBtn.disabled = !ok;
            if (ok) { runBtn.removeAttribute("title"); } else { runBtn.setAttribute("title", why); }
            ucm.clear(reason);
            if (!ok) { reason.appendChild(ucm.stateBox("warn", "Run search is disabled.", why)); }
            guard.warnings.forEach(function (w) { reason.appendChild(ucm.stateBox("info", "Check before you run.", w)); });
            return guard;
        }

        function finish() {
            active = null;
            stopBtn.disabled = true;
            refreshGuard();
        }

        function stop(label) {
            if (!active) { return; }
            var run = active;
            active = null;
            try { run.manager.cancel(); } catch (e) { /* the job may already be gone */ }
            try { run.manager.dispose(); } catch (e2) { /* nothing to release */ }
            if (label) { status.textContent = label; }
            stopBtn.disabled = true;
            refreshGuard();
        }

        function start(SearchManager) {
            var src = current();
            var guard = ucm.searchGuard(src.spl, uc.validation, uc.provenance.source_hash, src.primary);
            if (!guard.ok) { refreshGuard(); return; }
            var run = { manager: null };
            var settings = { id: "ucm_run_" + Date.now(), search: ucm.searchableSpl(src.spl), earliest_time: range.value, latest_time: "now",
                autostart: false, preview: false, cache: false, status_buckets: 0, max_time: SEARCH_MAX_SECONDS, cancelOnUnload: true,
                app: "sunavigator" };
            run.manager = new SearchManager(settings, { tokens: false });
            active = run;
            ucm.clear(out);
            status.textContent = "Running…";
            stopBtn.disabled = false;
            refreshGuard();
            var manager = run.manager;
            manager.on("search:progress", function (p) {
                var c = (p && p.content) || {};
                if (active === run && !c.isDone) {
                    status.textContent = "Running… " + (c.scanCount || 0) + " events scanned, " + (c.resultCount || 0) + " results so far.";
                }
            });
            manager.on("search:done", function (p) {
                if (active !== run) { return; }
                var c = (p && p.content) || {};
                var total = c.resultCount || 0;
                status.textContent = "Done: " + total + " results from " + (c.scanCount || 0) + " events scanned" +
                    (c.runDuration !== undefined ? " in " + c.runDuration + " s" : "") + "." +
                    (c.isFinalized ? " The search was finalized before it completed (limit " + SEARCH_MAX_SECONDS + " s)." : "");
                var results = manager.data("results", { count: SEARCH_ROW_CAP, offset: 0, output_mode: "json_rows" });
                results.on("data", function () {
                    if (active !== run) { return; }
                    var d = results.data() || {};
                    renderResults(out, d.fields || [], d.rows || [], total);
                    finish();
                });
                results.on("error", function () {
                    ucm.clear(out).appendChild(ucm.stateBox("error", "The results could not be read.", "Splunk did not return them."));
                    finish();
                });
            });
            manager.on("search:failed", function (p) {
                var msgs = ((p && p.content && p.content.messages) || []).map(function (m) { return m.text; }).filter(Boolean);
                ucm.clear(out).appendChild(ucm.stateBox("error", "Splunk could not run the search.", msgs.join(" ") || "The job failed."));
                status.textContent = "Failed.";
                finish();
            });
            manager.on("search:error", function (message) {
                ucm.clear(out).appendChild(ucm.stateBox("error", "Splunk refused the search.", String(message || "The search could not be started.")));
                status.textContent = "Not run.";
                finish();
            });
            manager.on("search:cancelled", function () { if (active === run) { status.textContent = "Cancelled."; finish(); } });
            manager.startSearch();
        }

        runBtn.addEventListener("click", function () {
            if (runBtn.disabled) { return; }
            runBtn.disabled = true;
            require(["splunkjs/mvc/searchmanager"], start, function () {
                status.textContent = "The Splunk search component could not be loaded.";
                refreshGuard();
            });
        });
        stopBtn.addEventListener("click", function () { stop("Cancelled."); });
        which.addEventListener("change", function () { ucm.clear(out); status.textContent = ""; refreshGuard(); });
        if (window.addEventListener) { window.addEventListener("pagehide", function () { stop(); }); }

        ucm.rawGet("services/authentication/current-context").done(function (data) {
            var caps = (((data.entry || [])[0] || {}).content || {}).capabilities || [];
            canSearch = caps.indexOf("search") >= 0;
            refreshGuard();
        }).fail(function () { canSearch = null; refreshGuard(); });
        refreshGuard();

        return el("div", { "class": "ucm-card ucm-search" },
            el("strong", { text: "Run this search" }),
            ucm.stateBox("warn", "This runs as you, outside SUNavigator's guard rails.",
                "The search runs in your browser through Splunk's search API, as your own Splunk user and with your own permissions. " +
                "It is not subject to the bounded preview (forced short window, result cap, read-only command checks) that the server applies, " +
                "and SUNavigator cannot audit it; Splunk records the search under your account. Nothing runs until you click Run search, " +
                "and the results are shown here only. Searches with side-effect commands (also inside a map search), or that run SPL this page cannot show (savedsearch, loadjob, dbxquery), are not offered."),
            el("div", { "class": "ucm-toolbar" },
                searchable.length > 1 ? el("div", { "class": "ucm-field" }, el("label", { text: "Search" }), which) : null,
                el("div", { "class": "ucm-field" }, el("label", { text: "Time range" }), range),
                runBtn, stopBtn),
            el("div", { "class": "ucm-sub", text: "The time range applies unless the SPL sets its own earliest= or latest=, which take precedence. The search is stopped after " + SEARCH_MAX_SECONDS +
                " seconds or when you leave the page, and only the first " + SEARCH_ROW_CAP + " rows are displayed." }),
            reason, status, out);
    }

    function mitreLink(m) {
        var path = m.object_id.replace(".", "/");
        var base = m.object_type === "tactic" ? "https://attack.mitre.org/tactics/" : "https://attack.mitre.org/techniques/";
        var label = m.object_id + (m.domain ? " (" + m.domain + ")" : "");
        return el("a", { href: base + path + "/", target: "_blank", rel: "noopener noreferrer", text: label });
    }

    function frameworks(uc) {
        var mitre = uc.framework_mappings.filter(function (m) { return m.framework === "mitre_attack"; });
        var other = uc.framework_mappings.filter(function (m) { return m.framework !== "mitre_attack"; });
        var parts = [];
        if (mitre.length) {
            parts.push(el("div", {}, el("strong", { text: "MITRE ATT&CK " }),
                el("span", { "class": "ucm-sub", text: "(framework version: unversioned in provider content)" })));
            parts.push(el("div", {}, mitre.map(function (m) { return el("span", { "class": "ucm-badge ucm-badge-chip" }, mitreLink(m)); })));
        }
        if (uc.framework_na_reasons.length) {
            parts.push(el("div", { "class": "ucm-sub", text: "Not mapped to ATT&CK: " + uc.framework_na_reasons.join("; ") }));
        }
        if (other.length) {
            var body = el("tbody", {});
            other.forEach(function (m) {
                var a = m.attributes || {};
                body.appendChild(el("tr", {}, el("td", { text: a.regulation_label || m.framework.replace("regulation:", "") }),
                    el("td", { text: m.framework_version || "unversioned" }),
                    el("td", {}, a.clause_url ? el("a", { href: a.clause_url, target: "_blank", rel: "noopener noreferrer", text: m.object_id }) : m.object_id),
                    el("td", { text: a.mode || "" }),
                    el("td", {}, a.assurance || "", a.requires_sme_review ? " " : null,
                        a.requires_sme_review ? ucm.badge("SME review required", "warn") : null)));
                var notes = [["Control objective", a.control_objective], ["Evidence artifact", a.evidence_artifact],
                    ["Assurance rationale", a.assurance_rationale], ["SME caveat", a.sme_caveat]].filter(function (n) { return n[1]; });
                if (notes.length) {
                    body.appendChild(el("tr", { "class": "ucm-subrow" }, el("td", { colspan: "5" },
                        el("details", { "class": "ucm-details" }, el("summary", { text: "Objective, evidence and rationale" }), kv(notes)))));
                }
            });
            parts.push(el("table", { "class": "ucm-table" }, el("thead", {}, el("tr", {},
                el("th", { text: "Framework" }), el("th", { text: "Version" }), el("th", { text: "Control" }),
                el("th", { text: "Mode" }), el("th", { text: "Assurance" }))), body));
        }
        return parts.length ? parts : text("", "No framework mappings supplied by the provider.");
    }

    function dependencies(uc) {
        var rows = [];
        uc.addons.forEach(function (a) {
            var name = a.url ? el("a", { href: a.url, target: "_blank", rel: "noopener noreferrer", text: a.name }) : a.name;
            rows.push(["Add-on", el("span", {}, name, a.min_version ? " ≥ " + a.min_version : "", a.role ? " — " + a.role : "")]);
        });
        uc.premium_apps.forEach(function (p) { rows.push(["Premium app", p]); });
        uc.macros.forEach(function (m) { rows.push(["Macro (from SPL)", el("span", { "class": "ucm-mono", text: m })]); });
        uc.lookups.forEach(function (l) { rows.push(["Lookup (from SPL)", el("span", { "class": "ucm-mono", text: l })]); });
        uc.cim_models.forEach(function (c) { rows.push(["CIM model", c]); });
        if ((uc.analytic_stories || []).length) { rows.push(["Analytic stories", filterLinks(uc.analytic_stories, "story")]); }
        if ((uc.data_sources || []).length) { rows.push(["Data sources (provider names)", filterLinks(uc.data_sources, "data_source")]); }
        if (uc.splunk_versions.length) { rows.push(["Splunk versions", uc.splunk_versions.join(", ")]); }
        if (uc.equipment.length) { rows.push(["Equipment", ucm.chips(uc.equipment)]); }
        if (uc.hardware) { rows.push(["Hardware / platform", uc.hardware]); }
        uc.prerequisite_use_cases.forEach(function (p) { rows.push(["Prerequisite use case", p]); });
        var parts = [rows.length ? kv(rows) : text("", "No structured dependencies supplied.")];
        if (uc.addons_text) { parts.push(el("details", { "class": "ucm-details" }, el("summary", { text: "Provider add-on notes" }), text(uc.addons_text))); }
        return parts;
    }

    var WAVE_TEXT = { crawl: "crawl — ship first", walk: "walk — builds on crawl use cases", run: "run — advanced, builds on walk" };

    function scopeAndTesting(uc) {
        var rows = [];
        if (uc.wave) { rows.push(["Maturity wave", WAVE_TEXT[uc.wave] || uc.wave]); }
        if (uc.exclusions) { rows.push(["Out of scope", uc.exclusions]); }
        var t = uc.control_test || {};
        [["positiveScenario", "Control test: should fire"], ["negativeScenario", "Control test: should stay quiet"],
            ["attackTechnique", "Test technique"], ["fixtureRef", "Test fixture"], ["fixtureStatus", "Fixture status"]].forEach(function (k) {
            if (t[k[0]]) { rows.push([k[1], t[k[0]]]); }
        });
        return rows.length ? kv(rows) : text("", "No scope or control-test information supplied.");
    }

    function extraValue(v) {
        if (typeof v === "string") { return v.length > 4000 ? v.slice(0, 4000) + "…" : v; }
        if (typeof v === "number" || typeof v === "boolean") { return String(v); }
        if (Array.isArray(v) && v.every(function (x) { return typeof x === "string"; })) { return v.join(", "); }
        var json = JSON.stringify(v, null, 2) || "";
        return el("pre", { "class": "ucm-pre ucm-mono", text: json.length > 4000 ? json.slice(0, 4000) + "…" : json });
    }

    function providerExtras(uc) {
        var keys = Object.keys(uc.provider_extras || {}).filter(function (k) { return k.charAt(0) !== "$"; }).sort();
        if (!keys.length) { return null; }
        return el("details", { "class": "ucm-details" }, el("summary", { text: "Other provider fields (" + keys.length + ")" }),
            el("div", { "class": "ucm-sub", text: "Shown as supplied by the provider; not interpreted by the app." }),
            kv(keys.map(function (k) { return [k, extraValue(uc.provider_extras[k])]; })));
    }

    function references(uc) {
        if (!uc.references.length) { return text("", "No references supplied."); }
        return el("ul", {}, uc.references.map(function (r) {
            if (r.url) {
                return el("li", {}, el("a", { href: r.url, target: "_blank", rel: "noopener noreferrer", text: r.title || r.url }),
                    r.retrieved ? el("span", { "class": "ucm-sub", text: " (retrieved " + r.retrieved + ")" }) : null);
            }
            return el("li", {}, (r.title || "") + " ", el("span", { "class": "ucm-mono", text: "[repository: " + r.repo_path + "]" }));
        }));
    }

    function filterLinks(values, param) {
        return el("span", {}, values.map(function (v) {
            return el("a", { "class": "ucm-badge ucm-badge-chip", href: "ucm_catalogue?" + param + "=" + encodeURIComponent(v),
                title: "Open the catalogue filtered to this value", text: v });
        }));
    }

    function twinLink(t) {
        return el("li", {},
            ucm.providerBadge(t.provider), " Same detection in " + ucm.providerLabel(t.provider) + ": ",
            el("a", { "class": "ucm-mono", href: "ucm_usecase?id=" + encodeURIComponent(t.key || t.content_id), text: t.content_id }),
            t.title ? el("span", { "class": "ucm-sub", text: " " + t.title }) : null,
            t.authority && t.authority.label ? el("span", { "class": "ucm-sub", text: " (" + t.authority.label + ")" }) : null);
    }

    /* Twins share the primary SPL text after whitespace normalisation; nothing more is claimed. */
    function lineageBox(uc) {
        var twins = uc.spl_twins || [];
        var twinIds = twins.map(function (t) { return t.content_id; });
        var same = (uc.spl_duplicates || []).filter(function (id) { return twinIds.indexOf(id) < 0; });
        if (!twins.length && !same.length) { return null; }
        var box = el("div", { "class": "ucm-lineage" });
        if (twins.length) {
            var own = uc.authority && uc.authority.label ? " This record comes from " + ucm.providerLabel(uc.provenance.provider) +
                ": " + uc.authority.label.toLowerCase() + "." : "";
            var inner = el("div", {}, el("ul", {}, twins.map(twinLink)),
                el("div", { "class": "ucm-sub", text: "The primary SPL is identical after whitespace is normalised. Title, schedule, severity and " +
                    "compliance mappings can still differ." + own }),
                el("div", { "class": "ucm-sub", text: "Provider rule: ESCU is the source for detection content; Fenre supplies compliance and mapping " +
                    "context. The rule comes from the provider roles, not from comparing the two records." }),
                el("div", { "class": "ucm-sub", text: "Deploy it once: deploying both creates two saved searches that run the same SPL." }));
            var twinBox = ucm.stateBox("info", "This search also exists in another provider");
            twinBox.appendChild(inner);
            box.appendChild(twinBox);
        }
        if (same.length) {
            box.appendChild(ucm.stateBox("warn", "The primary SPL is identical in other use cases of this provider",
                "Deploying more than one of them runs the same search twice: " + same.join(", ") + "."));
        }
        return box;
    }

    function planItem(label, node) {
        return el("span", { "class": "ucm-plan-item" }, el("span", { "class": "ucm-sub", text: label }), node);
    }

    /* Selection, review and deployment controls stay as they were; they sit behind one disclosure button. */
    function planSection(uc) {
        var view = uc.deployment || { deployment: null, allowed_actions: [] };
        var dep = view.deployment;
        var rd = uc.readiness;
        var sel = uc.selection;
        var drift = dep && dep.live && dep.live.drift ? dep.live.drift.length : 0;
        var can = (view.allowed_actions || []).filter(function (a) { return a !== "draft"; })
            .map(function (a) { return ACTION_LABELS[a] || a; });
        var status = el("div", { "class": "ucm-plan-status" },
            planItem("Selection", sel ? ucm.badge(sel.intent, sel.intent === "select" ? "ok" : "info") : ucm.badge("not selected", "neutral")),
            planItem("Readiness", rd ? ucm.readinessBadge(rd.state) : ucm.badge("not assessed", "neutral")),
            planItem("Deployment", dep ? ucm.badge(dep.state.replace("_", " "), STATE_KIND[dep.state] || "neutral") : ucm.badge("not deployed", "neutral")),
            dep ? planItem("Saved search", ucm.badge((dep.live && dep.live.status) || "absent", LIVE_KIND[(dep.live && dep.live.status) || "absent"])) : null,
            drift ? ucm.badge("drift: " + drift, "warn") : null,
            dep && dep.content_changed ? ucm.badge("provider content changed", "warn") : null);
        var panel = el("div", { "class": "ucm-plan-panel", id: "ucm-plan-panel" },
            anchored("ucm-sec-selection", section("Your selection", selectionBox(uc))),
            section("Deployment", deploymentBox(uc)));
        var toggle = el("button", { "class": "btn btn-primary", type: "button", "aria-controls": "ucm-plan-panel",
            onclick: function () { setPlan(!plan.open); } });
        plan.toggle = toggle;
        plan.panel = panel;
        setPlan(plan.open);
        return anchored("ucm-sec-deployment", section("Plan deployment",
            el("div", { "class": "ucm-plan" }, status,
                el("div", { "class": "ucm-actions" }, toggle,
                    el("span", { "class": "ucm-sub", text: can.length ? "Available to you now: " + can.join(", ") + "." :
                        "No deployment action is available to you right now; the panel explains why." })),
                panel)));
    }

    function render(uc) {
        var p = uc.provenance;
        ucm.clear(root);
        root.appendChild(el("div", { "class": "ucm-header" },
            el("div", { "class": "ucm-sub" }, el("a", { href: "ucm_catalogue", text: "‹ Content Catalogue" })),
            el("h2", { text: uc.title }),
            el("div", {}, ucm.providerBadge(p.provider), el("span", { "class": "ucm-mono", text: " " + uc.content_id + "  " }), ucm.criticalityBadge(uc.criticality),
                ucm.badge(uc.difficulty, "neutral"), ucm.chips(uc.domains), ucm.badge("review: " + uc.review_status, "info"),
                ucm.qualityBadges(uc.quality_flags),
                uc.provider_status === "withdrawn" ? ucm.badge("withdrawn upstream", "warn") : null),
            el("div", { "class": "ucm-sub", text: [ucm.providerLabel(p.provider), uc.category_name, uc.subcategory].filter(Boolean).join(" › ") })));

        root.appendChild(el("div", { "class": "ucm-actions ucm-jump" }, el("span", { "class": "ucm-sub", text: "Jump to:" }),
            jump("ucm-sec-requirements", "Requirements and readiness"), jump("ucm-sec-spl", "SPL and search"),
            jump("ucm-sec-selection", "Your selection"), jump("ucm-sec-deployment", "Plan deployment"), jump("ucm-sec-details", "Details")));
        root.appendChild(summaryStrip(uc));

        root.appendChild(section("Description", text(uc.description)));
        root.appendChild(section("Business value", text(uc.business_value)));
        root.appendChild(anchored("ucm-sec-requirements", section("Requirements and readiness",
            readinessBox(uc),
            requirementsTable(uc.requirements, uc.readiness),
            el("div", { "class": "ucm-sub", text: "Requirements come from the provider record or are derived from its SPL; derived requirements are hypotheses with lower confidence and weight. " +
                "Readiness combines the requirement results, and enabling a deployment is gated on it (see Deployment)." }),
            ucm.legend("What the statuses mean", ucm.STATUSES, ucm.statusBadge, ucm.STATUS_HELP),
            el("details", { "class": "ucm-details" }, el("summary", { text: "Provider data-source description" }), text(uc.data_sources_text)),
            uc.required_fields.length ? el("div", {}, el("strong", { text: "Required fields: " }), ucm.chips(uc.required_fields)) : null,
            uc.datamodel_acceleration_text ? el("details", { "class": "ucm-details" }, el("summary", { text: "Data model acceleration notes" }), text(uc.datamodel_acceleration_text)) : null)));
        var lineage = lineageBox(uc);
        if (lineage) { root.appendChild(lineage); }
        var sources = [{ label: "Primary search", spl: uc.spl, primary: true }, { label: "CIM search", spl: uc.cim_spl, primary: false }]
            .concat(uc.spl_variants.map(function (v) { return { label: "Variant: " + v.model, spl: v.spl, primary: false }; }));
        root.appendChild(anchored("ucm-sec-spl", section("SPL and search",
            ucm.stateBox("info", "Imported SPL is untrusted content.", "It is shown for review. The catalogue and SUNavigator's checks never run it; only the bounded preview and, at your request, the search below do."),
            spl("Primary search", uc.spl) || text("", "No primary SPL supplied."), spl("CIM search", uc.cim_spl),
            uc.spl_variants.map(function (v) { return spl("Variant: " + v.model + " (" + v.sourcetypes.join(", ") + ")", v.spl); }),
            validationBox(uc),
            searchBox(uc, sources))));
        root.appendChild(anchored("ucm-sec-details", el("div", { "class": "ucm-section" })));
        root.appendChild(section("Dependencies", dependencies(uc)));
        root.appendChild(section("Implementation", text(uc.instructions),
            uc.detailed_instructions ? el("details", { "class": "ucm-details" }, el("summary", { text: "Detailed implementation guide" }), text(uc.detailed_instructions)) : null,
            uc.visualization ? el("details", { "class": "ucm-details" }, el("summary", { text: "Suggested visualization" }), text(uc.visualization)) : null));
        root.appendChild(section("Scope and testing", scopeAndTesting(uc)));
        root.appendChild(section("Framework mappings", frameworks(uc)));
        root.appendChild(section("Known false positives", text(uc.known_false_positives)));
        root.appendChild(section("References", references(uc)));
        root.appendChild(planSection(uc));
        root.appendChild(section("Provenance", kv([
            ["Provider", p.provider], ["Provider record id", p.provider_record_id],
            ["Catalogue version", p.provider_version], ["Source commit", el("span", { "class": "ucm-mono", text: p.source_ref })],
            ["Source", p.source_url.indexOf("https://") === 0
                ? el("a", { href: p.source_url, target: "_blank", rel: "noopener noreferrer", text: p.source_path })
                : p.source_url],
            ["Git blob SHA (verified)", el("span", { "class": "ucm-mono", text: p.source_blob_sha })],
            ["Content hash (SHA-256)", el("span", { "class": "ucm-mono", text: p.source_hash })],
            ["Schema", p.source_schema], ["Imported (UTC)", p.imported_at],
            ["Normalizer", p.normalizer_version + (uc.normalized_with !== p.normalizer_version ? " (displayed with " + uc.normalized_with + ")" : "")],
            ["Last reviewed", uc.last_reviewed], ["Reviewer", uc.reviewer],
            ["Validation warnings", String(uc.validation_warning_count || 0)]]), providerExtras(uc)));
    }

    if (!id) {
        ucm.clear(root).appendChild(ucm.stateBox("error", "No use case selected.", "Open a use case from the Content Catalogue."));
        return;
    }
    if (/^#ucm-sec-(selection|deployment)$/.test(window.location.hash || "")) { plan.open = true; }

    function load() {
        ucm.get("usecase", { id: id }).done(render).fail(function (err) {
            ucm.clear(root).appendChild(ucm.stateBox("error", "The use case could not be loaded.", err.message));
        });
    }

    load();
}
