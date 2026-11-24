require([
    "jquery",
    "../app/sunavigator/ucm_common",
    "splunkjs/mvc/simplexml/ready!"
], function ($, ucm) {
    "use strict";
    var el = ucm.el;
    var root = document.getElementById("ucm-usecase");
    var id = ucm.queryParams().id || "";

    function section(title) {
        var body = Array.prototype.slice.call(arguments, 1);
        return el("div", { "class": "ucm-section" }, el("h3", { text: title }), body);
    }

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

    function requirementsTable(reqs, readiness) {
        if (!reqs.length) { return text("", "No requirements could be derived from this record."); }
        var byId = {};
        ((readiness && readiness.results) || []).forEach(function (r) { byId[r.req_id] = r; });
        var head = el("tr", {});
        ["Type", "Requirement", "Level", "Source", "Confidence", "Status", "Evidence"].forEach(function (h) {
            head.appendChild(el("th", { text: h }));
        });
        var body = el("tbody", {});
        reqs.forEach(function (r) {
            var res = byId[r.req_id];
            var evidence = res ? evidenceText(res) : (r.notes || "");
            body.appendChild(el("tr", {},
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
                        : null)));
        });
        return el("table", { "class": "ucm-table" }, el("thead", {}, head), body);
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
            el("div", { "class": "ucm-sub", text: (counts.met || 0) + " met, " + (counts.partial || 0) + " partial, " +
                (counts.not_met || 0) + " not met, " + (counts.unknown || 0) + " unknown, " + (rd.unverified || 0) +
                " not verified. Evaluated " + rd.evaluated_at + " UTC against discovery " +
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
        enable: "Enable", disable: "Disable", rollback: "Roll back", retire: "Retire", verify: "Verify now" };

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
            if ((settings.block_enable_states || []).indexOf(rd) >= 0) {
                ucm.askText("Override the readiness gate", "Readiness is " + rd + ". The override reason is audited.",
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
            dep && dep.content_changed ? ucm.badge("provider content changed since this revision", "warn") : null);
        var card = el("div", { "class": "ucm-card" }, head);
        if (!dep) {
            if (allowed.indexOf("draft") < 0) {
                card.appendChild(el("div", { "class": "ucm-sub", text: "Not deployed. Preparing a deployment needs the ucm_run_discovery or ucm_deploy capability." }));
                return card;
            }
            card.appendChild(draftForm(uc, view, null));
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
        if (dep.last_error) { card.appendChild(ucm.stateBox("error", "Last error", dep.last_error)); }
        var drift = (dep.live && dep.live.drift) || [];
        if (drift.length) {
            card.appendChild(ucm.stateBox("warn", "Drift detected (" + (dep.live.verified_at || "") + " UTC)",
                drift.map(function (d) { return d.field + (d.detail ? ": " + d.detail : (" expected " + d.expected + ", observed " + d.observed)); }).join("; ")));
        }
        card.appendChild(el("div", { "class": "ucm-actions" }, allowed.filter(function (a) { return a !== "draft"; }).map(function (a) {
            return el("button", { "class": "btn" + (a === "deploy" || a === "approve" || a === "submit" ? " btn-primary" : ""),
                type: "button", text: ACTION_LABELS[a] || a, onclick: function () { runAction(uc, view, a); } });
        })));
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
        card.appendChild(el("div", { "class": "ucm-sub", text: "Every deploy and rollback writes the saved search disabled. Enabling is a separate, audited step. The search runs as its owner." }));
        return card;
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
                body.appendChild(el("tr", {}, el("td", { text: m.framework.replace("regulation:", "") }),
                    el("td", { text: m.framework_version || "unversioned" }), el("td", { text: m.object_id }),
                    el("td", { text: (m.attributes && m.attributes.mode) || "" }),
                    el("td", { text: (m.attributes && m.attributes.assurance) || "" })));
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
        if (uc.splunk_versions.length) { rows.push(["Splunk versions", uc.splunk_versions.join(", ")]); }
        uc.prerequisite_use_cases.forEach(function (p) { rows.push(["Prerequisite use case", p]); });
        var parts = [rows.length ? kv(rows) : text("", "No structured dependencies supplied.")];
        if (uc.addons_text) { parts.push(el("details", { "class": "ucm-details" }, el("summary", { text: "Provider add-on notes" }), text(uc.addons_text))); }
        return parts;
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

    function render(uc) {
        var p = uc.provenance;
        ucm.clear(root);
        root.appendChild(el("div", { "class": "ucm-header" },
            el("div", { "class": "ucm-sub" }, el("a", { href: "ucm_catalogue", text: "‹ Content Catalogue" })),
            el("h2", { text: uc.title }),
            el("div", {}, el("span", { "class": "ucm-mono", text: uc.content_id + "  " }), ucm.criticalityBadge(uc.criticality),
                ucm.badge(uc.difficulty, "neutral"), ucm.chips(uc.domains), ucm.badge("review: " + uc.review_status, "info"),
                uc.provider_status === "withdrawn" ? ucm.badge("withdrawn upstream", "warn") : null),
            el("div", { "class": "ucm-sub", text: [uc.category_name, uc.subcategory].filter(Boolean).join(" › ") })));

        root.appendChild(readinessBox(uc));
        root.appendChild(selectionBox(uc));
        root.appendChild(validationBox(uc));
        root.appendChild(deploymentBox(uc));

        root.appendChild(section("Description", text(uc.description)));
        root.appendChild(section("Business value", text(uc.business_value)));
        root.appendChild(section("Requirements", requirementsTable(uc.requirements, uc.readiness),
            el("div", { "class": "ucm-sub", text: "Requirements come from the provider record or are derived from its SPL; derived requirements are hypotheses with lower confidence and weight." }),
            el("details", { "class": "ucm-details" }, el("summary", { text: "Provider data-source description" }), text(uc.data_sources_text)),
            uc.required_fields.length ? el("div", {}, el("strong", { text: "Required fields: " }), ucm.chips(uc.required_fields)) : null,
            uc.datamodel_acceleration_text ? el("details", { "class": "ucm-details" }, el("summary", { text: "Data model acceleration notes" }), text(uc.datamodel_acceleration_text)) : null));
        root.appendChild(section("SPL",
            ucm.stateBox("info", "Imported SPL is untrusted content.", "It is shown for review only and is never executed by the catalogue."),
            spl("Primary search", uc.spl) || text("", "No primary SPL supplied."), spl("CIM search", uc.cim_spl),
            uc.spl_variants.map(function (v) { return spl("Variant: " + v.model + " (" + v.sourcetypes.join(", ") + ")", v.spl); })));
        root.appendChild(section("Dependencies", dependencies(uc)));
        root.appendChild(section("Implementation", text(uc.instructions),
            uc.detailed_instructions ? el("details", { "class": "ucm-details" }, el("summary", { text: "Detailed implementation guide" }), text(uc.detailed_instructions)) : null,
            uc.visualization ? el("details", { "class": "ucm-details" }, el("summary", { text: "Suggested visualization" }), text(uc.visualization)) : null));
        root.appendChild(section("Framework mappings", frameworks(uc)));
        root.appendChild(section("Known false positives", text(uc.known_false_positives)));
        root.appendChild(section("References", references(uc)));
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
            ["Validation warnings", String(uc.validation_warning_count || 0)]])));
    }

    if (!id) {
        ucm.clear(root).appendChild(ucm.stateBox("error", "No use case selected.", "Open a use case from the Content Catalogue."));
        return;
    }
    function load() {
        ucm.get("usecase", { id: id }).done(render).fail(function (err) {
            ucm.clear(root).appendChild(ucm.stateBox("error", "The use case could not be loaded.", err.message));
        });
    }

    load();
});
