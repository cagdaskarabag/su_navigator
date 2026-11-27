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
    var root = document.getElementById("ucm-admin");
    var stateCard = el("div", { "class": "ucm-card" });
    var platformCard = el("div", { "class": "ucm-card" });
    var providerBox = el("div", {});
    var importBox = el("div", {});
    var jobsBox = el("div", {});
    var boundBox = el("div", {});
    var reindexBox = el("div", {});
    var auditBox = el("div", {});
    var refreshTimer = null;
    var localCategories = {};

    function statusBadge(status) {
        var kinds = { succeeded: "ok", ok: "ok", unchanged: "ok", partial: "warn", queued: "info", running: "info",
            failed: "error", available: "ok", unavailable: "warn", unknown: "neutral" };
        return ucm.badge(status || "unknown", kinds[status] || "neutral");
    }

    function renderState(data) {
        var s = data.provider_state || {};
        ucm.clear(stateCard).appendChild(el("div", {},
            el("h3", { text: "Fenre provider" }),
            el("dl", { "class": "ucm-kv" },
                el("dt", { text: "Configured ref" }), el("dd", { "class": "ucm-mono", text: data.configured_ref }),
                el("dt", { text: "Allowed refs" }), el("dd", { "class": "ucm-mono", text: (data.allowed_refs || []).join(", ") }),
                el("dt", { text: "Remote sync" }), el("dd", {}, statusBadge(data.remote_sync_enabled ? "available" : "unavailable")),
                el("dt", { text: "Last good version" }), el("dd", { text: s.last_good_version || "none" }),
                el("dt", { text: "Last good commit" }), el("dd", { "class": "ucm-mono", text: s.last_good_ref || "none" }),
                el("dt", { text: "Last good source" }), el("dd", { text: s.last_good_source || (s.last_good_ref ? "unknown" : "none") }),
                el("dt", { text: "Schema version" }), el("dd", { text: s.schema_version || "unknown" }),
                el("dt", { text: "Last success (UTC)" }), el("dd", { text: s.last_success_at || "never" }),
                el("dt", { text: "Last attempt" }), el("dd", {}, s.last_attempt_at ? s.last_attempt_at + " " : "never ",
                    s.last_attempt_status ? statusBadge(s.last_attempt_status) : null),
                el("dt", { text: "Selected categories" }), el("dd", { text: (s.selected_categories || []).join(", ") || "none" }))));
    }

    function renderJobs(jobs) {
        ucm.clear(jobsBox).appendChild(el("h3", { text: "Synchronization and import history" }));
        if (!jobs.length) { jobsBox.appendChild(ucm.stateBox("empty", "No jobs yet.")); return false; }
        var head = el("tr", {});
        ["Requested (UTC)", "Source", "Status", "Requested by", "Version", "Commit", "Added", "Updated", "Re-normalized",
            "Unchanged", "Withdrawn", "Invalid", "Errors"].forEach(function (h) { head.appendChild(el("th", { text: h })); });
        var body = el("tbody", {});
        var active = false;
        jobs.forEach(function (j) {
            var t = j.totals || {};
            if (j.status === "queued" || j.status === "running") { active = true; }
            var errors = ucm.jobErrors(j);
            body.appendChild(el("tr", {},
                el("td", { text: j.requested_at }), el("td", { text: j.source }), el("td", {}, statusBadge(j.status)),
                el("td", { text: j.requested_by }), el("td", { text: j.provider_version || "" }),
                el("td", { "class": "ucm-mono", text: ucm.shortSha(j.source_ref) }),
                el("td", { text: t.added === undefined ? "" : t.added }), el("td", { text: t.updated === undefined ? "" : t.updated }),
                el("td", { text: t.renormalized === undefined ? "" : t.renormalized }),
                el("td", { text: t.unchanged === undefined ? "" : t.unchanged }),
                el("td", { text: t.withdrawn === undefined ? "" : t.withdrawn }),
                el("td", { text: t.invalid === undefined ? "" : t.invalid }),
                el("td", { "class": j.status === "failed" ? "ucm-job-error" : "ucm-sub", text: errors.slice(0, 3).join("; ") })));
        });
        var failure = ucm.jobFailureBox(jobs);
        if (failure) { jobsBox.appendChild(failure); }
        jobsBox.appendChild(el("table", { "class": "ucm-table" }, el("thead", {}, head), body));
        return active;
    }

    function refresh() {
        clearTimeout(refreshTimer);
        $.when(ucm.get("sync"), ucm.get("categories")).done(function (sync, cats) {
            localCategories = {};
            (cats.categories || []).forEach(function (c) { localCategories[c.category_id] = c; });
            renderState(sync);
            var rows = (cats.categories || []).reduce(function (n, c) { return n + (c.imported_count || 0); }, 0);
            var bound = ucm.rowBoundNote(rows, sync.kv_row_limit);
            ucm.clear(boundBox);
            if (bound) { boundBox.appendChild(bound); }
            if (renderJobs(sync.jobs || [])) { refreshTimer = setTimeout(refresh, 5000); }
        }).fail(function (err) {
            ucm.clear(stateCard).appendChild(ucm.stateBox("error", "Synchronization state unavailable.", err.message));
        });
    }

    function renderManifest(manifest) {
        ucm.clear(providerBox);
        providerBox.appendChild(el("div", { "class": "ucm-sub",
            text: "Provider version " + manifest.provider_version + " at commit " + manifest.source_ref +
                " (ref " + manifest.requested_ref + "), schema " + manifest.schema_version + "." }));
        (manifest.warnings || []).forEach(function (w) { providerBox.appendChild(ucm.stateBox("info", "Provider warning", w)); });
        var body = el("tbody", {});
        var boxes = [];
        var rows = manifest.categories.map(function (c) {
            var local = localCategories[c.category_id] || {};
            var box = el("input", { type: "checkbox", value: c.category_id, "aria-label": c.name });
            if (local.selected) { box.checked = true; }
            boxes.push(box);
            return { c: c, local: local, box: box };
        });
        var bulk = ucm.selectAll(boxes, "categories");
        var head = el("tr", {}, el("th", {}, bulk.header), el("th", { text: "Category" }), el("th", { text: "Upstream use cases" }),
            el("th", { text: "Imported locally" }), el("th", { text: "Last sync" }));
        rows.forEach(function (row) {
            var c = row.c, local = row.local, box = row.box;
            body.appendChild(el("tr", {}, el("td", {}, box),
                el("td", {}, el("div", { text: c.category_id + ". " + c.name }), el("div", { "class": "ucm-sub", text: c.description || "" })),
                el("td", { text: c.upstream_count === null ? "unknown" : c.upstream_count }),
                el("td", { text: local.imported_count === undefined ? "0" : local.imported_count }),
                el("td", {}, local.last_sync_status ? statusBadge(local.last_sync_status) : "never")));
        });
        var force = el("input", { type: "checkbox", id: "ucm-force" });
        var allowSchema = el("input", { type: "checkbox", id: "ucm-allow-schema" });
        var message = el("div", {});
        var syncBtn = el("button", { "class": "btn btn-primary", type: "button", text: "Synchronize selected categories",
            onclick: function () {
                var selected = boxes.filter(function (b) { return b.checked; }).map(function (b) { return b.value; });
                if (!selected.length) { ucm.clear(message).appendChild(ucm.stateBox("error", "Select at least one category.")); return; }
                syncBtn.disabled = true;
                ucm.post("sync", { categories: selected, ref: manifest.source_ref, force: force.checked,
                    allow_schema_change: allowSchema.checked }).done(function (res) {
                    ucm.clear(message).appendChild(ucm.stateBox("info", "Synchronization queued.",
                        "Job " + res.job.job_id + " pinned to commit " + ucm.shortSha(manifest.source_ref) +
                        ". The background worker starts it within about a minute."));
                    refresh();
                }).fail(function (err) {
                    ucm.clear(message).appendChild(ucm.stateBox("error", "Synchronization was not queued.", err.message));
                }).always(function () { syncBtn.disabled = false; });
            } });
        providerBox.appendChild(el("div", { "class": "ucm-actions" }, bulk.selectAllButton, bulk.deselectAllButton, bulk.count,
            el("span", { "class": "ucm-sub", text: "Selecting categories does not re-download records; that is the separate option below." })));
        providerBox.appendChild(el("table", { "class": "ucm-table" }, el("thead", {}, head), body));
        providerBox.appendChild(el("div", { "class": "ucm-actions" }, syncBtn,
            el("label", {}, force, " Re-download all records"),
            el("label", {}, allowSchema, " Accept a provider schema major-version change")));
        providerBox.appendChild(message);
    }

    function providerSection() {
        var refInput = el("input", { type: "text", placeholder: "Allowed branch or tag, or a commit on one (default: configured ref)",
            maxlength: "200", "aria-label": "Provider ref" });
        var loadBtn = el("button", { "class": "btn", type: "button", text: "Check provider for categories",
            onclick: function () {
                loadBtn.disabled = true;
                ucm.clear(providerBox).appendChild(el("div", { "class": "ucm-loading", text: "Contacting provider…" }));
                ucm.get("provider/manifest", refInput.value.trim() ? { ref: refInput.value.trim() } : {})
                    .done(renderManifest)
                    .fail(function (err) {
                        ucm.clear(providerBox).appendChild(err.status === 400
                            ? ucm.stateBox("error", "The ref was refused.", err.message +
                                ". Allowed refs are set by [provider:fenre] allowed_refs in ucm.conf.")
                            : ucm.stateBox("error", "The provider could not be reached.",
                                err.message + " Previously imported content remains available. Use offline import if this stack has no outbound access."));
                    }).always(function () { loadBtn.disabled = false; });
            } });
        return el("div", { "class": "ucm-section" }, el("h3", { text: "Remote synchronization" }),
            el("div", { "class": "ucm-actions" }, el("div", { "class": "ucm-field" }, el("label", { text: "Version pin (optional)" }), refInput), loadBtn),
            providerBox);
    }

    function importSection() {
        var file = el("input", { type: "file", accept: ".json,application/json", "aria-label": "Bundle file" });
        var btn = el("button", { "class": "btn btn-primary", type: "button", text: "Import bundle",
            onclick: function () {
                if (!file.files || !file.files.length) { ucm.clear(importBox).appendChild(ucm.stateBox("error", "Choose a bundle file first.")); return; }
                var reader = new FileReader();
                btn.disabled = true;
                ucm.clear(importBox).appendChild(el("div", { "class": "ucm-loading", text: "Validating and importing…" }));
                reader.onload = function () {
                    ucm.postRaw("import", reader.result).done(function (res) {
                        var t = res.job.totals || {};
                        ucm.clear(importBox).appendChild(ucm.stateBox(res.job.status === "succeeded" ? "info" : "error",
                            "Import " + res.job.status + ".",
                            "Added " + (t.added || 0) + ", updated " + (t.updated || 0) + ", unchanged " + (t.unchanged || 0) +
                            ", invalid " + (t.invalid || 0) + "."));
                        refresh();
                    }).fail(function (err) {
                        ucm.clear(importBox).appendChild(ucm.stateBox("error", "Import rejected.", err.message));
                    }).always(function () { btn.disabled = false; });
                };
                reader.onerror = function () { btn.disabled = false; ucm.clear(importBox).appendChild(ucm.stateBox("error", "The file could not be read.")); };
                reader.readAsText(file.files[0]);
            } });
        return el("div", { "class": "ucm-section" }, el("h3", { text: "Offline import" }),
            el("div", { "class": "ucm-sub", text: "Import a ucm-content-bundle file built with tools/ucm_cli.py build-bundle. " +
                "Every record is verified against its git blob hash, validated and normalized exactly like a remote sync." }),
            el("div", { "class": "ucm-actions" }, file, btn), importBox);
    }

    function appPhrase(app, name) {
        if (!app) { return name + " unknown"; }
        if (app.state === "installed") { return name + " " + (app.version || "(version unknown)"); }
        if (app.state === "disabled") { return name + " " + (app.version || "") + " (disabled)"; }
        if (app.state === "not_installed") { return name + ": not installed"; }
        return name + ": unverified" + (app.reason ? " (" + app.reason + ")" : "");
    }

    function securityRow(sc) {
        if (!sc) { return []; }
        return [[el("dt", { text: "security content apps" }), el("dd", {},
            appPhrase(sc.es, "Enterprise Security"), "; ", appPhrase(sc.escu, "ESCU"), " ",
            el("span", { "class": "ucm-sub", text: sc.note || "" }))]];
    }

    function renderPlatform() {
        ucm.get("platform").done(function (p) {
            ucm.clear(platformCard).appendChild(el("div", {}, el("h3", { text: "Platform" }),
                el("div", { "class": "ucm-sub", text: p.platform + " " + p.version + (p.shc_member ? ", search head cluster member" : "") }),
                el("dl", { "class": "ucm-kv" }, p.capabilities.map(function (c) {
                    return [el("dt", { text: c.name.replace(/_/g, " ") }), el("dd", {}, statusBadge(c.status), " ", el("span", { "class": "ucm-sub", text: c.evidence }))];
                }).concat(securityRow(p.security_content)))));
        }).fail(function (err) {
            ucm.clear(platformCard).appendChild(ucm.stateBox("error", "Platform capabilities unavailable.", err.message));
        });
    }

    function reindexSection() {
        var message = el("div", {});
        var button = el("button", { "class": "btn", type: "button", text: "Reindex catalogue summaries", onclick: function () {
            ucm.confirmAction("Reindex the catalogue?",
                "Every summary is re-derived from the stored records, without any download. It takes about 5 seconds per 1,000 use cases. " +
                "Selections, readiness and deployments are not changed.", "Reindex", function () {
                    button.disabled = true;
                    ucm.clear(message).appendChild(el("div", { "class": "ucm-loading", text: "Reindexing…" }));
                    ucm.post("catalog/reindex", {}).done(function (res) {
                        ucm.clear(message).appendChild(ucm.stateBox("info", "Reindex finished.", "Re-derived " + (res.reindexed || 0) +
                            " summaries, skipped " + (res.skipped || 0) + "."));
                        loadHint();
                    }).fail(function (err) {
                        ucm.clear(message).appendChild(ucm.stateBox("error", "Reindex failed.", err.message));
                    }).always(function () { button.disabled = false; });
                });
        } });
        return el("div", { "class": "ucm-section" }, el("h3", { text: "Catalogue summaries" }), reindexBox,
            el("div", { "class": "ucm-sub", text: "Reindex re-derives the searchable summaries and the catalogue facets from the stored records. " +
                "Run it after an upgrade that adds filters. It needs the ucm_content_manager role." }),
            el("div", { "class": "ucm-actions" }, button), message);
    }

    function loadHint() {
        ucm.get("catalog/facets").done(function (f) {
            ucm.clear(reindexBox);
            var summary = f && f.summary;
            var note = ucm.reindexHint(summary, f && f.active);
            reindexBox.appendChild(note || el("div", { "class": "ucm-sub", text: summary
                ? "All active catalogue summaries are current (version " + summary.version + ")." : "" }));
        }).fail(function () { ucm.clear(reindexBox); });
    }

    function verifyResult(r) {
        var problems = r.modified_count + r.missing_count + r.restart_count;
        var lines = [r.chained + " of " + r.rows + " rows are chained" + (r.legacy ? " (" + r.legacy + " older rows from before the chain are not checked)" : "") + ".",
            "Head " + (r.head || "none") + ". Record it outside Splunk to also detect removal of the newest rows."];
        if (r.branches) { lines.push(r.branches + " rows were written at the same moment as another; that is normal and not a failure."); }
        if (r.truncated) { lines.push("Only the first " + r.rows + " rows were checked."); }
        if (!problems) { return ucm.stateBox("info", "The audit chain is intact.", lines.join(" ")); }
        var found = [];
        if (r.modified_count) { found.push(r.modified_count + " row(s) were changed after they were written: " + r.modified.map(function (m) { return m.action + " at " + m.time; }).join("; ")); }
        if (r.missing_count) { found.push(r.missing_count + " row(s) follow a row that no longer exists: " + r.missing_predecessor.map(function (m) { return m.action + " at " + m.time; }).join("; ")); }
        if (r.restart_count) { found.push("the chain restarted " + r.restart_count + " time(s), for example after the previous row could not be read: " + r.restarts.map(function (m) { return m.time; }).join("; ")); }
        return ucm.stateBox("warn", "The audit chain has problems.", found.join(". ") + ". " + lines.join(" "));
    }

    function auditIntegrity() {
        var out = el("div", {});
        return el("div", { "class": "ucm-actions" }, el("button", { "class": "btn", type: "button", text: "Verify audit chain", onclick: function () {
            ucm.post("audit/verify", {}).done(function (r) { ucm.clear(out).appendChild(verifyResult(r)); })
                .fail(function (err) { ucm.clear(out).appendChild(ucm.stateBox("error", "Could not verify the audit chain.", err.message)); });
        } }), el("span", { "class": "ucm-sub", text: "Each audit row carries a hash of itself and of the row before it. Verification finds an edited row or one removed from the middle." }), out);
    }

    function renderAudit() {
        ucm.get("audit", { limit: 15, prefix: "content." }).done(function (data) {
            var body = el("tbody", {});
            data.events.forEach(function (e) {
                body.appendChild(el("tr", {}, el("td", { text: e.time_iso }), el("td", { text: e.actor }),
                    el("td", { text: e.action }), el("td", { "class": "ucm-mono", text: e.object_id }), el("td", {}, e.outcome === "refused" ? ucm.badge("refused", "warn") : statusBadge(e.outcome))));
            });
            ucm.clear(auditBox).appendChild(el("div", { "class": "ucm-section" }, el("h3", { text: "Content audit trail" }),
                data.events.length ? el("table", { "class": "ucm-table" }, el("thead", {}, el("tr", {},
                    el("th", { text: "Time (UTC)" }), el("th", { text: "Actor" }), el("th", { text: "Action" }),
                    el("th", { text: "Object" }), el("th", { text: "Outcome" }))), body) : ucm.stateBox("empty", "No audit events yet."), auditIntegrity()));
            ucm.get("audit", { limit: 15, prefix: "refused." }).done(function (refused) {
                if (!refused.events.length) { return; }
                var rows = el("tbody", {});
                refused.events.forEach(function (e) {
                    var d = e.details || {};
                    rows.appendChild(el("tr", {}, el("td", { text: e.time_iso }), el("td", { text: e.actor }),
                        el("td", { text: e.action.replace(/^refused\./, "") }), el("td", { "class": "ucm-mono", text: e.object_id }),
                        el("td", { text: d.code || (d.scope ? "rate limited (" + d.scope + ")" : "") }),
                        el("td", { "class": "ucm-sub", text: d.message || "" })));
                });
                auditBox.appendChild(el("div", { "class": "ucm-section" }, el("h3", { text: "Refused requests" }),
                    el("div", { "class": "ucm-sub", text: "Governance requests that were refused. Repeats are written once per window and each user has an hourly limit ([audit] in ucm.conf)." }),
                    el("table", { "class": "ucm-table" }, el("thead", {}, el("tr", {}, ["Time (UTC)", "User", "Route", "Object", "Code", "Message"].map(function (t) { return el("th", { text: t }); }))), rows)));
            });
        }).fail(function () { ucm.clear(auditBox); });
    }

    ucm.clear(root);
    root.appendChild(el("div", { "class": "ucm-cards" }, stateCard, platformCard));
    root.appendChild(boundBox);
    root.appendChild(reindexSection());
    root.appendChild(providerSection());
    root.appendChild(importSection());
    root.appendChild(jobsBox);
    root.appendChild(auditBox);
    refresh();
    loadHint();
    renderPlatform();
    renderAudit();
}
