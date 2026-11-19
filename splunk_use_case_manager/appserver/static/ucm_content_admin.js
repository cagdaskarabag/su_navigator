require([
    "jquery",
    "../app/splunk_use_case_manager/ucm_common",
    "splunkjs/mvc/simplexml/ready!"
], function ($, ucm) {
    "use strict";
    var el = ucm.el;
    var root = document.getElementById("ucm-admin");
    var stateCard = el("div", { "class": "ucm-card" });
    var platformCard = el("div", { "class": "ucm-card" });
    var providerBox = el("div", {});
    var importBox = el("div", {});
    var jobsBox = el("div", {});
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
            var errors = (j.errors || []).map(function (e) { return e.message; });
            (j.results || []).forEach(function (r) {
                if (r.status === "failed") {
                    errors.push("category " + r.category_id + ": " + ((r.errors[0] || {}).message || "failed"));
                }
            });
            body.appendChild(el("tr", {},
                el("td", { text: j.requested_at }), el("td", { text: j.source }), el("td", {}, statusBadge(j.status)),
                el("td", { text: j.requested_by }), el("td", { text: j.provider_version || "" }),
                el("td", { "class": "ucm-mono", text: ucm.shortSha(j.source_ref) }),
                el("td", { text: t.added === undefined ? "" : t.added }), el("td", { text: t.updated === undefined ? "" : t.updated }),
                el("td", { text: t.renormalized === undefined ? "" : t.renormalized }),
                el("td", { text: t.unchanged === undefined ? "" : t.unchanged }),
                el("td", { text: t.withdrawn === undefined ? "" : t.withdrawn }),
                el("td", { text: t.invalid === undefined ? "" : t.invalid }),
                el("td", { "class": "ucm-sub", text: errors.slice(0, 3).join("; ") })));
        });
        jobsBox.appendChild(el("table", { "class": "ucm-table" }, el("thead", {}, head), body));
        return active;
    }

    function refresh() {
        clearTimeout(refreshTimer);
        $.when(ucm.get("sync"), ucm.get("categories")).done(function (sync, cats) {
            localCategories = {};
            (cats.categories || []).forEach(function (c) { localCategories[c.category_id] = c; });
            renderState(sync);
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
        var head = el("tr", {}, el("th", {}), el("th", { text: "Category" }), el("th", { text: "Upstream use cases" }),
            el("th", { text: "Imported locally" }), el("th", { text: "Last sync" }));
        var body = el("tbody", {});
        var boxes = [];
        manifest.categories.forEach(function (c) {
            var local = localCategories[c.category_id] || {};
            var box = el("input", { type: "checkbox", value: c.category_id, "aria-label": c.name });
            if (local.selected) { box.checked = true; }
            boxes.push(box);
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
        providerBox.appendChild(el("table", { "class": "ucm-table" }, el("thead", {}, head), body));
        providerBox.appendChild(el("div", { "class": "ucm-actions" }, syncBtn,
            el("label", {}, force, " Re-download all records"),
            el("label", {}, allowSchema, " Accept a provider schema major-version change")));
        providerBox.appendChild(message);
    }

    function providerSection() {
        var refInput = el("input", { type: "text", placeholder: "Branch, tag or commit (default: configured ref)",
            maxlength: "200", "aria-label": "Provider ref" });
        var loadBtn = el("button", { "class": "btn", type: "button", text: "Check provider for categories",
            onclick: function () {
                loadBtn.disabled = true;
                ucm.clear(providerBox).appendChild(el("div", { "class": "ucm-loading", text: "Contacting provider…" }));
                ucm.get("provider/manifest", refInput.value.trim() ? { ref: refInput.value.trim() } : {})
                    .done(renderManifest)
                    .fail(function (err) {
                        ucm.clear(providerBox).appendChild(ucm.stateBox("error", "The provider could not be reached.",
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

    function renderPlatform() {
        ucm.get("platform").done(function (p) {
            ucm.clear(platformCard).appendChild(el("div", {}, el("h3", { text: "Platform" }),
                el("div", { "class": "ucm-sub", text: p.platform + " " + p.version + (p.shc_member ? ", search head cluster member" : "") }),
                el("dl", { "class": "ucm-kv" }, p.capabilities.map(function (c) {
                    return [el("dt", { text: c.name.replace(/_/g, " ") }), el("dd", {}, statusBadge(c.status), " ", el("span", { "class": "ucm-sub", text: c.evidence }))];
                }))));
        }).fail(function (err) {
            ucm.clear(platformCard).appendChild(ucm.stateBox("error", "Platform capabilities unavailable.", err.message));
        });
    }

    function renderAudit() {
        ucm.get("audit", { limit: 15, prefix: "content." }).done(function (data) {
            var body = el("tbody", {});
            data.events.forEach(function (e) {
                body.appendChild(el("tr", {}, el("td", { text: e.time_iso }), el("td", { text: e.actor }),
                    el("td", { text: e.action }), el("td", { "class": "ucm-mono", text: e.object_id }), el("td", {}, statusBadge(e.outcome))));
            });
            ucm.clear(auditBox).appendChild(el("div", { "class": "ucm-section" }, el("h3", { text: "Content audit trail" }),
                data.events.length ? el("table", { "class": "ucm-table" }, el("thead", {}, el("tr", {},
                    el("th", { text: "Time (UTC)" }), el("th", { text: "Actor" }), el("th", { text: "Action" }),
                    el("th", { text: "Object" }), el("th", { text: "Outcome" }))), body) : ucm.stateBox("empty", "No audit events yet.")));
        }).fail(function () { ucm.clear(auditBox); });
    }

    ucm.clear(root);
    root.appendChild(el("div", { "class": "ucm-cards" }, stateCard, platformCard));
    root.appendChild(providerSection());
    root.appendChild(importSection());
    root.appendChild(jobsBox);
    root.appendChild(auditBox);
    refresh();
    renderPlatform();
    renderAudit();
});
