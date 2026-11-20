require([
    "jquery",
    "../app/splunk_use_case_manager/ucm_common",
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
        if (res.via_mapping) {
            parts.push("Via " + res.via_mapping.origin + " mapping from " + res.via_mapping.value + ".");
        }
        return parts.join(" ");
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
                el("td", { "class": "ucm-mono", text: r.value }),
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
                    .fail(function (err) { window.alert(err.message); });
            } });
        if (!rd) {
            return el("div", {}, ucm.stateBox("info", "Readiness: not assessed",
                "This use case has not been evaluated against this deployment yet. Assessment runs automatically after " +
                "environment discovery. Deployment state: not selected, not deployed."),
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
                " not verified (fields and SPL checks need WP4). Evaluated " + rd.evaluated_at + " UTC against discovery " +
                (rd.discovery_at || "–") + "." }),
            rd.blockers && rd.blockers.length ? el("div", {}, el("strong", { text: "Blocked by critical requirement: " }),
                rd.blockers.map(function (b) { return ucm.badge(b.type + ": " + b.value, "critical"); })) : null,
            rd.gaps && rd.gaps.length ? el("div", {}, el("strong", { text: "Unmet required: " }),
                rd.gaps.map(function (g) { return ucm.badge(g.type + ": " + g.value, "high"); })) : null,
            el("div", { "class": "ucm-sub", text: "Readiness is inventory evidence, not a guarantee that the search returns results. Deployment state: not selected, not deployed." }));
        return box;
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
