"use strict";
var assert = require("assert");
var fs = require("fs");
var path = require("path");
var runView = require("./fake_dom").runView;

function fixture(name) {
    return JSON.parse(fs.readFileSync(path.join(__dirname, "..", "fixtures", "ui", "usecase_" + name + ".json"), "utf8"));
}

var STANZA = "ESCU - Disable Windows Defender Real-time Protection - Rule";
var SEARCH_CAP = { entry: [{ content: { capabilities: ["search", "rest_properties_get"] } }] };

function app(state, version, reason) { return { app_id: "x", state: state, version: version || "", label: "", reason: reason || "" }; }

function handoff(opts) {
    opts = opts || {};
    var es = opts.es || app("not_installed");
    var stanza = opts.stanza === undefined ? { name: STANZA, state: "disabled", reason: "", scheduled: true, cron: "0 * * * *",
        earliest: "-70m@m", latest: "-10m@m", notable: true, risk: false, actions: ["notable"] } : opts.stanza;
    var installed = es.state === "installed";
    var enabled = !!stanza && stanza.state === "enabled";
    return {
        provider: "escu", code: opts.code || (installed ? "enable_in_es" : "escu_without_es"),
        text: opts.text || (installed ? "Enterprise Security is installed. Enable this detection in ES Content Management so ES manages it."
            : "ESCU is installed without Enterprise Security: the shipped search is disabled and nothing manages it. SUN can deploy an independent copy."),
        es: es, escu: opts.escu || app("installed", "6.11.1"), stanza: stanza,
        es_link: installed ? { app_id: "SplunkEnterpriseSecuritySuite", content_management_view: "ess_content_management", verified: false,
            note: "The exact path of Content Management varies by ES version and was not verified." } : null,
        parallel_copy: { warn: installed || enabled, es_installed: installed, escu_enabled: enabled,
            text: installed || enabled ? "A SUN deployment creates a separate plain scheduled search next to ESCU's." : "" },
        coverage_note: "Enabled in ES or in ESCU is shown here only. It does not count as enabled in SUN coverage.",
        validated: "ESCU-only behaviour was verified on a lab; behaviour with ES installed is unvalidated (no ES lab)."
    };
}

function open(uc, pathname) {
    return runView("ucm_usecase.js", "ucm-usecase", { usecase: uc, "RAW services/authentication/current-context": SEARCH_CAP },
        { search: "?id=" + encodeURIComponent(uc.content_id), pathname: pathname || "/en-US/app/sunavigator/ucm_usecase", amd: { "splunkjs/mvc/searchmanager": function () {} } });
}
function text(v) { return v.root.textContent; }
function links(v) { return v.root.find(function (n) { return n.tagName === "A" && /ess_content_management|SplunkEnterpriseSecuritySuite/.test(n.getAttribute("href") || ""); }); }

var tests = {
    "ESCU only: the card shows the stanza state read from ESCU and offers no ES link": function () {
        var uc = fixture("escu_macros");
        uc.escu_handoff = handoff();
        var v = open(uc);
        var t = text(v);
        assert.ok(/Shipped by ESCU/.test(t) && /state: disabled/.test(t));
        assert.ok(t.indexOf(STANZA) >= 0);
        assert.ok(/cron 0 \* \* \* \*/.test(t) && /notable yes, risk no/.test(t));
        assert.ok(/ESCU 6\.11\.1 installed; Enterprise Security not installed/.test(t));
        assert.ok(/independent copy/.test(t));
        assert.strictEqual(links(v).length, 0);
        assert.ok(/does not count as enabled in SUN coverage/.test(t));
        assert.ok(!/parallel copy/i.test(t), "no warning when ESCU's copy is disabled and ES is absent");
    },
    "ES present: deep link to Content Management with the not-verified note, and the parallel-copy warning in the deployment panel": function () {
        var uc = fixture("escu_macros");
        uc.escu_handoff = handoff({ es: app("installed", "8.8.0") });
        var v = open(uc);
        var a = links(v);
        assert.strictEqual(a.length, 2);
        assert.strictEqual(a[0].getAttribute("href"), "https://splunk.test:8000/en-US/app/SplunkEnterpriseSecuritySuite/ess_content_management");
        assert.strictEqual(a[1].getAttribute("href"), "https://splunk.test:8000/en-US/app/SplunkEnterpriseSecuritySuite");
        assert.strictEqual(a[0].getAttribute("rel"), "noopener noreferrer");
        var t = text(v);
        assert.ok(/varies by ES version and was not verified/.test(t));
        assert.ok(/unvalidated \(no ES lab\)/.test(t));
        assert.ok(/would be a parallel copy \(Enterprise Security is installed\)/.test(t));
        assert.ok(/does not block the workflow/.test(t));
    },
    "the link is only built from the page's own path and a plain app id": function () {
        var uc = fixture("escu_macros");
        uc.escu_handoff = handoff({ es: app("installed", "8.8.0") });
        uc.escu_handoff.es_link.app_id = "x/../evil";
        assert.strictEqual(links(open(uc)).length, 0);
        uc.escu_handoff.es_link.app_id = "SplunkEnterpriseSecuritySuite";
        assert.strictEqual(links(open(uc, "/view")).length, 0, "no /app/ in the path, no link");
    },
    "ESCU's copy enabled warns without ES and never claims SUN coverage": function () {
        var uc = fixture("escu_macros");
        var h = handoff({ stanza: { name: STANZA, state: "enabled", reason: "", scheduled: true, cron: "0 * * * *", earliest: "-70m@m",
            latest: "-10m@m", notable: true, risk: true, actions: ["notable", "risk"] } });
        uc.escu_handoff = h;
        var v = open(uc);
        var t = text(v);
        assert.ok(/state: enabled/.test(t) && /ESCU's own copy of this search is enabled/.test(t));
        assert.ok(/notable yes, risk yes/.test(t));
        assert.ok(/does not count as enabled in SUN coverage/.test(t));
    },
    "unreadable stanza shows unverified and the reason, never disabled": function () {
        var uc = fixture("escu_macros");
        uc.escu_handoff = handoff({ stanza: { name: STANZA, state: "unverified", reason: "read failed (HTTP 403)", scheduled: null, cron: "",
            earliest: "", latest: "", notable: null, risk: null, actions: [] }, code: "unverified",
            text: "The state of the shipped search could not be read (read failed (HTTP 403)). Do not assume it is disabled." });
        var v = open(uc);
        var t = text(v);
        assert.ok(/state: unverified/.test(t) && /read failed \(HTTP 403\)/.test(t));
        assert.ok(!/state: disabled/.test(t));
        assert.ok(!/notable (yes|no)/.test(t));
    },
    "ESCU not installed: card says there is nothing to enable": function () {
        var uc = fixture("escu_macros");
        uc.escu_handoff = handoff({ escu: app("not_installed"), stanza: null, code: "escu_not_installed",
            text: "The ESCU app is not installed on this search head, so there is no shipped search to enable. SUN can deploy an independent copy." });
        var v = open(uc);
        assert.ok(/state: not installed/.test(text(v)) && /ESCU not installed/.test(text(v)));
    },
    "a record from another provider has no card and no warning": function () {
        var uc = fixture("fenre_plain");
        uc.escu_handoff = null;
        var v = open(uc);
        assert.ok(!/Shipped by ESCU/.test(text(v)) && !/parallel copy/.test(text(v)));
    },
    "a draft revision shows what was recorded about the parallel copy": function () {
        var uc = fixture("fenre_deployed");
        var rev = uc.deployment.deployment.revisions[uc.deployment.deployment.revisions.length - 1];
        rev.parallel_copy = { warned: true, es_installed: true, escu_enabled: false, stanza: STANZA, stanza_state: "disabled", read_at: "2026-11-24T10:00:00Z" };
        var v = open(uc);
        assert.ok(/Recorded when this revision was drafted: Enterprise Security was installed/.test(text(v)));
    },
    "populated chip is a separate, informational flag next to the CIM requirement": function () {
        var uc = fixture("escu_macros");
        uc.requirements.push({ req_id: "cim_model:Authentication", type: "cim_model", value: "Authentication", level: "required",
            source: "provider_structured", confidence: "high", attributes: {}, notes: "" });
        uc.readiness.results.push({ req_id: "cim_model:Authentication", type: "cim_model", value: "Authentication", level: "required",
            source: "provider_structured", confidence: "high", status: "met", code: "model_present", populated: "no",
            detail: "Data model definition is installed; populated: no (the discovery check found no events in the last 24 h).",
            observed: [{ name: "Authentication", populated: "no", populated_count: 0 }], via_mapping: null });
        var v = open(uc);
        var chips = v.root.find(function (n) { return /populated: no/.test(n.getAttribute("class") ? n.textContent : "") && /ucm-badge/.test(n.getAttribute("class")); });
        assert.strictEqual(chips.length, 1);
        assert.ok(/informational/i.test(chips[0].getAttribute("title")));
        assert.ok(/Data model populated flags \(informational, not part of the score\): Authentication: no\./.test(text(v)));
        var status = v.root.find(function (n) { return /ucm-badge/.test(n.getAttribute("class") || "") && n.textContent === "met"; });
        assert.ok(status.length >= 1, "the status stays met");
    },
    "populated unverified and yes render their own values; results without the field show no chip": function () {
        ["yes", "unverified"].forEach(function (value) {
            var uc = fixture("escu_macros");
            uc.requirements.push({ req_id: "cim_model:Web", type: "cim_model", value: "Web", level: "required", source: "provider_structured",
                confidence: "high", attributes: {}, notes: "" });
            uc.readiness.results.push({ req_id: "cim_model:Web", type: "cim_model", value: "Web", level: "required", source: "provider_structured",
                confidence: "high", status: "met", code: "model_present", populated: value, detail: "x", observed: [], via_mapping: null });
            var v = open(uc);
            assert.ok(text(v).indexOf("populated: " + value) >= 0, value);
        });
        var plain = open(fixture("escu_macros"));
        assert.ok(text(plain).indexOf("populated:") < 0);
    },
    "nothing is posted when the card renders": function () {
        var uc = fixture("escu_macros");
        uc.escu_handoff = handoff({ es: app("installed", "8.8.0") });
        assert.strictEqual(open(uc).calls.filter(function (c) { return c.method === "POST"; }).length, 0);
    }
};

var adminTests = {
    "platform card lists the security content apps with versions": function () {
        var platform = { platform: "enterprise", version: "10.2.9", shc_member: false, capabilities: [{ name: "kvstore", status: "available", evidence: "kvstore/status" }],
            security_content: { es: app("not_installed"), escu: app("installed", "6.11.1"), note: "Read-only presence check." } };
        var v = runView("ucm_content_admin.js", "ucm-admin", { sync: {}, categories: { categories: [] }, platform: platform,
            audit: { events: [] }, "catalog/facets": { active: 1, summary: { version: 6, outdated: 0 } } });
        var t = v.root.textContent;
        assert.ok(/security content apps/.test(t));
        assert.ok(/Enterprise Security: not installed; ESCU 6\.11\.1/.test(t), t.slice(0, 400));
        platform.security_content = { es: app("installed", "8.8.0"), escu: app("unverified", "", "read failed (HTTP 403)") };
        v = runView("ucm_content_admin.js", "ucm-admin", { sync: {}, categories: { categories: [] }, platform: platform,
            audit: { events: [] }, "catalog/facets": { active: 1, summary: { version: 6, outdated: 0 } } });
        assert.ok(/Enterprise Security 8\.8\.0; ESCU: unverified \(read failed \(HTTP 403\)\)/.test(v.root.textContent));
    },
    "an older platform response without the field still renders": function () {
        var v = runView("ucm_content_admin.js", "ucm-admin", { sync: {}, categories: { categories: [] },
            platform: { platform: "enterprise", version: "10", shc_member: false, capabilities: [] }, audit: { events: [] },
            "catalog/facets": { active: 1, summary: { version: 6, outdated: 0 } } });
        assert.ok(!/security content apps/.test(v.root.textContent));
    }
};

var failed = 0;
[tests, adminTests].forEach(function (group) {
    Object.keys(group).forEach(function (name) {
        try { group[name](); console.log("ok   " + name); } catch (e) { failed++; console.log("FAIL " + name + ": " + (e.stack || e.message)); }
    });
});
process.exit(failed ? 1 : 0);
