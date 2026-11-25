"use strict";
var assert = require("assert");
var runView = require("./fake_dom").runView;

function row(id, title, parent, kind, extra) {
    return Object.assign({ id: id, title: title, parent: parent, kind: kind, withdrawn: false, level: null,
        counts: { catalogue: 0, ready: 0, deployed: 0, enabled: 0, operational: 0 }, use_cases: [], clauses: [], mapped: false,
        gap: ASSESSED.indexOf(kind) >= 0, below: { controls: 0, mapped: 0, ready: 0, enabled: 0 } }, extra || {});
}
var ASSESSED = ["control", "enhancement", "requirement", "subcategory"];

function catalogue() {
    return {
        catalogue: { framework_id: "nist-800-53", name: "NIST SP 800-53", version: "5.2.0", version_label: "Rev. 5.2.0", modified: "2026-10-22T11:30:00",
            source: "https://raw.githubusercontent.com/usnistgov/oscal-content/x/y.json", attribution: "Source: NIST OSCAL content." },
        regulation_ids: ["nist-800-53"], levels: [],
        totals: { controls: 4, mapped: 2, unmapped: 2, ready: 1, deployed: 1, enabled: 1, withdrawn: 1, mapped_to_withdrawn: 0 },
        controls: [
            row("AC", "Access Control", null, "family", { below: { controls: 3, mapped: 2, ready: 1, enabled: 1 } }),
            row("AC-1", "Policy", "AC", "control"),
            row("AC-2", "Account Management", "AC", "control", { mapped: true, level: "enabled", gap: false, clauses: ["AC-2"],
                use_cases: ["UC-1.1.1"], counts: { catalogue: 1, ready: 1, deployed: 1, enabled: 1, operational: 0 }, below: { controls: 1, mapped: 1, ready: 0, enabled: 0 } }),
            row("AC-2(1)", "Automated", "AC-2", "enhancement", { mapped: true, level: "catalogue", clauses: ["ac-02.01"], use_cases: ["UC-2.2.2"],
                counts: { catalogue: 1, ready: 0, deployed: 0, enabled: 0, operational: 0 } }),
            row("AC-13", "Withdrawn one", "AC", "control", { withdrawn: true, gap: false }),
            row("AU", "Audit", null, "family", { below: { controls: 1, mapped: 0, ready: 0, enabled: 0 } }),
            row("AU-6", "Review", "AU", "control")
        ],
        unmatched: [{ clause: "ZZ-9", level: "deployed", counts: {}, use_cases: ["UC-9.9.9"] }], unmatched_count: 1,
        versions: [{ version: "5.2.0", label: "Rev. 5.2.0" }], active_version: "5.2.0"
    };
}

var DEFS = [
    { framework_id: "mitre_attack_enterprise", name: "MITRE ATT&CK Enterprise", version: "18.1", kind: "attack", active: true },
    { framework_id: "nist-800-53", name: "NIST SP 800-53", version: "5.2.0", version_label: "Rev. 5.2.0", kind: "controls", active: true, controls: 7, regulation_ids: ["nist-800-53"] },
    { framework_id: "nist-csf", name: "NIST CSF", version: "2.0", version_label: "2.0", kind: "controls", active: true, controls: 3, regulation_ids: ["nist-csf"] }
];

function open(search, cat) {
    return runView("ucm_coverage.js", "ucm-coverage", {
        frameworks: { definitions: DEFS, coverage: [], use_cases: 3 },
        "frameworks/matrix": { framework_id: "mitre_attack_enterprise", version: "18.1", name: "x", domain: "enterprise", attribution: "", levels: [],
            totals: { techniques: 0, covered: {}, grade_avg: 0 }, tactics: [], remapped: [], unresolved: [] },
        "frameworks/catalogue": function () { return cat || catalogue(); },
        "frameworks/clause": { framework: "regulation:nist-800-53", clause: "AC-2", use_cases: [] }
    }, { search: search || "" });
}

function find(v, pred) { return v.root.find(pred); }
function summaries(v) { return find(v, function (n) { return n.tagName === "SUMMARY"; }).map(function (n) { return n.textContent; }); }

var tests = {
    "catalogues are listed apart from ATT&CK and each family shows its roll-up": function () {
        var v = open();
        var t = v.root.textContent;
        assert.ok(/Control catalogues/.test(t) && /Rev\. 5\.2\.0/.test(t), t.slice(0, 300));
        var s = summaries(v);
        assert.ok(s.some(function (x) { return /AC Access Control 2 of 3 mapped, 1 data ready or better, 1 without a use case/.test(x); }), s.join("|"));
        assert.ok(s.some(function (x) { return /AU Audit 0 of 1 mapped/.test(x); }));
        var selects = find(v, function (n) { return n.tagName === "SELECT"; });
        var first = selects[0].textContent;
        assert.ok(/MITRE ATT&CK Enterprise/.test(first) && !/NIST CSF/.test(first), "matrix selector lists only ATT&CK: " + first);
    },
    "totals separate mapped from unmapped and say withdrawn controls are not counted": function () {
        var t = open().root.textContent;
        assert.ok(/2Without any mapped use case/.test(t) && /2With a mapped use case/.test(t) && /4Controls/.test(t), t.slice(0, 600));
        assert.ok(/1 withdrawn controls are not counted/.test(t));
        assert.ok(/Mapped means the catalogue provider mapped/.test(t));
    },
    "an unmapped control is shown as such and a withdrawn one is hidden": function () {
        var v = open();
        var d = find(v, function (n) { return n.tagName === "DETAILS"; })[0];
        d.dispatch("toggle");
        var t = d.textContent;
        assert.ok(/AC-1/.test(t) && /no mapped use case/.test(t), t);
        assert.ok(!/AC-13/.test(t) && !/Withdrawn one/.test(t));
    },
    "show withdrawn reveals them": function () {
        var v = open("?catw=1");
        var d = find(v, function (n) { return n.tagName === "DETAILS"; })[0];
        d.dispatch("toggle");
        assert.ok(/AC-13/.test(d.textContent) && /withdrawn/.test(d.textContent));
    },
    "no mapped use case filter keeps only unmapped assessed controls and opens the families": function () {
        var v = open("?catu=1");
        var t = v.root.textContent;
        assert.ok(/AC-1/.test(t) && /AU-6/.test(t), t.slice(0, 800));
        assert.ok(!/Account Management/.test(t));
    },
    "the text filter matches id and title": function () {
        var t = open("?catq=automated").root.textContent;
        assert.ok(/AC-2\(1\)/.test(t) && !/Policy/.test(t) && !/AU-6/.test(t));
    },
    "gaps filter lists controls below data ready, including mapped ones": function () {
        var t = open("?catg=1").root.textContent;
        assert.ok(/AC-2\(1\)/.test(t) && /AC-1/.test(t) && !/Account Management/.test(t));
    },
    "a filter with no result says so": function () {
        assert.ok(/No control matches these filters/.test(open("?catq=zzzz").root.textContent));
    },
    "clicking a mapped control opens its use cases through the regulation clause": function () {
        var v = open("?catq=account");
        var link = find(v, function (n) { return n.tagName === "A" && n.textContent === "AC-2"; })[0];
        assert.ok(link, "AC-2 should be a link");
        link.dispatch("click");
        var call = v.calls.filter(function (c) { return c.path === "frameworks/clause"; }).pop();
        assert.deepStrictEqual([call.params.framework, call.params.clause], ["regulation:nist-800-53", "AC-2"]);
    },
    "clauses mapped but absent from the catalogue are listed, not counted": function () {
        var t = open().root.textContent;
        assert.ok(/Mapped clauses that are not in this catalogue \(1\)/.test(t) && /ZZ-9/.test(t) && /UC-9\.9\.9/.test(t));
        var none = catalogue(); none.unmatched = []; none.unmatched_count = 0;
        assert.ok(!/not in this catalogue/.test(open("", none).root.textContent));
    },
    "attribution and source are always shown": function () {
        var t = open().root.textContent;
        assert.ok(/Source: NIST OSCAL content\./.test(t) && /usnistgov\/oscal-content/.test(t) && /2026-10-22/.test(t));
    },
    "choosing the other catalogue asks the server for it": function () {
        var v = open();
        var selects = find(v, function (n) { return n.tagName === "SELECT"; });
        var pick = selects.filter(function (s) { return /NIST CSF/.test(s.textContent); })[0];
        pick.value = "nist-csf";
        pick.dispatch("change");
        var call = v.calls.filter(function (c) { return c.path === "frameworks/catalogue"; }).pop();
        assert.strictEqual(call.params.framework_id, "nist-csf");
    }
};

var failed = 0;
Object.keys(tests).forEach(function (name) {
    try { tests[name](); console.log("ok   " + name); } catch (e) { failed++; console.log("FAIL " + name + ": " + (e.stack || e.message).split("\n").slice(0, 5).join("\n")); }
});
process.exit(failed ? 1 : 0);
