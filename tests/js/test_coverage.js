"use strict";
var assert = require("assert");
var runView = require("./fake_dom").runView;

function cell(id, name, level, grade, basis, counts) {
    return { id: id, name: name, level: level, grade: grade, basis: basis || "", direct: level ? 1 : 0, via_sub: 0, subs: [],
        counts: Object.assign({ catalogue: 0, ready: 0, deployed: 0, enabled: 0, operational: 0 }, counts || {}) };
}

function matrix() {
    return {
        framework_id: "mitre_attack_enterprise", version: "18.1", name: "MITRE ATT&CK Enterprise", domain: "enterprise", attribution: "",
        levels: ["catalogue", "ready", "deployed", "enabled"],
        totals: { techniques: 4, covered: { catalogue: 3, ready: 2, deployed: 1, enabled: 1, operational: 0 }, grade_avg: 0.325 },
        tactics: [{ id: "TA1", name: "Access", covered: 2, techniques: [
            cell("T1", "Brute force", "enabled", 0.9, "direct", { catalogue: 2, ready: 2, deployed: 1, enabled: 1 }),
            cell("T2", "Wipe", "ready", 0.25, "direct", { catalogue: 1, ready: 1 })] }],
        remapped: [], unresolved: [],
        gaps: { counts: { data_ready: 1, content_no_data: 1, no_content: 1 }, truncated: false,
            data_ready: [{ id: "T2", name: "Wipe", tactics: ["Access"], level: "ready", grade: 0.25, catalogue: 1, ready: 1 }],
            content_no_data: [{ id: "T3", name: "Exfil", tactics: ["Access", "Impact"], level: "catalogue", grade: 0, catalogue: 2, ready: 0 }],
            no_content: [{ id: "T4", name: "Untouched", tactics: ["Impact"], level: null, grade: 0, catalogue: 0, ready: 0 }] }
    };
}

function open(m) {
    return runView("ucm_coverage.js", "ucm-coverage", {
        frameworks: { definitions: [{ framework_id: "mitre_attack_enterprise", name: "MITRE ATT&CK Enterprise", version: "18.1", active: true }], coverage: [], use_cases: 3 },
        "frameworks/matrix": m
    }, { search: "" });
}

var tests = {
    "graded coverage card explains the weights and shows the average": function () {
        var t = open(matrix()).root.textContent;
        assert.ok(/Graded coverage/.test(t) && /33%/.test(t), t.slice(0, 400));
        assert.ok(/ready 0\.25, deployed 0\.5, enabled 0\.9, ran without error 1\.0/.test(t));
        assert.ok(/through a sub-technique 0\.6, through the parent technique 0\.4/.test(t));
    },
    "gap lists show the three kinds with counts and tactics": function () {
        var t = open(matrix()).root.textContent;
        assert.ok(/Coverage gaps/.test(t));
        assert.ok(/Data is ready, nothing is deployed \(1\)/.test(t));
        assert.ok(/Content exists, data is missing \(1\)/.test(t));
        assert.ok(/No content in the catalogue \(1\)/.test(t));
        assert.ok(/Access, Impact/.test(t));
    },
    "no gaps section when the response has none": function () {
        var m = matrix();
        m.gaps = { counts: { data_ready: 0, content_no_data: 0, no_content: 0 }, truncated: false, data_ready: [], content_no_data: [], no_content: [] };
        assert.ok(!/Coverage gaps/.test(open(m).root.textContent));
    },
    "enabled elsewhere is shown on the cell, in a card and in a gap row, never as a level": function () {
        var m = matrix();
        m.totals.elsewhere = 1;
        m.tactics[0].techniques[1].elsewhere = 1;
        m.gaps.data_ready[0].elsewhere = 1;
        var v = open(m);
        var t = v.root.textContent;
        assert.ok(/Enabled elsewhere1/.test(t) && /enabled elsewhere/.test(t), t.slice(0, 600));
        var a = v.root.find(function (n) { return n.tagName === "A" && /T2 Wipe/.test(n.getAttribute("title") || ""); })[0];
        assert.ok(/ucm-matrix-elsewhere/.test(a.getAttribute("class")));
        assert.ok(/Enabled elsewhere: 1 use case\(s\).*Not counted above/.test(a.getAttribute("title")));
        assert.ok(!/ucm-matrix-elsewhere/.test(v.root.find(function (n) { return n.tagName === "A" && /T1 Brute/.test(n.getAttribute("title") || ""); })[0].getAttribute("class")));
    },
    "no elsewhere card when nothing is matched": function () {
        assert.ok(!/Enabled elsewhere/.test(open(matrix()).root.textContent));
    },
    "cell tooltip carries the grade and its basis": function () {
        var v = open(matrix());
        var a = v.root.find(function (n) { return n.tagName === "A" && /T1 Brute force/.test(n.getAttribute("title") || ""); });
        assert.strictEqual(a.length, 1);
        assert.ok(/Grade 0\.90 \(a use case maps to this technique\)/.test(a[0].getAttribute("title")));
    }
};

var failed = 0;
Object.keys(tests).forEach(function (name) {
    try { tests[name](); console.log("ok   " + name); } catch (e) { failed++; console.log("FAIL " + name + "\n  " + (e && e.stack || e)); }
});
process.exit(failed ? 1 : 0);
