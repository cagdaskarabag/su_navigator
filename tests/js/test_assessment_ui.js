"use strict";
var assert = require("assert");
var runView = require("./fake_dom").runView;

var DEFS = [
    { framework_id: "mitre_attack_enterprise", name: "MITRE ATT&CK Enterprise", version: "18.1", kind: "attack", active: true },
    { framework_id: "cmmc-l2", name: "CMMC Level 2", version: "2.0", version_label: "2.0 Level 2", kind: "controls", active: true, controls: 3 }
];

function row(id, title, parent, kind, extra) {
    return Object.assign({ id: id, title: title, parent: parent, kind: kind, withdrawn: false, level: null,
        counts: { catalogue: 0, ready: 0, deployed: 0, enabled: 0, operational: 0 }, use_cases: [], clauses: [], mapped: false,
        gap: kind !== "family", below: { controls: 0, mapped: 0, ready: 0, enabled: 0 } }, extra || {});
}

var CATALOGUE = {
    catalogue: { framework_id: "cmmc-l2", name: "CMMC Level 2", version: "2.0", version_label: "2.0 Level 2", modified: "", source: "", attribution: "DoD." },
    regulation_ids: ["cmmc"], levels: [],
    totals: { controls: 2, mapped: 0, unmapped: 2, ready: 0, deployed: 0, enabled: 0, withdrawn: 0, mapped_to_withdrawn: 0 },
    controls: [row("AC", "Access Control", null, "family", { below: { controls: 2, mapped: 0, ready: 0, enabled: 0 } }),
        row("3.1.1", "Limit access", "AC", "requirement", { weight: 5, objective_count: 2 }),
        row("3.1.2", "Limit functions", "AC", "requirement", { weight: 5 })],
    unmatched: [], unmatched_count: 0
};

function assessment() {
    return {
        framework_id: "cmmc-l2", version: "2.0",
        assessments: { "3.1.2": { control_id: "3.1.2", status: "planned", complete: true, note: "Waiting for the vendor", assessed_by: "alice",
            assessed_at: "2026-11-20T10:00:00+00:00", first_assessed_by: "alice", first_assessed_at: "2026-11-20T10:00:00+00:00",
            history: [{ at: "2026-11-20T10:00:00+00:00", by: "alice", status: "planned", note: "Waiting for the vendor" }], objectives: {}, stale_version: false } },
        orphaned: [],
        summary: { controls: 2, assessed: 1, not_assessed: 1, by_status: { implemented: 0, partially_implemented: 0, planned: 1, not_implemented: 0, not_applicable: 0 },
            incomplete: 0, stale_version: 0, objectives: 2, objectives_assessed: 0 },
        score: { method: "dod", start: 110, note: "DoD methodology.", score: 100, ceiling: 110, points_lost: 10, requirements: 2, assessed: 1, unassessed: 1,
            lost_by_value: {}, complete: false, blocked_by: ["3.12.4"] }
    };
}

function open(caps, extra) {
    var routes = {
        frameworks: { definitions: DEFS, coverage: [], use_cases: 0, features: { compliance: true } },
        "frameworks/matrix": { framework_id: "mitre_attack_enterprise", version: "18.1", name: "x", domain: "enterprise", attribution: "", levels: [],
            totals: { techniques: 0, covered: {}, grade_avg: 0 }, tactics: [], remapped: [], unresolved: [] },
        "frameworks/catalogue": CATALOGUE,
        assessment: assessment(),
        "assessment/control": function (p) {
            return p.control_id === "3.1.1"
                ? { control: { id: "3.1.1", title: "Limit access", objectives: [{ id: "A.03.01.01.a", text: "authorized users are identified" }, { id: "A.03.01.01.b", text: "processes are identified" }] }, assessment: null }
                : { control: { id: "3.1.2", title: "Limit functions", objectives: [] }, assessment: assessment().assessments["3.1.2"] };
        },
        poam: { items: [{ id: "pm_1", control_id: "3.1.2", title: "Buy the tool", weakness: "No tool", owner: "bob", due: "2026-01-01", state: "open", overdue: true,
            milestones: [{ text: "Quote", due: "2026-02-01", done: false }], control_status: "planned" }],
            counts: { open: 1, in_progress: 0, closed: 0, risk_accepted: 0, overdue: 1 }, total: 1, today: "2026-11-25" },
        "assessment/snapshots": { items: [{ id: "sn_1", created_at: "2026-11-20T10:00:00+00:00", created_by: "alice", label: "Q4", version_label: "2.0 Level 2", sha256: "a".repeat(64), size: 10 }] },
        "RAW services/authentication/current-context": { entry: [{ content: { capabilities: caps } }] }
    };
    return runView("ucm_coverage.js", "ucm-coverage", Object.assign(routes, extra || {}), {});
}

function find(v, pred) { return v.root.find(pred); }
function button(v, text) { return find(v, function (n) { return n.tagName === "BUTTON" && n.textContent === text; }); }
function openAll(v) { find(v, function (n) { return n.tagName === "DETAILS"; }).forEach(function (d) { d.dispatch("toggle"); }); }

var tests = {
    "without the capability nothing about assessment is shown or requested": function () {
        var v = open(["ucm_read"]);
        openAll(v);
        assert.ok(!/Assessment|Plan of action/.test(v.root.textContent));
        assert.ok(!v.calls.some(function (c) { return /^(assessment|poam)/.test(c.path); }));
    },
    "with the module turned off nothing about assessment is shown or requested, whatever the role": function () {
        var v = open(["ucm_assess"], { frameworks: { definitions: DEFS, coverage: [], use_cases: 0, features: { compliance: false } } });
        openAll(v);
        assert.ok(!/Assessment|Plan of action|Evidence snapshots/.test(v.root.textContent));
        assert.strictEqual(button(v, "Assess").length, 0);
        assert.ok(!v.calls.some(function (c) { return /^(assessment|poam)/.test(c.path); }));
        assert.ok(/Control catalogues/.test(v.root.textContent), "the control catalogue stays");
    },
    "with the capability the summary, score, blocked requirement, plan items and snapshots are shown": function () {
        var v = open(["ucm_assess"]);
        var t = v.root.textContent;
        var i = t.indexOf("Assessment");
        assert.ok(/1 of 2Assessed/.test(t) && /100Score now/.test(t) && /110Best possible score/.test(t), t.slice(i, i + 900));
        assert.ok(/A requirement that must be implemented is not: 3\.12\.4/.test(t));
        assert.ok(/Plan of action and milestones/.test(t) && /Buy the tool/.test(t) && /overdue/.test(t) && /Control: Planned/.test(t));
        assert.ok(/Evidence snapshots/.test(t) && /Q4/.test(t) && /aaaaaaaaaaaaaaaa/.test(t));
    },
    "a control row shows its status and an Assess or Edit button": function () {
        var v = open(["ucm_assess"]);
        openAll(v);
        var t = v.root.textContent;
        assert.ok(/Planned/.test(t) && /Not assessed/.test(t));
        assert.strictEqual(button(v, "Assess").length, 1);
        assert.strictEqual(button(v, "Edit").length, 1);
    },
    "a requirement with objectives is assessed per objective and only changed ones are sent": function () {
        var v = open(["ucm_assess"]);
        openAll(v);
        button(v, "Assess")[0].dispatch("click");
        var selects = find(v, function (n) { return n.tagName === "SELECT" && /^Result for/.test(n.getAttribute("aria-label") || ""); });
        assert.strictEqual(selects.length, 2);
        selects[0].value = "met";
        find(v, function (n) { return n.tagName === "TEXTAREA" && n.getAttribute("aria-label") === "Why this assessment"; })[0].value = "Reviewed the account list";
        button(v, "Save assessment")[0].dispatch("click");
        var call = v.calls.filter(function (c) { return c.method === "POST" && c.path === "assessment"; })[0];
        assert.deepStrictEqual(call.params.objectives, { "A.03.01.01.a": { result: "met", note: "" } });
        assert.strictEqual(call.params.note, "Reviewed the account list");
        assert.strictEqual(call.params.control_id, "3.1.1");
    },
    "a control without objectives is assessed with a status and the reason is mandatory input": function () {
        var posted = null;
        var v = open(["ucm_assess"], { "POST assessment": function (p) {
            posted = p;
            var a = assessment();
            a.assessments["3.1.2"].status = "implemented";
            return { assessment: a.assessments["3.1.2"], summary: a.summary, score: a.score };
        } });
        openAll(v);
        button(v, "Edit")[0].dispatch("click");
        var sel = find(v, function (n) { return n.getAttribute("aria-label") === "Status"; })[0];
        sel.value = "implemented";
        find(v, function (n) { return n.tagName === "TEXTAREA"; }).filter(function (n) { return n.getAttribute("aria-label") === "Why this assessment"; })[0].value = "Verified in the console";
        button(v, "Save assessment")[0].dispatch("click");
        assert.deepStrictEqual([posted.status, posted.control_id, posted.note], ["implemented", "3.1.2", "Verified in the console"]);
        assert.ok(/Implemented/.test(v.root.textContent));
    },
    "a refused assessment shows the server message and keeps the form": function () {
        var v = open(["ucm_assess"], { "POST assessment": new Error("a reason of at least 5 characters is needed") });
        openAll(v);
        button(v, "Edit")[0].dispatch("click");
        button(v, "Save assessment")[0].dispatch("click");
        assert.ok(/a reason of at least 5 characters is needed/.test(v.root.textContent));
        assert.strictEqual(button(v, "Save assessment").length, 1);
    },
    "removing an assessment asks for a reason first": function () {
        var v = open(["ucm_assess"]);
        openAll(v);
        button(v, "Edit")[0].dispatch("click");
        var asked = null;
        v.ucm.askText = function (title, text, opts, label, cb) { asked = { opts: opts, cb: cb }; };
        button(v, "Remove assessment")[0].dispatch("click");
        assert.strictEqual(asked.opts.minLength, 5);
        assert.ok(!v.calls.some(function (c) { return c.path === "assessment/clear"; }));
    },
    "a plan item that may not count toward Conditional status says why, and the score line is shown": function () {
        var elig = { eligible: false, basis: "32 CFR 170.21(a)(2) and (b)", notice: "Information only: this is not a CMMC status determination.",
            reasons: ["Its point value is 5; only requirements worth one point may be on a plan."] };
        var v = open(["ucm_assess"], { poam: { items: [{ id: "pm_1", control_id: "AC.L2-3.1.1", title: "MFA", weakness: "none", owner: "bob", due: "2026-12-01",
            state: "open", overdue: false, milestones: [], control_status: "not_implemented", eligibility: elig }],
            counts: { open: 1, in_progress: 0, closed: 0, risk_accepted: 0, overdue: 0 }, total: 1, today: "2026-11-25",
            programme: { basis: "32 CFR 170.21(a)(2) and (b)", notice: elig.notice, score: 95, requirements: 110, ratio: 0.8636, threshold: 0.8, meets_threshold: true } } });
        openAll(v);
        var t = v.root.textContent;
        assert.ok(/may not count toward Conditional status/.test(t) && /point value is 5/.test(t), t);
        assert.ok(/Score now 95 of 110 \(0\.86\)/.test(t) && /at least 0\.80/.test(t) && /not a CMMC status determination/.test(t), t);
        assert.ok(button(v, "Close").length === 1, "the item is not blocked");
    },
    "the programme banner does not call a score a pass while the system security plan is missing": function () {
        function banner(programme) {
            var v = open(["ucm_assess"], { poam: { items: [{ id: "pm_1", control_id: "AC.L2-3.1.3", title: "t", weakness: "w", owner: "bob", due: "2026-12-01",
                state: "open", overdue: false, milestones: [], eligibility: { eligible: true, reasons: [], basis: "b", notice: "n" } }],
                counts: { open: 1, in_progress: 0, closed: 0, risk_accepted: 0, overdue: 0 }, total: 1, today: "2026-11-25",
                programme: Object.assign({ basis: "32 CFR 170.21(a)(2) and (b)", notice: "Information only.", score: 100, requirements: 110, ratio: 0.9091,
                    threshold: 0.8, meets_threshold: true }, programme) } });
            openAll(v);
            var box = find(v, function (n) { return /ucm-state /.test((n.getAttribute("class") || "") + " ") && /Score now/.test(n.textContent); })[0];
            return { text: v.root.textContent, warn: /ucm-state-warn/.test(box.getAttribute("class")) ? 1 : 0,
                info: /ucm-state-info/.test(box.getAttribute("class")) ? 1 : 0 };
        }
        var blocked = banner({ can_pass: false, blocked_by: ["CA.L2-3.12.4"] });
        assert.ok(/reaches the threshold, but this is not a pass/.test(blocked.text) && /system security plan/.test(blocked.text) && /CA\.L2-3\.12\.4/.test(blocked.text), blocked.text);
        assert.strictEqual(blocked.warn, 1, "shown as a warning");
        var below = banner({ meets_threshold: false, ratio: 0.5, score: 55, can_pass: false, blocked_by: [] });
        assert.ok(/Not a pass either way/.test(below.text), below.text);
        var clear = banner({ can_pass: true, blocked_by: [] });
        assert.ok(!/not a pass/i.test(clear.text) && /Score now 100 of 110/.test(clear.text), clear.text);
        assert.strictEqual(clear.info, 1);
        var old = banner({});
        assert.ok(!/not a pass/i.test(old.text), "an answer without can_pass keeps the old wording");
    },
    "an eligible item shows no warning": function () {
        var v = open(["ucm_assess"], { poam: { items: [{ id: "pm_1", control_id: "AC.L2-3.1.3", title: "t", weakness: "w", owner: "bob", due: "2026-12-01",
            state: "open", overdue: false, milestones: [], eligibility: { eligible: true, reasons: [], basis: "b", notice: "n" } }],
            counts: { open: 1, in_progress: 0, closed: 0, risk_accepted: 0, overdue: 0 }, total: 1, today: "2026-11-25", programme: null } });
        openAll(v);
        assert.ok(!/may not count toward/.test(v.root.textContent));
    },
    "closing a plan item needs a note and accepting a risk needs a longer one": function () {
        var v = open(["ucm_assess"], { "POST poam/close": { item: {} } });
        var asked = [];
        v.ucm.askText = function (title, text, opts, label, cb) { asked.push({ opts: opts, cb: cb }); };
        button(v, "Close")[0].dispatch("click");
        button(v, "Accept risk")[0].dispatch("click");
        assert.deepStrictEqual(asked.map(function (a) { return a.opts.minLength; }), [5, 10]);
        asked[1].cb("Accepted by the CISO");
        var call = v.calls.filter(function (c) { return c.path === "poam/close"; })[0];
        assert.deepStrictEqual([call.params.id, call.params.resolution, call.params.note], ["pm_1", "risk_accepted", "Accepted by the CISO"]);
    },
    "adding a plan item sends milestones with optional dates": function () {
        var v = open(["ucm_assess"]);
        var byLabel = function (l) { return find(v, function (n) { return n.getAttribute("aria-label") === l; })[0]; };
        byLabel("Control id").value = "3.1.2";
        byLabel("Title").value = "Buy the tool";
        byLabel("Weakness").value = "No tool today";
        byLabel("Owner").value = "bob";
        byLabel("Due date").value = "2027-01-31";
        byLabel("Milestones").value = "2026-12-01 Get quotes\nSign the order";
        button(v, "Add plan item").filter(function (b) { return b.getAttribute("type") === "button"; }).pop().dispatch("click");
        var call = v.calls.filter(function (c) { return c.method === "POST" && c.path === "poam"; })[0];
        assert.deepStrictEqual(call.params.milestones, [{ text: "Get quotes", due: "2026-12-01" }, { text: "Sign the order", due: "" }]);
        assert.strictEqual(call.params.due, "2027-01-31");
    },
    "a snapshot download reports a failed integrity check": function () {
        var v = open(["ucm_assess"], { "assessment/snapshot": { id: "sn_1", filename: "a.json", content: "{}", sha256: "x",
            integrity: { ok: false, expected: "aa", actual: "bb" } } });
        global.URL = { createObjectURL: function () { return "blob:x"; }, revokeObjectURL: function () {} };
        global.Blob = function () {};
        global.document.body = { appendChild: function () {}, removeChild: function () {} };
        var origCreate = global.document.createElement;
        global.document.createElement = function (tag) { var n = origCreate(tag); n.click = function () {}; return n; };
        try {
            button(v, "Download")[0].dispatch("click");
            assert.ok(/WARNING: the stored snapshot does not match/.test(v.root.textContent));
        } finally { global.document.createElement = origCreate; }
    }
};

var failed = 0;
Object.keys(tests).forEach(function (name) {
    try { tests[name](); console.log("ok   " + name); } catch (e) { failed++; console.log("FAIL " + name + ": " + (e.stack || e.message).split("\n").slice(0, 6).join("\n")); }
});
process.exit(failed ? 1 : 0);
