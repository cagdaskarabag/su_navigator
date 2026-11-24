"use strict";
var assert = require("assert");
var fakeDom = require("./fake_dom");
var runView = fakeDom.runView;
var ucm = fakeDom.loadAmd("ucm_common.js");

var SUMMARY = {
    by_state: { ready: 1, partially_ready: 1, not_ready: 0, blocked: 0, insufficient_evidence: 0 },
    jobs: [], state: { last_success_at: "2026-11-24T12:12:32Z", discovery_at: "d1" }, discovery_completed_at: "d1",
    settings: { scoring: { ready_threshold: 80, partial_threshold: 50, min_coverage: 0.5 } }, top_blockers: [], top_gaps: []
};
function item(id, counts, unverified) {
    return { content_id: id, title: "T " + id, criticality: "high", state: "ready", score: 90, coverage: 0.9,
        blockers: [], gaps: [], counts: counts, unverified: unverified };
}
var PAGE = { total: 2, offset: 0, count: 25, has_more: false, items: [
    item("fenre:UC-1", { met: 5, partial: 1, not_met: 0, unknown: 2, unverified: 3, not_applicable: 0 }, 3),
    item("fenre:UC-2", { met: 2, partial: 0, not_met: 1, unknown: 0, unverified: 0, not_applicable: 1 }, 0)] };

function open(page) {
    return runView("ucm_readiness.js", "ucm-readiness", { readiness: page, "readiness/summary": SUMMARY, catalog: { total: 268 } },
        { jquery: function () { var o = { on: function () { return o; }, val: function () { return ""; } }; return o; } });
}

var tests = {
    "result summary uses the stored counts in the status badge words": function () {
        assert.strictEqual(ucm.resultSummary({ met: 5, partial: 1, not_met: 0, unknown: 2, unverified: 3, not_applicable: 0 }, 3),
            "5 met, 1 partial, 0 not met, 2 unknown, 3 not verified");
        assert.strictEqual(ucm.resultSummary({ met: 1, not_applicable: 2 }, 4), "1 met, 0 partial, 0 not met, 0 unknown, 4 not verified, 2 n/a");
        assert.strictEqual(ucm.resultSummary(undefined, 0), "0 met, 0 partial, 0 not met, 0 unknown, 0 not verified");
    },
    "result badges show only non-zero counts and explain each status": function () {
        var box = ucm.resultBadges({ met: 5, partial: 1, not_met: 0, unknown: 2, unverified: 3, not_applicable: 0 }, 3);
        assert.deepStrictEqual(box.childNodes.map(function (b) { return b.textContent; }), ["5 met", "1 partial", "2 unknown", "3 not verified"]);
        box.childNodes.forEach(function (b) { assert.ok(b.getAttribute("title").length > 20); });
        assert.strictEqual(ucm.resultBadges({}, 0).textContent, "–");
    },
    "an old row without counts falls back to the stored unverified number": function () {
        assert.strictEqual(ucm.resultBadges(undefined, 4).textContent, "4 not verified");
    },
    "readiness table lists the per-status counts of each row": function () {
        var v = open(PAGE);
        var rows = v.root.find(function (n) { return n.tagName === "TR"; });
        var text = rows.map(function (r) { return r.textContent; }).join("\n");
        assert.ok(/5 met1 partial2 unknown3 not verified/.test(text), text);
        assert.ok(/2 met1 not met1 n\/a/.test(text), text);
        var heads = v.root.find(function (n) { return n.tagName === "TH"; }).map(function (n) { return n.textContent; });
        assert.ok(heads.indexOf("Requirement results") >= 0 && heads.indexOf("Not verified") < 0, heads.join("|"));
    }
};

var failed = 0;
Object.keys(tests).forEach(function (name) {
    try { tests[name](); console.log("ok   " + name); } catch (e) { failed++; console.log("FAIL " + name + ": " + (e.stack || e.message)); }
});
process.exit(failed ? 1 : 0);
