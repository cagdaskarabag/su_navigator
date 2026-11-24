"use strict";
var assert = require("assert");
var runView = require("./fake_dom").runView;

function texts(root) { return root.textContent; }
function links(root) {
    return root.find(function (n) { return n.tagName === "A"; }).map(function (n) { return n.getAttribute("href"); });
}
function nextSteps(root) {
    return root.find(function (n) { return /ucm-step-next/.test(n.getAttribute("class") || ""); }).map(function (n) { return n.textContent; });
}

var RS = ["ready", "partially_ready", "not_ready", "blocked", "insufficient_evidence"];
function routes(over) {
    var base = {
        "catalog": { total: 268, items: [] },
        "sync": { provider_state: { last_success_at: "2026-01-02T00:00:00Z", last_good_version: "8.28.0" } },
        "discovery": { state: { last_completed_at: "2026-01-03T00:00:00Z", totals: { pairs: 32, indexes_eligible: 14, truncated: false } } },
        "readiness/summary": { total: 268, by_state: { ready: 111, partially_ready: 15, not_ready: 141, blocked: 0, insufficient_evidence: 1 },
            state: { last_success_at: "2026-01-04T00:00:00Z", discovery_at: "2026-01-03T00:00:00Z" }, discovery_completed_at: "2026-01-03T00:00:00Z" }
    };
    return Object.assign(base, over || {});
}

var tests = {
    "full state renders counts, links and Choose as next step": function () {
        var v = runView("ucm_home.js", "ucm-home", routes());
        var t = texts(v.root);
        assert.ok(/268/.test(t) && /8\.28\.0/.test(t) && /32 index\/sourcetype pairs in 14 indexes/.test(t), t);
        assert.deepStrictEqual(nextSteps(v.root).map(function (s) { return s.indexOf("Choose") >= 0; }), [true]);
        RS.forEach(function (st) { assert.ok(links(v.root).indexOf("ucm_readiness?state=" + st) >= 0, st); });
    },
    "no catalogue: next step is Get content and nothing claims data": function () {
        var v = runView("ucm_home.js", "ucm-home", routes({ "catalog": { total: 0, items: [] } }));
        assert.ok(/No use cases imported yet/.test(texts(v.root)));
        var n = nextSteps(v.root);
        assert.strictEqual(n.length, 1); assert.ok(/Get content/.test(n[0]));
    },
    "no discovery: next step is Discover": function () {
        var v = runView("ucm_home.js", "ucm-home", routes({ "discovery": { state: {} } }));
        assert.ok(/Discovery has not completed yet/.test(texts(v.root)));
        assert.ok(/Discover/.test(nextSteps(v.root)[0]));
    },
    "discovery but no assessment: next step is Assess": function () {
        var v = runView("ucm_home.js", "ucm-home", routes({ "readiness/summary": { total: 0, by_state: {}, state: {}, discovery_completed_at: "2026-01-03T00:00:00Z" } }));
        assert.ok(/not been assessed yet/.test(texts(v.root)));
        assert.ok(/Assess/.test(nextSteps(v.root)[0]));
    },
    "stale readiness is flagged": function () {
        var r = routes();
        r["readiness/summary"].state.discovery_at = "2025-12-31T00:00:00Z";
        var v = runView("ucm_home.js", "ucm-home", r);
        assert.ok(/older than the latest discovery/.test(texts(v.root)));
    },
    "a failing endpoint only fails its own card": function () {
        var v = runView("ucm_home.js", "ucm-home", routes({ "discovery": new Error("boom") }));
        var t = texts(v.root);
        assert.ok(/boom/.test(t) && /268/.test(t) && /111/.test(t));
        assert.strictEqual(nextSteps(v.root).length, 0, "no next step is claimed when discovery state is unknown");
    },
    "domain links cover the 13 domains plus all": function () {
        var v = runView("ucm_home.js", "ucm-home", routes());
        var d = links(v.root).filter(function (h) { return h.indexOf("ucm_domain?form.domain=") === 0; });
        assert.strictEqual(d.length, 14);
        assert.ok(d.indexOf("ucm_domain?form.domain=ot_ics") >= 0 && d.indexOf("ucm_domain?form.domain=*") >= 0);
    },
    "static sections exist and Overview stays linked": function () {
        var v = runView("ucm_home.js", "ucm-home", routes());
        assert.ok(/The user guide is in development/.test(texts(v.root)));
        assert.ok(links(v.root).indexOf("ucm_overview") >= 0);
        assert.ok(v.root.find(function (n) { return n.getAttribute("id") === "ucm-home-recommendations"; }).length === 1);
    }
};

var failed = 0;
Object.keys(tests).forEach(function (name) {
    try { tests[name](); console.log("ok   " + name); } catch (e) { failed++; console.log("FAIL " + name + ": " + (e.stack || e.message)); }
});
process.exit(failed ? 1 : 0);
