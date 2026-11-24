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

var ITEM = { content_id: "fenre:UC-9.1.1", record_id: "9.1.1", title: "<img src=x onerror=1> Brute force", state: "ready", score: 100,
    coverage: 1, criticality: "high", criticality_rank: 3, domains: ["security"], draft_score: 83.75,
    score_parts: { readiness: 40, criticality: 18.75, mitre_gain: 10, coverage: 15 }, mitre_total: 2, mitre_new: ["T1110"],
    unverified: 1, flags: ["in_backlog", "deployment_in_progress"], deployment_state: "pending_approval",
    reasons: ["Readiness ready: score 100, 100% of the requirement weight decided.", "1 requirement not verified yet (not checked, which is different from missing)."] };
var REC = { items: [ITEM], eligible_total: 12, empty: null, excluded: { rejected_by_you: 2 },
    formula: { version: "ucm.recommend/1", weights: { readiness: 0.4, criticality: 0.25, mitre_gain: 0.2, coverage: 0.15 } } };
function emptyRec(kind, excluded) { return { items: [], eligible_total: 0, empty: kind, excluded: excluded || {}, formula: REC.formula }; }

var RS = ["ready", "partially_ready", "not_ready", "blocked", "insufficient_evidence"];
function routes(over) {
    var base = {
        "catalog": { total: 268, items: [] },
        "sync": { provider_state: { last_success_at: "2026-01-02T00:00:00Z", last_good_version: "8.28.0" } },
        "discovery": { state: { last_completed_at: "2026-01-03T00:00:00Z", totals: { pairs: 32, indexes_eligible: 14, truncated: false } } },
        "readiness/recommendations": REC,
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
    "recommendations list real fields, link to the use case and show the formula": function () {
        var v = runView("ucm_home.js", "ucm-home", routes());
        var t = texts(v.root);
        assert.ok(/Showing 1 of 12 eligible use cases/.test(t), t);
        assert.ok(/Draft score = 40% readiness score \+ 25% criticality \+ 20% new MITRE coverage \+ 15% requirement coverage/.test(t));
        assert.ok(/Draft score 83\.75 = readiness score 40 \+ criticality 18\.75 \+ new MITRE coverage 10 \+ requirement coverage 15/.test(t), t);
        assert.ok(links(v.root).indexOf("ucm_usecase?id=fenre%3AUC-9.1.1") >= 0, links(v.root).join(" "));
        assert.ok(/In your backlog/.test(t) && /Deployment pending approval/.test(t));
        assert.ok(/1 requirement not verified yet/.test(t));
        assert.strictEqual(v.root.find(function (n) { return n.tagName === "IMG"; }).length, 0, "titles are text");
        assert.ok(t.indexOf("<img src=x onerror=1> Brute force") >= 0);
        assert.strictEqual(v.calls.filter(function (c) { return c.method !== "GET"; }).length, 0, "reading recommendations changes nothing");
    },
    "the four empty states are distinct": function () {
        var want = { no_catalogue: /No use cases have been imported yet/, no_discovery: /Discovery has not completed yet\.[\s\S]*Recommendations need/,
            no_assessment: /have not been assessed yet/, none_eligible: /No use case is eligible right now[\s\S]*Left out: 3 rejected by you, 5 not ready\./ };
        Object.keys(want).forEach(function (k) {
            var r = routes({ "readiness/recommendations": emptyRec(k, k === "none_eligible" ? { rejected_by_you: 3, not_ready: 5 } : {}) });
            var rec = runView("ucm_home.js", "ucm-home", r).root.find(function (n) { return n.getAttribute("id") === "ucm-home-recommendations"; })[0];
            assert.ok(want[k].test(rec.textContent), k + ": " + rec.textContent);
            Object.keys(want).filter(function (o) { return o !== k; }).forEach(function (o) {
                if (o === "no_discovery" || o === "no_catalogue") { assert.ok(!want[o].test(rec.textContent), k + " vs " + o); }
            });
        });
    },
    "a failing recommendations request only fails that section": function () {
        var v = runView("ucm_home.js", "ucm-home", routes({ "readiness/recommendations": new Error("nope") }));
        var rec = v.root.find(function (n) { return n.getAttribute("id") === "ucm-home-recommendations"; })[0];
        assert.ok(/Recommendations are not available/.test(rec.textContent) && /nope/.test(rec.textContent));
        assert.ok(/268/.test(texts(v.root)), "the rest of the page still renders");
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
