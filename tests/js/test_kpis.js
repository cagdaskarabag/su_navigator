"use strict";
var assert = require("assert");
var fakeDom = require("./fake_dom");
var runView = fakeDom.runView;
var ucm = fakeDom.loadAmd("ucm_common.js");

function by(over) { return Object.assign({ ready: 0, partially_ready: 0, not_ready: 0, blocked: 0, insufficient_evidence: 0 }, over); }
function kpi(list, label) { return list.filter(function (k) { return k.label === label; })[0]; }

var tests = {
    "percent keeps one decimal below 10 percent and has no value without a denominator": function () {
        assert.strictEqual(ucm.percent(111, 268), "41%");
        assert.strictEqual(ucm.percent(1, 268), "0.4%");
        assert.strictEqual(ucm.percent(0, 268), "0%");
        assert.strictEqual(ucm.percent(5, 0), null);
    },
    "readiness KPIs use the stored counts and say how they are calculated": function () {
        var list = ucm.readinessKpis(268, { by_state: by({ ready: 111, partially_ready: 15, not_ready: 141, insufficient_evidence: 1 }) });
        var a = kpi(list, "Assessed"), r = kpi(list, "Ready"), p = kpi(list, "Ready or partially ready");
        assert.strictEqual(a.value, "100%"); assert.strictEqual(a.detail, "268 of 268 active use cases");
        assert.strictEqual(r.value, "41%"); assert.strictEqual(r.detail, "111 of 268 assessed");
        assert.strictEqual(p.value, "47%"); assert.strictEqual(p.detail, "126 of 268 assessed");
        list.forEach(function (k) { assert.ok(k.how.length > 40 && /÷/.test(k.how), k.label); });
    },
    "nothing assessed gives dashes, not zero percent": function () {
        var list = ucm.readinessKpis(268, { by_state: by() });
        assert.strictEqual(kpi(list, "Assessed").value, "0%");
        assert.strictEqual(kpi(list, "Ready").value, null);
        assert.ok(/nothing assessed yet/.test(kpi(list, "Ready").detail));
    },
    "unknown catalogue size does not invent a percentage": function () {
        var a = kpi(ucm.readinessKpis(null, { by_state: by({ ready: 3 }) }), "Assessed");
        assert.strictEqual(a.value, null);
        assert.ok(/catalogue size unavailable/.test(a.detail));
    },
    "a KPI card renders value, detail and the calculation as text": function () {
        var card = ucm.kpiCard({ label: "Ready", value: "41%", detail: "111 of 268 assessed", how: "ready ÷ assessed" });
        assert.ok(/Ready41%111 of 268 assessedready ÷ assessed/.test(card.textContent), card.textContent);
        assert.strictEqual(card.getAttribute("title"), "ready ÷ assessed");
        assert.strictEqual(/–/.test(ucm.kpiCard({ label: "x", value: null, how: "h" }).textContent), true);
    },
    "overview shows the shared KPIs plus deployments": function () {
        var v = runView("ucm_overview.js", "ucm-overview-kpis", {
            catalog: { total: 268, items: [] },
            "readiness/summary": { by_state: by({ ready: 111, partially_ready: 15, not_ready: 141, insufficient_evidence: 1 }) },
            deployments: { items: [], summary: { total: 5, by_state: { deployed: 2, retired: 1 }, by_live: { enabled: 1 } } } });
        var t = v.root.textContent;
        assert.ok(/Assessed100%268 of 268 active use cases/.test(t), t);
        assert.ok(/Deployed2/.test(t) && /1 enabled; 5 deployments recorded/.test(t), t);
        assert.deepStrictEqual(v.calls.map(function (c) { return c.path; }).sort(), ["catalog", "catalog/facets", "deployments", "readiness/summary"]);
        assert.strictEqual(v.calls.filter(function (c) { return c.method !== "GET"; }).length, 0);
    },
    "overview still shows readiness KPIs when deployments fail": function () {
        var v = runView("ucm_overview.js", "ucm-overview-kpis", {
            catalog: { total: 10 }, "readiness/summary": { by_state: by({ ready: 5 }) }, deployments: new Error("nope") });
        assert.ok(/Assessed50%/.test(v.root.textContent) && /Ready100%/.test(v.root.textContent) && !/Deployed/.test(v.root.textContent));
    },
    "overview reports a failing catalogue instead of empty KPIs": function () {
        var v = runView("ucm_overview.js", "ucm-overview-kpis", { catalog: new Error("down"), "readiness/summary": { by_state: by() } });
        assert.ok(/could not be loaded/.test(v.root.textContent) && /down/.test(v.root.textContent));
    }
};

var failed = 0;
Object.keys(tests).forEach(function (name) {
    try { tests[name](); console.log("ok   " + name); } catch (e) { failed++; console.log("FAIL " + name + ": " + (e.stack || e.message)); }
});
process.exit(failed ? 1 : 0);
