"use strict";
var assert = require("assert");
var runView = require("./fake_dom").runView;

var CATS = { categories: [{ _key: "fenre_cat-9", category_id: "9", name: "Authentication", domains: ["security"], provider: "fenre" }] };
var FACETS = { review_statuses: [], regulations: [], quality_flags: [], domains: { security: 7 }, categories: { "fenre_cat-9": 7 },
    criticality: { high: 6 }, difficulty: { beginner: 3 }, providers: { fenre: 5, escu: 2 }, waves: {},
    maturities: { raw: 3, normalized: 2, enriched: 1, correlated: 1 },
    provider_info: { fenre: { count: 5, version: "2026.11", updated: "2026-11-20T09:00:00Z" }, escu: { count: 2, version: "6.11.1", updated: "2026-11-24T10:00:00Z" } },
    summary: { version: 7, outdated: 0 }, active: 7, computed_at: "t" };
var ITEMS = [{ _key: "fenre_UC-9.1.1", content_id: "fenre:UC-9.1.1", record_id: "9.1.1", title: "t", summary: "s", domains: ["security"],
    criticality: "high", difficulty: "beginner", sourcetypes: [], mitre_ids: [], review_status: "verified" }];

function open(over, opts) {
    var routes = { categories: CATS, "catalog/facets": FACETS, "readiness/summary": { total: 0, by_state: {} }, selections: { items: [] },
        catalog: { items: ITEMS, total: 1, offset: 0, count: 25, has_more: false } };
    Object.assign(routes, over || {});
    return runView("ucm_catalogue.js", "ucm-catalogue", routes, opts);
}
function lastParams(v) {
    var c = v.calls.filter(function (x) { return x.method === "GET" && x.path === "catalog"; });
    return c[c.length - 1].params;
}
function box(v, value) {
    return v.root.find(function (n) { return n.tagName === "INPUT" && n.getAttribute("type") === "checkbox" && n.getAttribute("value") === value; })[0];
}

var tests = {
    "data maturity facet lists the four levels with catalogue counts and their meaning": function () {
        var t = open().root.textContent;
        assert.ok(/Data maturity/.test(t) && /not Splunk's levels/.test(t));
        ["raw", "normalized", "enriched", "correlated"].forEach(function (l) { assert.ok(box(open(), l), l); });
        assert.ok(/normalized\s*\(2\)/.test(t) && /raw\s*\(3\)/.test(t));
    },
    "choosing a maturity level sends it and shows an active filter chip": function () {
        var v = open();
        var b = box(v, "enriched");
        b.checked = true;
        b.dispatch("change");
        assert.strictEqual(lastParams(v).maturity, "enriched");
        assert.ok(/data maturity: enriched/.test(v.root.textContent));
    },
    "the maturity filter is restored from the address": function () {
        var v = open({}, { search: "?maturity=raw,correlated" });
        assert.strictEqual(lastParams(v).maturity, "raw,correlated");
        assert.strictEqual(box(v, "raw").checked, true);
    },
    "an info strip shows each provider's version, count and import date": function () {
        var t = open().root.textContent;
        assert.ok(/7 active use cases/.test(t));
        assert.ok(/Fenre 2026\.11: 5, imported 2026-11-20 09:00:00 UTC/.test(t));
        assert.ok(/ESCU 6\.11\.1: 2, imported 2026-11-24 10:00:00 UTC/.test(t));
    },
    "no strip when the facets carry no provider information": function () {
        var t = open({ "catalog/facets": Object.assign({}, FACETS, { provider_info: {} }) }).root.textContent;
        assert.ok(!/active use cases\./.test(t));
    },
    "the link button copies the address, or shows it when copying is unavailable": function () {
        var v = open({}, { search: "?maturity=raw" });
        var btn = v.root.find(function (n) { return n.tagName === "BUTTON" && n.textContent === "Copy link to this view"; })[0];
        assert.ok(btn);
        assert.ok(/Only my bookmarks/.test(btn.getAttribute("title") || "") || /bookmarks/.test(btn.getAttribute("title")));
        var copied = null;
        Object.defineProperty(global, "navigator", { configurable: true, writable: true, value: { clipboard: { writeText: function (u) { copied = u; return { then: function (f) { f(); } }; } } } });
        btn.dispatch("click");
        assert.ok(copied && /splunk\.test/.test(copied), copied);
        assert.ok(/Link copied/.test(v.root.textContent));
        global.navigator = {};
        btn.dispatch("click");
        var shown = v.root.find(function (n) { return n.tagName === "INPUT" && n.getAttribute("aria-label") === "Link to this view"; })[0];
        assert.ok(shown && shown.getAttribute("hidden") === null && /splunk\.test/.test(shown.value), shown && shown.value);
    },
    "outdated summaries now name the data maturity filter": function () {
        var v = open({ "catalog/facets": Object.assign({}, FACETS, { summary: { version: 7, outdated: 5 } }) });
        assert.ok(/wave, data maturity, analytic story and data source filters/.test(v.root.textContent));
    }
};

var failed = 0;
Object.keys(tests).forEach(function (name) {
    try { tests[name](); console.log("ok   " + name); } catch (e) { failed++; console.log("FAIL " + name + "\n  " + (e && e.stack || e)); }
});
process.exit(failed ? 1 : 0);
