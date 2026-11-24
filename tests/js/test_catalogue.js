"use strict";
var assert = require("assert");
var runView = require("./fake_dom").runView;

var CATS = { categories: [
    { _key: "fenre_cat-9", category_id: "9", name: "Authentication", domains: ["security"] },
    { _key: "fenre_cat-2", category_id: "2", name: "Servers", domains: ["infrastructure"] },
    { _key: "escu_cat-endpoint", category_id: "1", name: "Endpoint", domains: ["endpoint", "security"] }] };
var FACETS = { review_statuses: [{ id: "verified", count: 3 }], regulations: [{ id: "gdpr", label: "GDPR", count: 4 }],
    quality_flags: [{ id: "duplicate_spl", count: 2 }], domains: { security: 7, infrastructure: 2, endpoint: 1 },
    categories: { "fenre_cat-9": 5, "fenre_cat-2": 2, "escu_cat-endpoint": 1 }, criticality: { high: 6, low: 4 },
    difficulty: { beginner: 3 }, active: 10, computed_at: "t" };
var ITEMS = [{ _key: "fenre_UC-9.1.1", content_id: "fenre:UC-9.1.1", record_id: "9.1.1", title: "<img src=x onerror=1>",
    summary: "s", domains: ["security"], criticality: "high", difficulty: "beginner", sourcetypes: [], mitre_ids: [], review_status: "verified" }];

function open(over, opts) {
    var routes = { categories: CATS, "catalog/facets": FACETS,
        "readiness/summary": { total: 8, by_state: { ready: 5, partially_ready: 1, not_ready: 2, blocked: 0, insufficient_evidence: 0 } },
        selections: { items: [] }, "POST selections": { selection: {} }, "POST selections/delete": { deleted: true }, catalog: { items: ITEMS, total: 1, offset: 0, count: 25, has_more: false } };
    Object.assign(routes, over || {});
    return runView("ucm_catalogue.js", "ucm-catalogue", routes, opts);
}
function catalogCalls(v) { return v.calls.filter(function (c) { return c.method === "GET" && c.path === "catalog"; }); }
function lastParams(v) { var c = catalogCalls(v); return c[c.length - 1].params; }
function box(v, key, value) {
    var found = v.root.find(function (n) { return n.tagName === "INPUT" && n.getAttribute("type") === "checkbox" && n.getAttribute("value") === value
        && n.parentNode && n.parentNode.parentNode && n.parentNode.parentNode.parentNode && /ucm-facet/.test(n.parentNode.parentNode.parentNode.getAttribute("class") || ""); });
    return found.filter(function (n) { return n.getAttribute("aria-label") !== null; })[0] || found[0];
}
function click(node, checked) { if (checked !== undefined) { node.checked = checked; } node.dispatch(node.tagName === "INPUT" ? "change" : "click"); }
function button(v, label) {
    var b = v.root.find(function (n) { return n.tagName === "BUTTON" && n.textContent === label; });
    return b[0];
}

var tests = {
    "first load asks for the unfiltered catalogue once": function () {
        var v = open();
        assert.strictEqual(catalogCalls(v).length, 1);
        var p = lastParams(v);
        ["domain", "category", "criticality", "difficulty", "availability", "review", "quality", "regulation", "bookmarked"].forEach(function (k) {
            assert.ok(!(k in p), k);
        });
    },
    "several values per facet are sent comma separated": function () {
        var v = open();
        click(box(v, "domain", "security"), true);
        click(box(v, "domain", "infrastructure"), true);
        click(box(v, "criticality", "high"), true);
        click(box(v, "availability", "ready"), true);
        click(box(v, "availability", "not_assessed"), true);
        click(box(v, "category", "fenre_cat-9"), true);
        var p = lastParams(v);
        assert.strictEqual(p.domain, "security,infrastructure");
        assert.strictEqual(p.criticality, "high");
        assert.strictEqual(p.availability, "ready,not_assessed");
        assert.strictEqual(p.category, "fenre_cat-9");
        assert.strictEqual(p.offset, 0);
        click(box(v, "domain", "security"), false);
        assert.strictEqual(lastParams(v).domain, "infrastructure");
    },
    "filters survive in the URL and come back from it": function () {
        var v = open({}, { search: "?domain=security,cloud&availability=ready&bookmarked=1&q=brute" });
        var p = lastParams(v);
        assert.strictEqual(p.domain, "security,cloud");
        assert.strictEqual(p.availability, "ready");
        assert.strictEqual(p.bookmarked, "1");
        assert.strictEqual(p.q, "brute");
        assert.ok(box(v, "domain", "security").checked);
        assert.ok(/domain=security,cloud/.test(v.urls[v.urls.length - 1]), v.urls[v.urls.length - 1]);
    },
    "bookmark filter sends bookmarked=1 and never a user": function () {
        var v = open();
        var toggle = v.root.find(function (n) { return n.tagName === "INPUT" && n.getAttribute("name") === "bookmarked"; })[0];
        click(toggle, true);
        var p = lastParams(v);
        assert.strictEqual(p.bookmarked, "1");
        assert.ok(!("user" in p));
        click(toggle, false);
        assert.ok(!("bookmarked" in lastParams(v)));
    },
    "facet counts are the global ones and say so": function () {
        var v = open();
        var t = v.root.textContent;
        assert.ok(/security \(7\)/.test(t) && /ready\s?\(5\)/.test(t), t);
        assert.ok(/not assessed \(2\)/.test(t), "10 active - 8 assessed");
        assert.ok(/whole catalogue, not for the other filters/.test(t));
    },
    "categories are grouped under their first domain with counts": function () {
        var v = open();
        var groups = v.root.find(function (n) { return n.getAttribute("class") === "ucm-facet-group"; }).map(function (n) { return n.textContent; });
        assert.deepStrictEqual(groups, ["security (7)", "infrastructure (2)", "endpoint (1)"]);
        assert.ok(/9\. Authentication \(5\)/.test(v.root.textContent));
    },
    "active filters are listed and removable, clear all resets": function () {
        var v = open();
        click(box(v, "criticality", "high"), true);
        click(box(v, "regulation", "gdpr"), true);
        assert.ok(/criticality: high ×/.test(v.root.textContent) && /regulation: GDPR ×/.test(v.root.textContent));
        click(button(v, "regulation: GDPR ×"));
        assert.ok(!("regulation" in lastParams(v)));
        assert.strictEqual(lastParams(v).criticality, "high");
        assert.ok(!box(v, "regulation", "gdpr").checked);
        click(button(v, "Clear all filters"));
        assert.ok(!("criticality" in lastParams(v)));
        assert.ok(!box(v, "criticality", "high").checked);
    },
    "rows render safely and offer Bookmark/Select": function () {
        var v = open();
        assert.ok(v.root.textContent.indexOf("<img src=x onerror=1>") >= 0);
        assert.strictEqual(v.root.find(function (n) { return n.tagName === "IMG"; }).length, 0);
        assert.ok(button(v, "Bookmark") && button(v, "Select"));
        click(button(v, "Bookmark"));
        var post = v.calls.filter(function (c) { return c.method === "POST"; })[0];
        assert.deepStrictEqual(post.params, { id: "fenre:UC-9.1.1", intent: "bookmark" });
    },
    "a bookmarked row offers removal instead and a selected row cannot be overwritten by Bookmark": function () {
        var v = open({ selections: { items: [{ content_id: "fenre:UC-9.1.1", intent: "bookmark" }] } });
        assert.ok(button(v, "Remove bookmark") && !button(v, "Bookmark"));
        click(button(v, "Remove bookmark"));
        assert.strictEqual(v.calls.filter(function (c) { return c.method === "POST"; })[0].path, "selections/delete");
        var w = open({ selections: { items: [{ content_id: "fenre:UC-9.1.1", intent: "reject" }] } });
        assert.ok(!button(w, "Bookmark") && !button(w, "Remove bookmark"));
    },
    "empty states differ for bookmarks, filters and an empty catalogue": function () {
        var none = { catalog: { items: [], total: 0, offset: 0, count: 25, has_more: false } };
        assert.ok(/not bookmarked any use case/.test(open(none, { search: "?bookmarked=1" }).root.textContent));
        assert.ok(/No use cases match these filters/.test(open(none, { search: "?domain=cloud" }).root.textContent));
        assert.ok(/No content has been imported yet/.test(open(none).root.textContent));
    },
    "a failing readiness summary only removes the availability counts": function () {
        var v = open({ "readiness/summary": new Error("boom") });
        assert.ok(/availability/i.test(v.root.textContent));
        assert.ok(!/not assessed \(/.test(v.root.textContent));
        assert.strictEqual(catalogCalls(v).length, 1);
    },
    "old facets without the new fields still render": function () {
        var v = open({ "catalog/facets": { review_statuses: [], regulations: [], quality_flags: [] } });
        assert.strictEqual(catalogCalls(v).length, 1);
        assert.ok(/security \(0\)/.test(v.root.textContent));
    },
    "a failing catalogue request shows the error": function () {
        assert.ok(/boom/.test(open({ catalog: new Error("boom") }).root.textContent));
    }
};

var TWO = { providers: { fenre: 7, escu: 3 }, waves: { crawl: 4, walk: 2, run: 1 },
    analytic_stories: [{ id: "Brute Force", count: 2 }], data_sources: [{ id: "Sysmon EventID 1", count: 3 }],
    summary: { version: 6, outdated: 0 }, active: 10 };
var TWO_CATS = { categories: [
    { _key: "fenre_cat-9", category_id: "9", name: "Authentication", domains: ["security"], provider: "fenre" },
    { _key: "escu_cat-endpoint", category_id: "1", name: "Endpoint", domains: ["endpoint", "security"], provider: "escu" },
    { _key: "escu_cat-unassigned", category_id: "7", name: "Unassigned", domains: ["security"], provider: "escu" }] };
function two(extra) {
    return open({ categories: TWO_CATS, "catalog/facets": Object.assign({}, FACETS, TWO, extra || {}) });
}
function texts(v, cls) {
    return v.root.find(function (n) { return n.getAttribute("class") === cls; }).map(function (n) { return n.textContent; });
}

Object.assign(tests, {
    "provider, wave, story and data source filters are sent comma separated and restored from the URL": function () {
        var v = two();
        click(box(v, "provider", "escu"), true);
        click(box(v, "provider", "fenre"), true);
        click(box(v, "wave", "crawl"), true);
        click(box(v, "story", "Brute Force"), true);
        click(box(v, "data_source", "Sysmon EventID 1"), true);
        var p = lastParams(v);
        assert.strictEqual(p.provider, "escu,fenre");
        assert.strictEqual(p.wave, "crawl");
        assert.strictEqual(p.story, "Brute Force");
        assert.strictEqual(p.data_source, "Sysmon EventID 1");
        var url = v.urls[v.urls.length - 1];
        assert.ok(/provider=escu,fenre/.test(url) && /wave=crawl/.test(url), url);
        var w = two() && open({ categories: TWO_CATS, "catalog/facets": Object.assign({}, FACETS, TWO) },
            { search: "?provider=escu&wave=walk,run&exclude_quality=unreviewed" });
        var q = lastParams(w);
        assert.deepStrictEqual([q.provider, q.wave, q.exclude_quality], ["escu", "walk,run", "unreviewed"]);
        assert.ok(box(w, "provider", "escu").checked && box(w, "wave", "run").checked);
    },
    "provider facet lists the providers with their counts": function () {
        var t = two().root.textContent;
        assert.ok(/Fenre \(7\)/.test(t) && /ESCU \(3\)/.test(t), t);
        assert.ok(/crawl \(4\)/.test(t) && /walk \(2\)/.test(t));
        assert.ok(/Brute Force \(2\)/.test(t) && /Sysmon EventID 1 \(3\)/.test(t));
    },
    "categories name their provider only when both providers are present": function () {
        var both = two().root.textContent;
        assert.ok(/Fenre \u00b7 9\. Authentication/.test(both), both);
        assert.ok(/ESCU \u00b7 Endpoint/.test(both) && !/ESCU \u00b7 1\. Endpoint/.test(both), "ESCU ids are not shown as numbers");
        assert.ok(/ESCU \u00b7 Unassigned/.test(both));
        var one = open({ categories: TWO_CATS, "catalog/facets": Object.assign({}, FACETS, { providers: { escu: 3 } }) }).root.textContent;
        assert.ok(/Endpoint/.test(one) && !/ESCU \u00b7 Endpoint/.test(one));
    },
    "the category filter value stays the unchanged category id": function () {
        var v = two();
        click(box(v, "category", "escu_cat-unassigned"), true);
        assert.strictEqual(lastParams(v).category, "escu_cat-unassigned");
        assert.ok(/category: ESCU \u00b7 Unassigned/.test(v.root.textContent));
    },
    "rows carry a provider badge": function () {
        var v = open({ catalog: { items: [Object.assign({ provider: "escu" }, ITEMS[0])], total: 1, offset: 0, count: 25, has_more: false } });
        assert.deepStrictEqual(texts(v, "ucm-badge ucm-badge-provider"), ["ESCU"]);
    },
    "a long story list gets a find box that only hides rows": function () {
        var many = []; for (var i = 0; i < 20; i++) { many.push({ id: "Story " + i, count: i + 1 }); }
        var v = two({ analytic_stories: many });
        var finder = v.root.find(function (n) { return n.getAttribute("class") === "ucm-facet-find"; })[0];
        assert.ok(finder);
        finder.value = "story 1";
        finder.dispatch("input");
        var hidden = v.root.find(function (n) { return n.tagName === "LABEL" && n.getAttribute("hidden") !== null; });
        assert.ok(hidden.length > 0 && hidden.length < 20);
        assert.strictEqual(catalogCalls(v).length, 1, "finding does not query the server");
    },
    "hiding a quality flag is a separate filter and off by default": function () {
        var v = two({ quality_flags: [{ id: "ai_reviewed", count: 3 }] });
        assert.ok(!("exclude_quality" in lastParams(v)));
        var group = v.root.find(function (n) { return n.tagName === "DETAILS" && /^Hide quality flag/.test(n.textContent); })[0];
        var hide = group.find(function (n) { return n.tagName === "INPUT" && n.getAttribute("value") === "ai_reviewed"; })[0];
        click(hide, true);
        assert.strictEqual(lastParams(v).exclude_quality, "ai_reviewed");
        assert.ok(!("quality" in lastParams(v)));
        assert.ok(/hide quality flag: ai reviewed|exclude_quality|Hide quality flag/i.test(v.root.textContent));
    },
    "an old summary shows the Reindex hint and an empty wave filter explains itself": function () {
        var old = { summary: { version: 6, outdated: 8 } };
        var v = open({ categories: TWO_CATS, "catalog/facets": Object.assign({}, FACETS, TWO, old),
            catalog: { items: [], total: 0, offset: 0, count: 25, has_more: false } }, { search: "?wave=crawl" });
        var t = v.root.textContent;
        assert.ok(/Reindex needed/.test(t) && /8 of 10/.test(t), t);
        assert.ok(/cannot match this filter yet/.test(t));
        var fresh = open({ categories: TWO_CATS, "catalog/facets": Object.assign({}, FACETS, TWO),
            catalog: { items: [], total: 0, offset: 0, count: 25, has_more: false } }, { search: "?wave=crawl" });
        assert.ok(!/Reindex needed/.test(fresh.root.textContent) && /No use cases match/.test(fresh.root.textContent));
    },
    "a provider filter alone never claims a Reindex is needed for it": function () {
        var v = open({ categories: TWO_CATS, "catalog/facets": Object.assign({}, FACETS, TWO, { summary: { version: 6, outdated: 8 } }),
            catalog: { items: [], total: 0, offset: 0, count: 25, has_more: false } }, { search: "?provider=escu" });
        assert.ok(!/cannot match this filter yet/.test(v.root.textContent));
        assert.ok(/The provider filter and the other filters work/.test(v.root.textContent));
    }
});

var failed = 0;
Object.keys(tests).forEach(function (name) {
    try { tests[name](); console.log("ok   " + name); } catch (e) { failed++; console.log("FAIL " + name + ": " + (e.stack || e.message)); }
});
process.exit(failed ? 1 : 0);
