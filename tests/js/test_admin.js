"use strict";
var assert = require("assert");
var runView = require("./fake_dom").runView;

function open(facets) {
    return runView("ucm_content_admin.js", "ucm-admin", { sync: {}, categories: { categories: [] }, platform: new Error("x"),
        audit: { events: [] }, "catalog/facets": facets });
}
function buttons(v) { return v.root.find(function (n) { return n.tagName === "BUTTON"; }).map(function (n) { return n.textContent; }); }

var tests = {
    "an old summary shows the Reindex hint next to the Reindex button": function () {
        var v = open({ active: 10, summary: { version: 6, outdated: 4 } });
        assert.ok(/Reindex needed/.test(v.root.textContent) && /4 of 10/.test(v.root.textContent));
        assert.ok(buttons(v).indexOf("Reindex catalogue summaries") >= 0);
    },
    "a current summary says so and offers no warning": function () {
        var v = open({ active: 10, summary: { version: 6, outdated: 0 } });
        assert.ok(!/Reindex needed/.test(v.root.textContent));
        assert.ok(/summaries are current \(version 6\)/.test(v.root.textContent));
    },
    "a failing facets request leaves the page working": function () {
        var v = open(new Error("down"));
        assert.ok(!/Reindex needed/.test(v.root.textContent));
        assert.ok(buttons(v).indexOf("Reindex catalogue summaries") >= 0);
    },
    "nothing is posted when the page opens": function () {
        assert.strictEqual(open({ active: 1, summary: { version: 6, outdated: 1 } }).calls.filter(function (c) { return c.method === "POST"; }).length, 0);
    }
};

var failed = 0;
Object.keys(tests).forEach(function (name) {
    try { tests[name](); console.log("ok   " + name); } catch (e) { failed++; console.log("FAIL " + name + ": " + (e.stack || e.message)); }
});
process.exit(failed ? 1 : 0);
