"use strict";
var assert = require("assert");
var runView = require("./fake_dom").runView;

function open(facets, verify) {
    return runView("ucm_content_admin.js", "ucm-admin", { sync: {}, categories: { categories: [] }, platform: new Error("x"),
        audit: { events: [] }, "catalog/facets": facets, "audit/verify": verify || new Error("not asked") });
}
function intact() {
    return { ok: true, rows: 10, chained: 8, legacy: 2, modified: [], modified_count: 0, missing_predecessor: [], missing_count: 0,
        restarts: [], restart_count: 0, branches: 1, head: "abc123", truncated: false };
}
function press(v, label) {
    v.root.find(function (n) { return n.tagName === "BUTTON" && n.textContent === label; })[0].dispatch("click");
}
function buttons(v) { return v.root.find(function (n) { return n.tagName === "BUTTON"; }).map(function (n) { return n.textContent; }); }

var tests = {
    "an old summary shows the Reindex hint next to the Reindex button": function () {
        var v = open({ active: 10, summary: { version: 6, outdated: 4 } });
        assert.ok(/Reindex needed/.test(v.root.textContent) && /4 of 10/.test(v.root.textContent));
        assert.ok(buttons(v).indexOf("Reindex catalogue summaries") >= 0);
    },
    "records from an older provider normalizer say a re-import is needed, and Reindex is not offered for them alone": function () {
        var v = open({ active: 10, summary: { version: 7, outdated: 0, normalizer_outdated: 6 } });
        var t = v.root.textContent;
        assert.ok(/earlier release/.test(t) && /6 records were written by an earlier version/.test(t) && /import the ESCU bundle again/.test(t), t);
        assert.ok(!/Reindex needed/.test(t));
    },
    "old summaries and old records are explained together": function () {
        var v = open({ active: 10, summary: { version: 7, outdated: 4, normalizer_outdated: 1 } });
        var t = v.root.textContent;
        assert.ok(/Reindex needed/.test(t) && /1 record was written by an earlier version/.test(t), t);
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
    "refused requests are listed with their code and the limits are explained": function () {
        var event = { time_iso: "2026-11-25T10:00:00Z", actor: "mallory", action: "refused.deployment.approve", object_id: "fenre:UC-1",
            outcome: "refused", details: { code: "permission_denied", message: "missing capability ucm_deploy" } };
        var v = runView("ucm_content_admin.js", "ucm-admin", { sync: {}, categories: { categories: [] }, platform: new Error("x"),
            audit: { events: [event] }, "catalog/facets": new Error("x"), "audit/verify": new Error("x") });
        var t = v.root.textContent;
        assert.ok(/Refused requests/.test(t) && /mallory/.test(t) && /deployment\.approve/.test(t) && /permission_denied/.test(t), t);
        assert.ok(/once per window/.test(t));
    },
    "no refused requests, no extra section": function () {
        assert.ok(!/Refused requests/.test(open({ active: 1, summary: { version: 6, outdated: 0 } }).root.textContent));
    },
    "verifying an intact chain says so, with the head and the rows it could not check": function () {
        var v = open({ active: 1, summary: { version: 6, outdated: 0 } }, intact());
        press(v, "Verify audit chain");
        var t = v.root.textContent;
        assert.ok(/The audit chain is intact/.test(t) && /8 of 10 rows are chained/.test(t) && /2 older rows from before the chain/.test(t), t);
        assert.ok(/Head abc123/.test(t) && /same moment as another/.test(t), t);
    },
    "a modified row and a missing predecessor are named": function () {
        var r = intact();
        r.ok = false; r.modified_count = 1; r.modified = [{ key: "k", time: "2026-11-25T10:00:00Z", action: "deployment.approve" }];
        r.missing_count = 1; r.missing_predecessor = [{ key: "j", time: "2026-11-25T11:00:00Z", action: "deployment.deploy" }];
        var v = open({ active: 1, summary: { version: 6, outdated: 0 } }, r);
        press(v, "Verify audit chain");
        var t = v.root.textContent;
        assert.ok(/The audit chain has problems/.test(t) && /changed after they were written: deployment.approve at 2026-11-25T10:00:00Z/.test(t), t);
        assert.ok(/follow a row that no longer exists: deployment.deploy/.test(t), t);
    },
    "a failed verification request is shown, not hidden": function () {
        var v = open({ active: 1, summary: { version: 6, outdated: 0 } });
        press(v, "Verify audit chain");
        assert.ok(/Could not verify the audit chain/.test(v.root.textContent));
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
