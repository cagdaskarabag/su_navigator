"use strict";
var assert = require("assert");
var ucm = require("./fake_dom").loadAmd("ucm_common.js");

var tests = {
    "the first error of a failed job is shown prominently": function () {
        var box = ucm.jobFailureBox([{ status: "failed", requested_at: "2026-11-24T10:00:00Z", requested_by: "admin",
            errors: [{ code: "invalid_request", message: "commit 0123abc is not reachable from the allowed branch" }] },
            { status: "succeeded" }]);
        assert.ok(/ucm-state-error/.test(box.getAttribute("class")));
        assert.ok(/The latest synchronization failed \(invalid_request\)/.test(box.textContent));
        assert.ok(/commit 0123abc is not reachable/.test(box.textContent));
        assert.ok(/Requested 2026-11-24T10:00:00Z by admin/.test(box.textContent));
    },
    "no box when the latest job did not fail, even if an older one did": function () {
        assert.strictEqual(ucm.jobFailureBox([{ status: "succeeded" }, { status: "failed", errors: [{ message: "x" }] }]), null);
        assert.strictEqual(ucm.jobFailureBox([]), null);
        assert.strictEqual(ucm.jobFailureBox(undefined), null);
    },
    "a failed job without a message still says it failed": function () {
        var box = ucm.jobFailureBox([{ status: "failed" }]);
        assert.ok(/No error message was recorded/.test(box.textContent));
    },
    "job errors list the job's own first and then failed categories": function () {
        var out = ucm.jobErrors({ errors: [{ message: "own" }], results: [{ status: "failed", category_id: "c1", errors: [{ message: "bad" }] },
            { status: "ok", category_id: "c2", errors: [] }, { status: "failed", category_id: "c3" }] });
        assert.deepStrictEqual(out, ["own", "category c1: bad", "category c3: failed"]);
        assert.deepStrictEqual(ucm.jobErrors({}), []);
    }
};

var failed = 0;
Object.keys(tests).forEach(function (name) {
    try { tests[name](); console.log("ok   " + name); } catch (e) { failed++; console.log("FAIL " + name + ": " + (e.stack || e.message).split("\n").slice(0, 4).join("\n")); }
});
process.exit(failed ? 1 : 0);
