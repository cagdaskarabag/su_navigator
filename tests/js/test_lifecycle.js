"use strict";
var assert = require("assert");
var fs = require("fs");
var path = require("path");
var runView = require("./fake_dom").runView;

function fixture() {
    return JSON.parse(fs.readFileSync(path.join(__dirname, "..", "fixtures", "ui", "usecase_fenre_deployed.json"), "utf8"));
}

function deployed(actions, patch, settings) {
    var uc = fixture();
    var dep = uc.deployment.deployment;
    dep.state = "deployed";
    dep.deployed_revision = 2;
    dep.live = { status: "disabled", drift: [] };
    Object.assign(dep, patch || {});
    uc.deployment.allowed_actions = actions || ["draft", "enable", "retire", "outcome"];
    uc.deployment.scheduler_access = { status: "met", detail: "ok", revision: 2 };
    uc.deployment.settings = Object.assign({}, uc.deployment.settings, settings || {});
    return uc;
}

function open(uc) {
    return runView("ucm_usecase.js", "ucm-usecase", {
        usecase: uc, "POST deployment/outcome": uc.deployment, "POST deployment/withdraw": uc.deployment, "POST deployment/cancel_enable": uc.deployment,
        "POST deployment/enable": uc.deployment, "GET deployment/diff": function (p) { return DIFF; },
        "RAW services/authentication/current-context": { entry: [{ content: { capabilities: ["search"] } }] }
    }, { search: "?id=" + encodeURIComponent(uc.content_id), amd: { "splunkjs/mvc/searchmanager": function () {} } });
}

function buttons(v, label) {
    return v.root.find(function (n) { return n.tagName === "BUTTON" && n.textContent === label; });
}

function posts(v) { return v.calls.filter(function (c) { return c.method === "POST"; }); }

var DIFF = { available: true, from: { rev: 1, created_by: "alice" }, to: { rev: 2, created_by: "bob" },
    fields: [{ field: "cron", from: "*/5 * * * *", to: "0 * * * *" }, { field: "actions", from: {}, to: { email: { recipients: 1 } } }],
    spl: { changed: true, added: 1, removed: 1, truncated: false, lines: ["--- revision 1", "+++ revision 2", "-index=main", "+index=other"] } };

var tests = {
    "enable is labelled Request enable when a second person is required": function () {
        var v = open(deployed(null, null, { enable_second_person: true }));
        assert.strictEqual(buttons(v, "Request enable").length, 1);
        assert.strictEqual(buttons(v, "Enable").length, 0);
        buttons(v, "Request enable")[0].dispatch("click");
        assert.strictEqual(posts(v)[0].path, "deployment/enable");
    },
    "an open request names who asked and offers confirm and cancel": function () {
        var v = open(deployed(["draft", "enable", "cancel_enable", "retire"], { enable_request_active: true,
            enable_request: { by: "bob", at: "2026-11-25T10:00:00Z", revision: 2, expires_at: "2026-11-26T10:00:00Z" } }, { enable_second_person: true }));
        var t = v.root.textContent;
        assert.ok(/Waiting for a second person to confirm enabling/.test(t) && /bob asked to enable/.test(t), t);
        assert.strictEqual(buttons(v, "Confirm enable (asked by bob)").length, 1);
        assert.strictEqual(buttons(v, "Cancel enable request").length, 1);
    },
    "withdraw asks for a reason of at least five characters before sending": function () {
        var v = open(deployed(["draft", "withdraw", "deploy", "retire"], { state: "approved", deployed_revision: null }));
        var asked = null;
        v.ucm.askText = function (title, text, opts, label, cb) { asked = { title: title, text: text, opts: opts, cb: cb }; };
        buttons(v, "Withdraw approval")[0].dispatch("click");
        assert.ok(asked && /cannot be deployed until it is approved again/.test(asked.text) && asked.opts.minLength === 5);
        assert.strictEqual(posts(v).length, 0);
        asked.cb("wrong recipients");
        assert.deepStrictEqual(posts(v)[0].params, { id: "fenre:UC-9.1.1", note: "wrong recipients" });
        assert.strictEqual(posts(v)[0].path, "deployment/withdraw");
    },
    "an active override says who, why and until when": function () {
        var v = open(deployed(null, { override_status: { reason: "data arrives Monday", by: "bob", at: "x", expires_at: "2026-12-09T10:00:00Z",
            expired: false, blocked_by: ["readiness is blocked"] } }));
        var t = v.root.textContent;
        assert.ok(/Enabled with an override until 2026-12-09T10:00:00Z UTC/.test(t) && /data arrives Monday/.test(t) && /readiness is blocked/.test(t), t);
    },
    "an expired override is an error box": function () {
        var v = open(deployed(null, { override_status: { reason: "data arrives Monday", by: "bob", expires_at: "2020-01-01T00:00:00Z", expired: true, blocked_by: [] } }));
        assert.ok(/The override expired at 2020-01-01T00:00:00Z UTC/.test(v.root.textContent));
    },
    "the override prompt mentions the expiry from settings": function () {
        var uc = deployed(null, null, { override_days: 14, override_expiry_action: "disable", block_enable_states: ["blocked"] });
        uc.readiness = { state: "blocked" };
        var v = open(uc);
        var asked = null;
        v.ucm.askText = function (title, text, opts, label, cb) { asked = text; };
        buttons(v, "Enable")[0].dispatch("click");
        assert.ok(/expires after 14 days/.test(asked) && /the search is disabled/.test(asked), asked);
    },
    "the outcome form posts the choice and the note": function () {
        var v = open(deployed());
        assert.ok(/Outcome after deployment/.test(v.root.textContent) && /No outcome recorded/.test(v.root.textContent));
        var select = v.root.find(function (n) { return n.getAttribute("id") === "ucm-outcome-value"; })[0];
        var note = v.root.find(function (n) { return n.getAttribute("id") === "ucm-outcome-note"; })[0];
        select.value = "waiting_on_data";
        note.value = "no sysmon yet";
        v.root.find(function (n) { return n.getAttribute("id") === "ucm-outcome-save"; })[0].dispatch("click");
        assert.deepStrictEqual(posts(v)[0].params, { id: "fenre:UC-9.1.1", outcome: "waiting_on_data", note: "no sysmon yet" });
    },
    "a recorded outcome shows for a viewer without a form": function () {
        var v = open(deployed(["draft"], { outcome: { value: "needs_tuning", note: "fires on every admin login", set_by: "bob", set_at: "2026-11-25T10:00:00Z" } }));
        var t = v.root.textContent;
        assert.ok(/Needs tuning/.test(t) && /fires on every admin login/.test(t) && /bob/.test(t), t);
        assert.strictEqual(v.root.find(function (n) { return n.getAttribute("id") === "ucm-outcome-save"; }).length, 0);
    },
    "a deployment without an outcome and without permission shows no outcome section": function () {
        assert.ok(!/Outcome after deployment/.test(open(deployed(["draft"])).root.textContent));
    },
    "compare revisions shows changed settings and the SPL diff": function () {
        var v = open(deployed());
        assert.ok(/Compare revisions/.test(v.root.textContent));
        v.root.find(function (n) { return n.getAttribute("id") === "ucm-diff-from"; })[0].value = "1";
        v.root.find(function (n) { return n.getAttribute("id") === "ucm-diff-to"; })[0].value = "2";
        v.root.find(function (n) { return n.getAttribute("id") === "ucm-diff-go"; })[0].dispatch("click");
        var t = v.root.textContent;
        assert.ok(/Revision 1 \(alice\) to revision 2 \(bob\)/.test(t) && /cron/.test(t) && /0 \* \* \* \*/.test(t), t);
        assert.ok(/1 line\(s\) added, 1 removed/.test(t) && /\+index=other/.test(t), t);
        var call = v.calls.filter(function (c) { return c.path === "deployment/diff"; })[0];
        assert.deepStrictEqual([call.params.from, call.params.to], ["1", "2"]);
    },
    "trimmed revisions are listed by hash": function () {
        var v = open(deployed(null, { revision_log: [{ rev: 1, spl_hash: "abcdef0123456789", approved_by: "carol" }] }));
        assert.ok(/1 older revision\(s\) were trimmed/.test(v.root.textContent) && /abcdef01/.test(v.root.textContent) && /approved by carol/.test(v.root.textContent));
    },
    "a diff that cannot be built says what remains": function () {
        var v = open(deployed());
        DIFF = { available: false, reason: "A revision was trimmed after max_revisions was reached; only its hash and record remain.", revisions: [{ rev: 1, spl_hash: "abcdef0123456789" }, { rev: 2 }] };
        v.root.find(function (n) { return n.getAttribute("id") === "ucm-diff-go"; })[0].dispatch("click");
        assert.ok(/Cannot compare these revisions/.test(v.root.textContent) && /hash abcdef012345/.test(v.root.textContent));
    }
};

var PIPE = { draft: 1, pending_approval: 2, approved: 0, deployed: 3, enabled: 4, needs_tuning: 2, waiting_on_data: 1, override_expired: 1,
    override_active: 2, enable_requested: 0, failed: 0, rejected: 0, drifted: 1 };

function deploymentsPage(items) {
    return runView("ucm_deployments.js", "ucm-deployments", {
        deployments: function (q) { return { items: items || [], has_more: false, summary: { total: 10, by_state: {}, by_live: {}, drifted: 1, pipeline: PIPE } }; },
        operations: { available: false, items: [] }
    }, { search: "" });
}

tests["the deployments page shows the pipeline and what needs attention"] = function () {
    var t = deploymentsPage().root.textContent;
    assert.ok(/Pipeline/.test(t) && /Needs attention/.test(t), t);
    assert.ok(/Pending approval2/.test(t) && /Enabled4/.test(t) && /Needs tuning2/.test(t) && /Waiting on data1/.test(t) && /Override expired1/.test(t), t);
};

tests["choosing a stage filters the list by outcome or override"] = function () {
    var v = deploymentsPage();
    var card = v.root.find(function (n) { return /ucm-card-link/.test(n.getAttribute("class") || "") && /Needs tuning/.test(n.textContent); })[0];
    card.dispatch("click");
    var last = v.calls.filter(function (c) { return c.path === "deployments"; }).pop();
    assert.strictEqual(last.params.outcome, "needs_tuning");
    var expired = v.root.find(function (n) { return /ucm-card-link/.test(n.getAttribute("class") || "") && /Override expired/.test(n.textContent); })[0];
    expired.dispatch("click");
    last = v.calls.filter(function (c) { return c.path === "deployments"; }).pop();
    assert.strictEqual(last.params.override, "1");
    assert.strictEqual(last.params.outcome, undefined);
};

tests["rows carry outcome, override and request badges"] = function () {
    var row = { content_id: "fenre:UC-1", title: "T", state: "deployed", saved_search: { name: "SUN - 1" }, live: { status: "enabled", drift: [] },
        revision: 2, deployed_revision: 2, outcome: { value: "needs_tuning" }, override_status: { expired: true }, enable_request_active: true };
    var t = deploymentsPage([row]).root.textContent;
    assert.ok(/needs tuning/.test(t) && /override expired/.test(t) && /enable requested/.test(t), t);
};

var failed = 0;
Object.keys(tests).forEach(function (name) {
    try { tests[name](); console.log("ok   " + name); } catch (e) { failed++; console.log("FAIL " + name + ": " + (e.stack || e.message).split("\n").slice(0, 5).join("\n")); }
});
process.exit(failed ? 1 : 0);
