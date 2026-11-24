"use strict";
var assert = require("assert");
var fs = require("fs");
var path = require("path");
var fake = require("./fake_dom");
var runView = fake.runView;
var ucm = fake.loadAmd("ucm_common.js");

function fixture(name) {
    return JSON.parse(fs.readFileSync(path.join(__dirname, "..", "fixtures", "ui", "usecase_" + name + ".json"), "utf8"));
}

var NOT_MET = { status: "not_met", code: "index_not_accessible", revision: 1,
    detail: "ucm_scheduler cannot search _internal (_internal: no allowed pattern matches it ('*' does not include internal indexes; '_*' does); roles: ucm_scheduler). " +
        "A scheduled run would return no events from them and still report success." };

function deployed(access, actions) {
    var uc = fixture("fenre_deployed");
    var dep = uc.deployment.deployment;
    dep.state = "deployed";
    dep.deployed_revision = 1;
    dep.live = { status: "disabled", drift: [] };
    uc.deployment.allowed_actions = actions || ["draft", "enable", "retire"];
    uc.deployment.scheduler_access = access;
    return uc;
}

function open(uc) {
    return runView("ucm_usecase.js", "ucm-usecase", {
        usecase: uc, "POST deployment/enable": uc.deployment,
        "RAW services/authentication/current-context": { entry: [{ content: { capabilities: ["search"] } }] }
    }, { search: "?id=" + encodeURIComponent(uc.content_id), amd: { "splunkjs/mvc/searchmanager": function () {} } });
}

function button(v, label) {
    var b = v.root.find(function (n) { return n.tagName === "BUTTON" && n.textContent === label; });
    assert.strictEqual(b.length, 1, "button " + label + " x" + b.length);
    return b[0];
}

function view(extra) {
    return Object.assign({ owner: "ucm_scheduler", status: "ok", reason: "", roles: ["ucm_scheduler"], internal_access: false,
        all_indexes_access: true, has_filter: false, has_disallowed: false, default_indexes: 1, unreadable_roles: [],
        discovery_include_internal: false }, extra || {});
}

var tests = {
    "scheduler card shows owner, roles and internal-index access": function () {
        var t = ucm.schedulerCard(view()).textContent;
        assert.ok(/Scheduler account/.test(t) && /ucm_scheduler/.test(t), t);
        assert.ok(/Roles founducm_scheduler/.test(t), t);
        assert.ok(/Can search internal indexes \(_internal, _audit\)no/.test(t), t);
        assert.ok(/still report success/.test(t) && /\* does not include internal indexes/.test(t), t);
        assert.ok(/Discovery scans internal indexesno/.test(t), t);
        assert.ok(/include_internal = false/.test(t), t);
    },
    "scheduler card with internal access says yes and omits the warning": function () {
        var t = ucm.schedulerCard(view({ internal_access: true, discovery_include_internal: true })).textContent;
        assert.ok(/internal indexes \(_internal, _audit\)yes/.test(t), t);
        assert.ok(!/still report success/.test(t) && !/include_internal = false/.test(t), t);
    },
    "scheduler card reports a missing owner without claiming access": function () {
        var t = ucm.schedulerCard(view({ status: "no_owner", owner: "", internal_access: null, roles: [] })).textContent;
        assert.ok(/No scheduled owner is configured/.test(t) && /Owner configurednot configured/.test(t), t);
        assert.ok(!/Roles found/.test(t) && !/Can search internal/.test(t), t);
    },
    "scheduler card says not verified when roles cannot be read": function () {
        var t = ucm.schedulerCard(view({ status: "unreadable", reason: "splunkd refused to read the user (HTTP 403)", internal_access: null })).textContent;
        assert.ok(/could not be read/.test(t) && /HTTP 403/.test(t) && /not verified/.test(t) && /does not block deployment/.test(t), t);
        assert.ok(!/Can search internal/.test(t), t);
    },
    "scheduler card notes a filter and disallowed indexes": function () {
        var t = ucm.schedulerCard(view({ has_filter: true, has_disallowed: true })).textContent;
        assert.ok(/srchFilter/.test(t) && /srchIndexesDisallowed/.test(t), t);
    },
    "scheduler card tolerates a missing summary": function () {
        assert.ok(/Not available/.test(ucm.schedulerCard(null).textContent));
    },
    "overview renders the card from the readiness summary without another request": function () {
        var v = runView("ucm_overview.js", "ucm-overview-kpis", {
            catalog: { total: 10, items: [] },
            "readiness/summary": { by_state: { ready: 5 }, scheduler: view() },
            deployments: { items: [], summary: { total: 0, by_state: {}, by_live: {} } } });
        assert.ok(/Scheduler account/.test(v.root.textContent));
        assert.deepStrictEqual(v.calls.map(function (c) { return c.path; }).sort(), ["catalog", "deployments", "readiness/summary"]);
    },
    "overview without a scheduler block shows no card": function () {
        var v = runView("ucm_overview.js", "ucm-overview-kpis", {
            catalog: { total: 10, items: [] }, "readiness/summary": { by_state: { ready: 5 } }, deployments: new Error("x") });
        assert.ok(!/Scheduler account/.test(v.root.textContent));
    },
    "access badge and box by status": function () {
        assert.strictEqual(ucm.accessBadge(null), null);
        assert.ok(/not met/.test(ucm.accessBadge(NOT_MET).textContent));
        assert.ok(/not verified/.test(ucm.accessBadge({ status: "unverified", detail: "x" }).textContent));
        assert.strictEqual(ucm.accessBox({ status: "met", detail: "ok" }), null);
        assert.strictEqual(ucm.accessBox({ status: "not_applicable", detail: "ok" }), null);
        assert.ok(/may not see this search's data/.test(ucm.accessBox(NOT_MET).textContent));
        assert.ok(/override reason/.test(ucm.accessBox(NOT_MET).textContent));
        var info = ucm.accessBox({ status: "unverified", detail: "uses a data model" });
        assert.ok(/not verified/.test(info.textContent) && !/override/.test(info.textContent));
    },
    "deployment card warns when the scheduler cannot see the data": function () {
        var v = open(deployed(NOT_MET));
        var t = v.root.textContent;
        assert.ok(/scheduler access: not met/.test(t), t);
        assert.ok(/The scheduler account may not see this search's data/.test(t), t);
        assert.ok(/ucm_scheduler cannot search _internal/.test(t), t);
    },
    "met access shows a badge and no warning": function () {
        var v = open(deployed({ status: "met", detail: "ucm_scheduler can search main.", revision: 1 }));
        var t = v.root.textContent;
        assert.ok(/scheduler access: met/.test(t) && !/may not see this search's data/.test(t), t);
    },
    "enable asks for an override reason when access is not met": function () {
        var v = open(deployed(NOT_MET));
        var asked = null;
        v.ucm.askText = function (title, text, opts, label, cb) { asked = { title: title, text: text, opts: opts, cb: cb }; };
        button(v, "Enable").dispatch("click");
        assert.ok(asked, "override dialog");
        assert.ok(/cannot search _internal/.test(asked.text) && /audited/.test(asked.text), asked.text);
        assert.strictEqual(asked.opts.minLength, 10);
        assert.strictEqual(v.calls.filter(function (c) { return c.method === "POST"; }).length, 0, "nothing is sent before the reason");
        asked.cb("Accepted: the role is changed on Friday");
        var post = v.calls.filter(function (c) { return c.method === "POST"; })[0];
        assert.strictEqual(post.path, "deployment/enable");
        assert.strictEqual(post.params.override_reason, "Accepted: the role is changed on Friday");
    },
    "enable goes straight through when access is met or unverified": function () {
        ["met", "unverified"].forEach(function (status) {
            var v = open(deployed({ status: status, detail: "x", revision: 1 }));
            var asked = false;
            v.ucm.askText = function () { asked = true; };
            button(v, "Enable").dispatch("click");
            assert.ok(!asked, status);
            var post = v.calls.filter(function (c) { return c.method === "POST"; })[0];
            assert.strictEqual(post.path, "deployment/enable");
            assert.strictEqual(post.params.override_reason, undefined);
        });
    },
    "inventory page explains the include internal setting": function () {
        var src = fs.readFileSync(path.join(__dirname, "..", "..", "sunavigator", "appserver", "static", "ucm_inventory.js"), "utf8");
        assert.ok(/include_internal = false/.test(src) && /not verified, never as present or missing/.test(src));
    },
    "coverage wording says ran without error and not a statement about data": function () {
        var src = fs.readFileSync(path.join(__dirname, "..", "..", "sunavigator", "appserver", "static", "ucm_coverage.js"), "utf8");
        assert.ok(/Ran without error \(not a statement about data\)/.test(src));
        assert.ok(!/Running successfully|running successfully/.test(src));
    }
};

var failed = 0;
Object.keys(tests).forEach(function (name) {
    try { tests[name](); console.log("ok   " + name); } catch (e) { failed++; console.log("FAIL " + name + ": " + (e.stack || e.message).split("\n").slice(0, 4).join("\n")); }
});
process.exit(failed ? 1 : 0);
