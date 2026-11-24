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

var MATCH = { rule: "L001", name: "eval_function_in_search_clause", severity: "warning", segment: 1, command: "search", in_map: 0,
    count: 2, call: "match(_raw, \"<b>x</b>\")", message: "match(...) is used as a search term. The search command does not evaluate eval functions.",
    suggestion: "Test it after the search: | where match(_raw, \"<b>x</b>\")", search: "primary" };
var TIMECHART = { rule: "L002", name: "timechart_multiple_by_fields", severity: "warning", segment: 3, command: "timechart", in_map: 1,
    count: 1, call: "by a, b", message: "timechart accepts one split-by field.", suggestion: "Use stats.", search: "cim" };

function dismissButtons(node) {
    return node.find(function (n) { return n.tagName === "BUTTON" && n.textContent === "Dismiss"; });
}

function open(uc) {
    return runView("ucm_usecase.js", "ucm-usecase", {
        usecase: uc, "RAW services/authentication/current-context": { entry: [{ content: { capabilities: ["search"] } }] }
    }, { search: "?id=" + encodeURIComponent(uc.content_id), amd: { "splunkjs/mvc/searchmanager": function () {} } });
}

var tests = {
    "no findings render nothing": function () {
        assert.strictEqual(ucm.lintBox([]), null);
        assert.strictEqual(ucm.lintBox(undefined), null);
        assert.strictEqual(ucm.lintBox([{ rule: "L001" }]), null);
    },
    "a finding shows rule, message, location, call and rewrite as text": function () {
        var box = ucm.lintBox([MATCH, TIMECHART]);
        var t = box.textContent;
        assert.ok(/SPL lint \(advisory\): 2 findings/.test(t), t);
        assert.ok(/L001/.test(t) && /L002/.test(t), t);
        assert.ok(/segment 1 \(search\), 2 times/.test(t), t);
        assert.ok(/segment 3 \(timechart\), inside a map search, CIM search/.test(t), t);
        assert.ok(t.indexOf('match(_raw, "<b>x</b>")') >= 0, "the call is shown as text, not parsed");
        assert.ok(/Suggested rewrite: Test it after the search/.test(t), t);
        assert.ok(/do not change readiness, approval or deployment/.test(t), t);
    },
    "dismissing hides one finding and then the box, and stores nothing": function () {
        var holder = new fake.FakeElement("div");
        var box = ucm.lintBox([MATCH, TIMECHART]);
        holder.appendChild(box);
        var buttons = dismissButtons(box);
        assert.strictEqual(buttons.length, 2);
        buttons[0].dispatch("click");
        assert.ok(!/L001/.test(box.textContent) && /L002/.test(box.textContent));
        dismissButtons(box)[0].dispatch("click");
        assert.strictEqual(box.parentNode, null, "the empty box is removed");
        assert.strictEqual(holder.childNodes.length, 0);
    },
    "validation panel lists the stored findings": function () {
        var uc = fixture("fenre_plain");
        uc.validation = { parse_ok: true, commands: ["search"], lint: [MATCH], warnings: [], side_effects: [], review_commands: [] };
        var v = open(uc);
        assert.ok(/SPL lint \(advisory\): 1 finding/.test(v.root.textContent));
        assert.ok(/L001/.test(v.root.textContent));
        assert.ok(!/SPL lint has not run/.test(v.root.textContent));
        assert.strictEqual(dismissButtons(v.root).length, 1);
    },
    "validation panel with an empty list shows no lint box and no hint": function () {
        var uc = fixture("fenre_plain");
        uc.validation = { parse_ok: true, commands: ["search"], lint: [], warnings: [], side_effects: [], review_commands: [] };
        var t = open(uc).root.textContent;
        assert.ok(!/SPL lint/.test(t));
    },
    "a validation stored before 0.8.9 says lint has not run": function () {
        var uc = fixture("fenre_plain");
        uc.validation = { parse_ok: true, commands: ["search"], warnings: [], side_effects: [], review_commands: [] };
        var t = open(uc).root.textContent;
        assert.ok(/SPL lint has not run for this validation/.test(t), t);
        var none = fixture("fenre_plain");
        none.validation = null;
        assert.ok(!/SPL lint has not run/.test(open(none).root.textContent));
    },
    "deployment card shows the revision's findings as a non-blocking note": function () {
        var uc = fixture("fenre_deployed");
        var dep = uc.deployment.deployment;
        dep.state = "draft";
        dep.revisions[dep.revisions.length - 1].lint = [MATCH];
        uc.deployment.allowed_actions = ["draft", "submit"];
        var v = open(uc);
        var t = v.root.textContent;
        assert.ok(/SPL lint \(advisory\): 1 finding/.test(t) && /submitting is not blocked/.test(t), t);
        var submit = v.root.find(function (n) { return n.tagName === "BUTTON" && n.textContent === "Submit for approval"; });
        assert.strictEqual(submit.length, 1);
        assert.strictEqual(submit[0].disabled, false);
    },
    "deployment revision without findings or from before 0.8.9 shows no note": function () {
        var uc = fixture("fenre_deployed");
        var t = open(uc).root.textContent;
        assert.ok(!/submitting is not blocked/.test(t));
    },
    "row bound note appears only near the bound": function () {
        assert.strictEqual(ucm.rowBoundNote(19000, 50000), null);
        assert.strictEqual(ucm.rowBoundNote(44999, 50000), null);
        assert.ok(/close to the KV Store row bound/.test(ucm.rowBoundNote(45000, 50000).textContent));
        var reached = ucm.rowBoundNote(50000, 50000).textContent;
        assert.ok(/reached the KV Store row bound/.test(reached) && /max_rows_per_query/.test(reached) && /kv_row_limit/.test(reached), reached);
        assert.ok(ucm.rowBoundNote(450, 500) !== null, "uses the configured limit");
        assert.ok(ucm.rowBoundNote(45000) !== null, "defaults to 50000");
    },
    "catalogue marks a capped total as a lower bound": function () {
        var routes = { categories: { categories: [] }, "catalog/facets": { review_statuses: [], regulations: [], quality_flags: [], domains: {},
            categories: {}, criticality: {}, difficulty: {}, active: 0, computed_at: "t" },
            "readiness/summary": { total: 0, by_state: {} }, selections: { items: [] },
            catalog: { items: [{ _key: "fenre_UC-9.1.1", content_id: "fenre:UC-9.1.1", record_id: "9.1.1", title: "t", summary: "s",
                domains: ["security"], criticality: "high", difficulty: "beginner", sourcetypes: [], mitre_ids: [], review_status: "verified" }],
                total: 50000, total_capped: true, offset: 0, count: 25, has_more: true } };
        var t = runView("ucm_catalogue.js", "ucm-catalogue", routes).root.textContent;
        assert.ok(/50000 or more use cases/.test(t) && /This total is a lower bound/.test(t), t);
        routes.catalog.total_capped = false;
        routes.catalog.total = 1;
        var plain = runView("ucm_catalogue.js", "ucm-catalogue", routes).root.textContent;
        assert.ok(/1 use cases/.test(plain) && !/lower bound/.test(plain), plain);
    }
};

var failed = 0;
Object.keys(tests).forEach(function (name) {
    try { tests[name](); console.log("ok   " + name); } catch (e) { failed++; console.log("FAIL " + name + ": " + (e.stack || e.message).split("\n").slice(0, 4).join("\n")); }
});
process.exit(failed ? 1 : 0);
