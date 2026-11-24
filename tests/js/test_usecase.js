"use strict";
var assert = require("assert");
var fs = require("fs");
var path = require("path");
var runView = require("./fake_dom").runView;

function fixture(name) {
    return JSON.parse(fs.readFileSync(path.join(__dirname, "..", "fixtures", "ui", "usecase_" + name + ".json"), "utf8"));
}

function FakeSearchManager(settings, options) {
    FakeSearchManager.instances.push(this);
    this.settings = settings; this.options = options; this.handlers = {}; this.started = false; this.cancelled = false; this.disposed = false;
}
FakeSearchManager.instances = [];
FakeSearchManager.prototype.on = function (ev, f) { this.handlers[ev] = f; };
FakeSearchManager.prototype.startSearch = function () { this.started = true; };
FakeSearchManager.prototype.cancel = function () { this.cancelled = true; };
FakeSearchManager.prototype.dispose = function () { this.disposed = true; };
FakeSearchManager.prototype.data = function (kind, params) {
    var self = this;
    this.dataArgs = [kind, params];
    this.results = { handlers: {}, payload: { fields: [], rows: [] },
        on: function (ev, f) { this.handlers[ev] = f; }, data: function () { return this.payload; } };
    return this.results;
};

var SEARCH_CAP = { entry: [{ content: { capabilities: ["search", "rest_properties_get"] } }] };
var NO_SEARCH_CAP = { entry: [{ content: { capabilities: ["rest_properties_get"] } }] };

function open(uc, extra) {
    FakeSearchManager.instances.length = 0;
    var routes = { usecase: uc, "RAW services/authentication/current-context": SEARCH_CAP };
    Object.assign(routes, extra || {});
    return runView("ucm_usecase.js", "ucm-usecase", routes,
        { search: "?id=" + encodeURIComponent(uc.content_id), amd: { "splunkjs/mvc/searchmanager": FakeSearchManager } });
}
function button(v, label) {
    var b = v.root.find(function (n) { return n.tagName === "BUTTON" && n.textContent === label; });
    assert.strictEqual(b.length, 1, "button " + label + " x" + b.length);
    return b[0];
}
function hasText(v, re) { return re.test(v.root.textContent); }

var tests = {
    "plain use case: run is enabled but nothing runs on load": function () {
        var v = open(fixture("fenre_plain"));
        assert.strictEqual(button(v, "Run search").disabled, false);
        assert.strictEqual(FakeSearchManager.instances.length, 0, "no search before the click");
        assert.ok(hasText(v, /runs as you, outside SUNavigator's guard rails/));
        assert.ok(hasText(v, /not subject to the bounded preview/));
        assert.ok(hasText(v, /cannot audit it/));
    },
    "time range defaults to last 24 hours and is always bounded": function () {
        var v = open(fixture("fenre_plain"));
        var sel = v.root.find(function (n) { return n.tagName === "SELECT" && n.getAttribute("aria-label") === "Time range"; })[0];
        assert.strictEqual(sel.value, "-24h");
        var values = sel.childNodes.map(function (o) { return o.getAttribute("value"); });
        assert.deepStrictEqual(values, ["-15m", "-1h", "-4h", "-24h", "-7d"]);
        assert.ok(values.indexOf("") < 0 && values.indexOf("0") < 0 && values.indexOf("rt") < 0);
    },
    "macros without a matching parse disable the button with a reason": function () {
        var v = open(fixture("escu_macros"));
        var b = button(v, "Run search");
        assert.strictEqual(b.disabled, true);
        assert.ok(/macros/.test(b.getAttribute("title")));
        assert.ok(hasText(v, /Run search is disabled/));
        b.dispatch("click");
        assert.strictEqual(FakeSearchManager.instances.length, 0);
    },
    "macros with a current clean parse are allowed": function () {
        var uc = fixture("escu_macros");
        uc.validation = { source_hash: uc.provenance.source_hash, parse_ok: true, side_effects: [], indirect_commands: [], unknown_commands: [] };
        var v = open(uc);
        assert.strictEqual(button(v, "Run search").disabled, false);
    },
    "a parse of older content does not count": function () {
        var uc = fixture("escu_macros");
        uc.validation = { source_hash: "0".repeat(64), parse_ok: true, side_effects: [] };
        assert.strictEqual(button(open(uc), "Run search").disabled, true);
    },
    "side-effect commands are refused and clicking does nothing": function () {
        var uc = fixture("fenre_plain");
        uc.spl = "index=main | stats count by host | outputlookup hosts.csv";
        var v = open(uc);
        var b = button(v, "Run search");
        assert.strictEqual(b.disabled, true);
        assert.ok(/outputlookup/.test(b.getAttribute("title")));
        b.dispatch("click");
        assert.strictEqual(FakeSearchManager.instances.length, 0);
    },
    "side effects inside a map search are refused": function () {
        ["collect index=s", "outputlookup x.csv", "sendemail to=a@b.c", "delete"].forEach(function (cmd) {
            var uc = fixture("fenre_plain");
            uc.spl = 'index=a | map search="search index=b | ' + cmd + '"';
            var v = open(uc);
            var b = button(v, "Run search");
            assert.strictEqual(b.disabled, true, cmd);
            assert.ok(new RegExp(cmd.split(" ")[0]).test(b.getAttribute("title")), cmd);
            assert.ok(/inside a map search/.test(b.getAttribute("title")));
            b.dispatch("click");
            assert.strictEqual(FakeSearchManager.instances.length, 0);
        });
    },
    "a map search without side effects only warns": function () {
        var uc = fixture("fenre_plain");
        uc.spl = 'index=a | head 3 | map search="search index=b host=$host$ | head 1" maxsearches=3';
        var v = open(uc);
        assert.strictEqual(button(v, "Run search").disabled, false);
        assert.ok(hasText(v, /run other searches or reach data/));
    },
    "commands that hide their SPL are refused": function () {
        ['| savedsearch "Errors"', '| loadjob savedsearch="admin:search:x"', '| dbxquery connection=c query="select 1"',
            "| from savedsearch:Errors", 'index=a | map savedsearch="x"', "index=a | map search=x",
            'index=a | map search="search `wrapper` | head 1"', 'index=a | map search="| savedsearch Errors"'].forEach(function (spl) {
            var uc = fixture("fenre_plain");
            uc.spl = spl;
            var v = open(uc);
            var b = button(v, "Run search");
            assert.strictEqual(b.disabled, true, spl);
            assert.ok(/does not show/.test(b.getAttribute("title")), spl);
            b.dispatch("click");
            assert.strictEqual(FakeSearchManager.instances.length, 0, spl);
        });
    },
    "a stored parse that found savedsearch refuses even when the text is clean": function () {
        var uc = fixture("escu_macros");
        uc.validation = { source_hash: uc.provenance.source_hash, parse_ok: true, side_effects: [], indirect_commands: ["savedsearch"] };
        var v = open(uc);
        var b = button(v, "Run search");
        assert.strictEqual(b.disabled, true);
        assert.ok(/savedsearch/.test(b.getAttribute("title")));
    },
    "the interactive search can be switched off by the administrator": function () {
        var uc = fixture("fenre_plain");
        uc.interactive_search = { enabled: false };
        var v = open(uc);
        assert.strictEqual(v.root.find(function (n) { return n.tagName === "BUTTON" && n.textContent === "Run search"; }).length, 0);
        assert.ok(hasText(v, /turned the interactive search off/));
        assert.strictEqual(FakeSearchManager.instances.length, 0);
    },
    "the search stays on when the server sends no setting": function () {
        var uc = fixture("fenre_plain");
        delete uc.interactive_search;
        assert.strictEqual(button(open(uc), "Run search").disabled, false);
    },
    "side effects found by the stored parse also refuse": function () {
        var uc = fixture("escu_macros");
        uc.validation = { source_hash: uc.provenance.source_hash, parse_ok: true, side_effects: ["collect"] };
        var v = open(uc);
        var b = button(v, "Run search");
        assert.strictEqual(b.disabled, true);
        assert.ok(/collect/.test(b.getAttribute("title")));
    },
    "a role without the search capability is refused with a reason": function () {
        var v = open(fixture("fenre_plain"), { "RAW services/authentication/current-context": NO_SEARCH_CAP });
        var b = button(v, "Run search");
        assert.strictEqual(b.disabled, true);
        assert.ok(/search capability/.test(b.getAttribute("title")));
    },
    "indirect commands only warn": function () {
        var uc = fixture("fenre_plain");
        uc.spl = "| rest /services/server/info | table version";
        var v = open(uc);
        assert.strictEqual(button(v, "Run search").disabled, false);
        assert.ok(hasText(v, /run other searches or reach data/));
    },
    "run starts one bounded search with preview off and no tokens": function () {
        var v = open(fixture("fenre_plain"));
        button(v, "Run search").dispatch("click");
        assert.strictEqual(FakeSearchManager.instances.length, 1);
        var sm = FakeSearchManager.instances[0];
        assert.strictEqual(sm.started, true);
        assert.strictEqual(sm.settings.preview, false);
        assert.strictEqual(sm.settings.cache, false);
        assert.strictEqual(sm.settings.autostart, false);
        assert.strictEqual(sm.settings.earliest_time, "-24h");
        assert.strictEqual(sm.settings.latest_time, "now");
        assert.strictEqual(sm.settings.max_time, 120);
        assert.strictEqual(sm.settings.status_buckets, 0);
        assert.strictEqual(sm.settings.cancelOnUnload, true);
        assert.strictEqual(sm.settings.app, "sunavigator");
        assert.deepStrictEqual(sm.options, { tokens: false });
        assert.ok(/^(search |\|)/.test(sm.settings.search));
        assert.strictEqual(button(v, "Run search").disabled, true, "no second run while one is active");
        assert.strictEqual(button(v, "Cancel").disabled, false);
    },
    "results are capped at 100 rows and rendered as text only": function () {
        var v = open(fixture("fenre_plain"));
        button(v, "Run search").dispatch("click");
        var sm = FakeSearchManager.instances[0];
        sm.handlers["search:done"]({ content: { resultCount: 250, scanCount: 9000, runDuration: 1.5 } });
        assert.deepStrictEqual(sm.dataArgs, ["results", { count: 100, offset: 0, output_mode: "json_rows" }]);
        var rows = [];
        for (var i = 0; i < 250; i++) { rows.push(["2026-01-01", i === 0 ? "<img src=x onerror=alert(1)>" : "v" + i, ["a", "b"], "x".repeat(900)]); }
        sm.results.payload = { fields: ["_time", "host", "mv", "_raw", "_bkt"], rows: rows.map(function (r) { return r.concat(["bucket"]); }) };
        sm.results.handlers.data();
        var trs = v.root.find(function (n) { return n.tagName === "TR"; });
        var body = trs.filter(function (tr) { return tr.childNodes[0] && tr.childNodes[0].tagName === "TD" && tr.childNodes.length === 4; });
        assert.strictEqual(body.length, 100);
        assert.ok(hasText(v, /Showing 100 of 250 results/));
        assert.ok(hasText(v, /<img src=x onerror=alert\(1\)>/), "markup is displayed as text");
        assert.strictEqual(v.root.find(function (n) { return n.tagName === "IMG"; }).length, 0);
        assert.ok(!hasText(v, /bucket/), "internal underscore fields are hidden");
        assert.ok(hasText(v, /a, b/));
        assert.ok(!/x{501}/.test(v.root.textContent), "cells are truncated");
        assert.ok(hasText(v, /does not store or export/));
        assert.strictEqual(button(v, "Run search").disabled, false);
    },
    "zero results is shown as a result, not an error": function () {
        var v = open(fixture("fenre_plain"));
        button(v, "Run search").dispatch("click");
        var sm = FakeSearchManager.instances[0];
        sm.handlers["search:done"]({ content: { resultCount: 0 } });
        sm.results.payload = { fields: ["a"], rows: [] };
        sm.results.handlers.data();
        assert.ok(hasText(v, /returned no results/));
    },
    "failures are shown and re-enable the button": function () {
        var v = open(fixture("fenre_plain"));
        button(v, "Run search").dispatch("click");
        FakeSearchManager.instances[0].handlers["search:failed"]({ content: { messages: [{ text: "Error in 'bogus' command" }] } });
        assert.ok(hasText(v, /Error in 'bogus' command/));
        assert.strictEqual(button(v, "Run search").disabled, false);
        FakeSearchManager.instances.length = 0;
        button(v, "Run search").dispatch("click");
        FakeSearchManager.instances[0].handlers["search:error"]("You do not have permission");
        assert.ok(hasText(v, /You do not have permission/));
    },
    "cancel stops the job": function () {
        var v = open(fixture("fenre_plain"));
        button(v, "Run search").dispatch("click");
        var sm = FakeSearchManager.instances[0];
        button(v, "Cancel").dispatch("click");
        assert.strictEqual(sm.cancelled, true);
        assert.strictEqual(sm.disposed, true);
        assert.strictEqual(button(v, "Run search").disabled, false);
        assert.strictEqual(button(v, "Cancel").disabled, true);
    },
    "leaving the page cancels a running job": function () {
        var v = open(fixture("fenre_plain"));
        button(v, "Run search").dispatch("click");
        var sm = FakeSearchManager.instances[0];
        assert.ok((v.windowListeners.pagehide || []).length >= 1);
        v.windowListeners.pagehide.forEach(function (f) { f(); });
        assert.strictEqual(sm.cancelled, true);
    },
    "nothing is posted to the server by the search": function () {
        var v = open(fixture("fenre_plain"));
        button(v, "Run search").dispatch("click");
        assert.ok(!v.calls.some(function (c) { return c.method === "POST"; }));
    },
    "requirements are grouped with the worst status first": function () {
        var uc = fixture("fenre_deployed");
        var v = open(uc);
        var heads = v.root.find(function (n) { return n.tagName === "H4"; }).map(function (n) { return n.textContent; });
        assert.ok(heads.length >= 1, "group headings");
        var order = ["not met", "unknown", "partial", "not verified", "met", "n/a", "not assessed"];
        var idx = heads.map(function (h) { return order.indexOf(h.replace(/ \(\d+\)$/, "")); });
        assert.ok(idx.every(function (i) { return i >= 0; }), heads.join(","));
        assert.deepStrictEqual(idx.slice().sort(function (a, b) { return a - b; }), idx);
        var total = heads.reduce(function (n, h) { return n + parseInt(/\((\d+)\)$/.exec(h)[1], 10); }, 0);
        var ids = {};
        uc.requirements.forEach(function (r) { ids[r.req_id] = true; });
        (uc.readiness.results || []).forEach(function (r) { ids[r.req_id] = true; });
        assert.strictEqual(total, Object.keys(ids).length, "every requirement and result appears exactly once");
    },
    "results without a requirement (SPL validity) are listed so the counts add up": function () {
        var uc = fixture("escu_macros");
        var v = open(uc);
        var heads = v.root.find(function (n) { return n.tagName === "H4"; }).map(function (n) { return n.textContent; });
        var total = heads.reduce(function (n, h) { return n + parseInt(/\((\d+)\)$/.exec(h)[1], 10); }, 0);
        var c = uc.readiness.counts;
        assert.strictEqual(total, c.met + c.partial + c.not_met + c.unknown + c.unverified + c.not_applicable);
        assert.ok(hasText(v, /spl_validity/) && hasText(v, /additional check/));
    },
    "summary shows requirements, readiness and deployment": function () {
        var v = open(fixture("fenre_deployed"));
        var t = v.root.textContent;
        assert.ok(/Requirements/.test(t) && /Readiness/.test(t) && /Deployment/.test(t) && /Your selection/.test(t));
        assert.ok(/retired/.test(t));
    },
    "unavailable actions all carry a reason": function () {
        var uc = fixture("fenre_deployed");
        var v = open(uc);
        var details = v.root.find(function (n) { return /ucm-unavailable/.test(n.getAttribute("class") || ""); });
        assert.strictEqual(details.length, 1);
        var dds = details[0].find(function (n) { return n.tagName === "DD"; });
        var dts = details[0].find(function (n) { return n.tagName === "DT"; });
        assert.strictEqual(dts.length, dds.length);
        assert.strictEqual(dts.length, 10, "every action except draft is unavailable here");
        dds.forEach(function (d) { assert.ok(d.textContent.length > 10); });
        assert.ok(/Already retired/.test(details[0].textContent));
    },
    "no innerHTML is used anywhere in the view": function () {
        var src = fs.readFileSync(path.join(__dirname, "..", "..", "sunavigator", "appserver", "static", "ucm_usecase.js"), "utf8");
        assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write/.test(src));
    }
};

var failed = 0;
Object.keys(tests).forEach(function (name) {
    try { tests[name](); console.log("ok   " + name); } catch (e) { failed++; console.log("FAIL " + name + ": " + (e.stack || e.message).split("\n").slice(0, 4).join("\n")); }
});
process.exit(failed ? 1 : 0);
