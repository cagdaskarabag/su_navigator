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

function open(uc, extra, more) {
    FakeSearchManager.instances.length = 0;
    var routes = { usecase: uc, "RAW services/authentication/current-context": SEARCH_CAP };
    Object.assign(routes, extra || {});
    return runView("ucm_usecase.js", "ucm-usecase", routes,
        Object.assign({ search: "?id=" + encodeURIComponent(uc.content_id), amd: { "splunkjs/mvc/searchmanager": FakeSearchManager } }, more || {}));
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
    "an add-on command that is not on the read-only list is refused (D-080)": function () {
        var uc = fixture("fenre_plain");
        uc.spl = 'index=os | head 1 | snowincident --account "prod" --short_description "x"';
        var v = open(uc);
        var b = button(v, "Run search");
        assert.strictEqual(b.disabled, true);
        assert.ok(/snowincident/.test(b.getAttribute("title")), b.getAttribute("title"));
        assert.ok(/read-only list/.test(b.getAttribute("title")));
        b.dispatch("click");
        assert.strictEqual(FakeSearchManager.instances.length, 0);
    },
    "an unknown command stays refused when the stored parse lists it": function () {
        var uc = fixture("fenre_plain");
        uc.spl = "index=os | head 1 | snowincident --account prod";
        uc.validation = { source_hash: uc.provenance.source_hash, parse_ok: true, side_effects: [], indirect_commands: [], unknown_commands: ["snowincident"] };
        var b = button(open(uc), "Run search");
        assert.strictEqual(b.disabled, true);
        assert.ok(/extra_safe_commands/.test(b.getAttribute("title")), b.getAttribute("title"));
    },
    "a command the server cleared through extra_safe_commands is offered without a warning about it": function () {
        var uc = fixture("fenre_plain");
        uc.spl = "index=os | head 1 | mytrusted a=1";
        uc.validation = { source_hash: uc.provenance.source_hash, parse_ok: true, side_effects: [], indirect_commands: [], unknown_commands: [] };
        assert.strictEqual(button(open(uc), "Run search").disabled, false);
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
        assert.strictEqual(dts.length, 13, "every action except draft is unavailable here");
        dds.forEach(function (d) { assert.ok(d.textContent.length > 10); });
        assert.ok(/Already retired/.test(details[0].textContent));
    },
    "control test: a content error is shown as its own verdict with the window and per-field results": function () {
        var uc = fixture("fenre_deployed");
        uc.deployment.deployment.control_test = { status: "content_error", reason: "the search failed on the positive test data: Error in 'eval' command",
            test_index: "ucm_controltest", revision: 3, ran_at: "2026-11-24T10:00:00Z", ran_by: "alice",
            positive: { indexed: 3, window: { earliest: "1776322800", latest: "1776330002", derived: true } } };
        var v = open(uc);
        var t = v.root.textContent;
        assert.ok(/Control test: content error/.test(t), "title");
        assert.ok(/failed with an error while it ran on the test data/.test(t));
        assert.ok(/Error in 'eval' command/.test(t));
        assert.ok(/Search window 2026-04-16T07:00:00Z to 2026-04-16T09:00:02Z, derived from the fixture timestamps/.test(t), t);
        var box = v.root.find(function (n) { return /ucm-state-error/.test(n.getAttribute("class") || ""); });
        assert.ok(box.length >= 1);
    },
    "control test: failed run lists each field assertion and max_count": function () {
        var uc = fixture("fenre_deployed");
        uc.deployment.deployment.control_test = { status: "failed", reason: "field host: expected one of ['a'], saw []",
            test_index: "ucm_controltest", revision: 3, ran_at: "2026-11-24T10:00:00Z", ran_by: "alice",
            positive: { indexed: 3, rows: 9, min_count: 1, max_count: 5, window: { earliest: "-10y", latest: "+1d", derived: false },
                fields: [{ name: "host", pass: false, failures: ["expected one of ['a'], saw []"] },
                    { name: "count", pass: true, failures: [] }] } };
        var v = open(uc);
        var items = v.root.find(function (n) { return n.tagName === "LI" && /ucm-control-fields/.test((n.parentNode.getAttribute("class") || "")); });
        assert.strictEqual(items.length, 2);
        assert.ok(/failed.*field host: expected one of/.test(items[0].textContent), items[0].textContent);
        assert.ok(/passed.*field count/.test(items[1].textContent), items[1].textContent);
        var t = v.root.textContent;
        assert.ok(/Positive run: 9 rows, expected 1 to 5/.test(t));
        assert.ok(/the default \(the fixture timestamps could not be read\)/.test(t));
    },
    "control test: results stored before 0.8.8 still render": function () {
        var uc = fixture("fenre_deployed");
        uc.deployment.deployment.control_test = { status: "inconclusive", reason: "timed out", test_index: "ucm_controltest",
            revision: 1, ran_at: "2026-11-01T10:00:00Z", ran_by: "bob", positive: { indexed: 3, rows: 0, min_count: 1, pass: false } };
        var t = open(uc).root.textContent;
        assert.ok(/Control test: inconclusive/.test(t) && /neither confirmed nor refuted/.test(t));
        assert.ok(!/Search window/.test(t));
    },
    "no innerHTML is used anywhere in the view": function () {
        var src = fs.readFileSync(path.join(__dirname, "..", "..", "sunavigator", "appserver", "static", "ucm_usecase.js"), "utf8");
        assert.ok(!/innerHTML|outerHTML|insertAdjacentHTML|document\.write/.test(src));
    }
};

function twin(over) {
    return Object.assign({ content_id: "escu:UC-aaaa", provider: "escu", record_id: "aaaa", title: "Defender disabled",
        category_name: "Endpoint", criticality: "high", review_status: "unreviewed", key: "escu_UC-aaaa",
        authority: { role: "detection", label: "Detection content source" } }, over || {});
}
function planPanel(v) { return v.root.find(function (n) { return n.getAttribute("id") === "ucm-plan-panel"; })[0]; }
function planToggle(v) { return v.root.find(function (n) { return n.tagName === "BUTTON" && n.getAttribute("aria-controls") === "ucm-plan-panel"; })[0]; }

Object.assign(tests, {
    "the deployment form is collapsed behind Plan deployment and the state stays visible": function () {
        var v = open(fixture("fenre_plain"));
        var panel = planPanel(v), toggle = planToggle(v);
        assert.ok(panel && toggle);
        assert.notStrictEqual(panel.getAttribute("hidden"), null, "collapsed on load");
        assert.strictEqual(toggle.textContent, "Plan deployment");
        assert.strictEqual(toggle.getAttribute("aria-expanded"), "false");
        assert.ok(hasText(v, /Selection/) && /not selected/.test(v.root.textContent) && /not deployed/.test(v.root.textContent),
            "selected / pending / deployed state is outside the collapsed panel");
        var inside = panel.textContent;
        assert.ok(/Your selection/.test(inside) && /Deployment/.test(inside));
    },
    "Plan deployment expands and collapses the same controls and works as a button": function () {
        var v = open(fixture("fenre_plain"));
        var toggle = planToggle(v);
        assert.strictEqual(toggle.tagName, "BUTTON");
        assert.strictEqual(toggle.getAttribute("type"), "button");
        toggle.dispatch("click");
        assert.strictEqual(planPanel(v).getAttribute("hidden"), null);
        assert.strictEqual(toggle.getAttribute("aria-expanded"), "true");
        assert.strictEqual(toggle.textContent, "Hide deployment plan");
        assert.ok(v.root.find(function (n) { return n.tagName === "BUTTON" && /Select/.test(n.textContent); }).length > 0);
        toggle.dispatch("click");
        assert.notStrictEqual(planPanel(v).getAttribute("hidden"), null);
    },
    "the jump links and a deep link open the plan": function () {
        var v = open(fixture("fenre_plain"));
        var link = v.root.find(function (n) { return n.tagName === "A" && n.getAttribute("href") === "#ucm-sec-deployment"; })[0];
        assert.ok(link);
        link.dispatch("click");
        assert.strictEqual(planPanel(v).getAttribute("hidden"), null);
        var w = open(fixture("fenre_plain"), {}, { hash: "#ucm-sec-selection" });
        assert.strictEqual(planPanel(w).getAttribute("hidden"), null);
        var other = open(fixture("fenre_plain"), {}, { hash: "#ucm-sec-spl" });
        assert.notStrictEqual(planPanel(other).getAttribute("hidden"), null);
    },
    "a deployed use case shows its deployment state without expanding": function () {
        var v = open(fixture("fenre_deployed"));
        assert.notStrictEqual(planPanel(v).getAttribute("hidden"), null);
        assert.ok(/retired/.test(v.root.textContent.replace(planPanel(v).textContent, "")), "state outside the panel");
    },
    "the plan comes after the content sections": function () {
        var v = open(fixture("fenre_plain"));
        var t = v.root.textContent;
        assert.ok(t.indexOf("References") < t.indexOf("Plan deployment", t.indexOf("Jump to") + 200));
    },
    "a twin is linked in both directions with the provider role and the deploy-once note": function () {
        var fen = fixture("fenre_plain");
        fen.spl_twins = [twin()];
        fen.authority = { role: "compliance", label: "Compliance and mapping context" };
        var v = open(fen);
        var t = v.root.textContent;
        assert.ok(/Same detection in ESCU: escu:UC-aaaa/.test(t), t);
        assert.ok(/deploying both creates two saved searches/.test(t));
        assert.ok(/Detection content source/.test(t) && /compliance and mapping context/.test(t));
        var a = v.root.find(function (n) { return n.tagName === "A" && n.getAttribute("href") === "ucm_usecase?id=escu_UC-aaaa"; });
        assert.strictEqual(a.length, 1);
        var esc = fixture("escu_macros");
        esc.spl_twins = [twin({ content_id: "fenre:UC-10.4.24", provider: "fenre", key: "fenre_UC-10.4.24",
            authority: { role: "compliance", label: "Compliance and mapping context" } })];
        esc.authority = { role: "detection", label: "Detection content source" };
        var w = open(esc);
        assert.ok(/Same detection in Fenre: fenre:UC-10.4.24/.test(w.root.textContent));
    },
    "the lineage wording claims only an identical primary SPL": function () {
        var fen = fixture("fenre_plain");
        fen.spl_twins = [twin()];
        var box = open(fen).root.find(function (n) { return n.getAttribute("class") === "ucm-lineage"; })[0];
        var t = box.textContent;
        assert.ok(/identical after whitespace is normalised/.test(t));
        assert.ok(/can still differ/.test(t));
        assert.ok(!/same author|derived from|copied from|equivalent/i.test(t));
    },
    "without a twin there is no lineage box": function () {
        var v = open(fixture("fenre_plain"));
        assert.ok(!/Same detection in/.test(v.root.textContent));
        assert.ok(!/also exists in another provider/.test(v.root.textContent));
    },
    "same-provider duplicates keep their own warning": function () {
        var fen = fixture("fenre_plain");
        fen.spl_duplicates = ["fenre:UC-1.1.1"];
        var t = open(fen).root.textContent;
        assert.ok(/identical in other use cases of this provider/.test(t) && /fenre:UC-1\.1\.1/.test(t));
        assert.ok(!/Same detection in/.test(t));
    },
    "the header carries a provider badge and a provider qualified category": function () {
        var uc = fixture("escu_macros");
        var v = open(uc);
        assert.ok(v.root.find(function (n) { return /ucm-badge-provider/.test(n.getAttribute("class") || ""); }).length >= 1);
        assert.ok(/ESCU ›/.test(v.root.textContent));
    },
    "ESCU stories and data sources are listed": function () {
        var uc = fixture("escu_macros");
        uc.analytic_stories = ["Brute Force"]; uc.data_sources = ["Sysmon EventID 1"];
        var t = open(uc).root.textContent;
        assert.ok(/Brute Force/.test(t) && /Sysmon EventID 1/.test(t));
    }
});

var failed = 0;
Object.keys(tests).forEach(function (name) {
    try { tests[name](); console.log("ok   " + name); } catch (e) { failed++; console.log("FAIL " + name + ": " + (e.stack || e.message).split("\n").slice(0, 4).join("\n")); }
});
process.exit(failed ? 1 : 0);
