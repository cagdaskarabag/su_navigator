"use strict";
var assert = require("assert");
var fs = require("fs");
var path = require("path");
var fake = require("./fake_dom");
var runView = fake.runView;

var EXT = {
    counts: { proposed: 2, accepted: 1, rejected: 0 }, has_more: false,
    items: [
        { _key: "xm_" + "a".repeat(40), app: "SplunkEnterpriseSecuritySuite", name: "ESCU - Windows Cmd Exec - Rule", enabled: true,
          status: "active", state: "proposed", content_key: "", candidates: [
            { content_key: "k1", content_id: "uc-1", title: "Windows Cmd Exec", basis: "spl_hash" },
            { content_key: "k2", content_id: "uc-2", title: "Windows Cmd Exec Variant", basis: "title" }] },
        { _key: "xm_" + "b".repeat(40), app: "other", name: "Changed search", enabled: false, status: "missing", state: "proposed",
          previous_state: "accepted", content_key: "", candidates: [{ content_key: "k1", content_id: "uc-1", title: "Windows Cmd Exec", basis: "title_mitre" }] }
    ]
};

function open(extra) {
    var routes = Object.assign({ discovery: { state: {}, jobs: [], settings: { earliest: "-7d", latest: "now" } }, "inventory/coverage": {}, "environment/health": { discovered: false },
        inventory: { items: [], total: 0, has_more: false }, mappings: { items: [] }, external: EXT, "POST external": { match: {} } }, extra || {});
    var o = { on: function () { return o; }, off: function () { return o; }, val: function () { return ""; }, prop: function () { return false; } };
    return runView("ucm_inventory.js", "ucm-inventory", routes, { jquery: function () { return o; } });
}

function buttons(v, label) {
    return v.root.find(function (n) { return n.tagName === "BUTTON" && n.textContent === label; });
}

function usecase(external) {
    var uc = JSON.parse(fs.readFileSync(path.join(__dirname, "..", "fixtures", "ui", "usecase_escu_macros.json"), "utf8"));
    uc.external = external;
    return runView("ucm_usecase.js", "ucm-usecase", { usecase: uc, "RAW services/authentication/current-context": { entry: [{ content: { capabilities: ["search"] } }] } },
        { search: "?id=" + encodeURIComponent(uc.content_id), amd: { "splunkjs/mvc/searchmanager": function () {} } }).root.textContent;
}

var tests = {
    "use case page says enabled elsewhere, with names only when the server sent them": function () {
        var t = usecase({ enabled: 1, accepted: 2, proposed: 1, matches: [{ app: "es", name: "Cmd Rule", enabled: true }, { app: "x", name: "Old", enabled: false }] });
        assert.ok(/Detections outside SUNavigator/.test(t) && /Enabled elsewhere: 1 matched search in other apps is enabled/.test(t), t);
        assert.ok(/Cmd Rule \(es\); Old \(x, disabled\)/.test(t), t);
        assert.ok(/1 search in other apps may implement this use case/.test(t) && /do not change its coverage levels/.test(t), t);
        var viewer = usecase({ enabled: 1, accepted: 1, proposed: 0, matches: null });
        assert.ok(/Enabled elsewhere: 1/.test(viewer) && !/Cmd Rule/.test(viewer), viewer);
    },
    "use case page shows nothing without any match": function () {
        assert.ok(!/Detections outside SUNavigator/.test(usecase({ enabled: 0, accepted: 0, proposed: 0, matches: null })));
        assert.ok(!/Detections outside SUNavigator/.test(usecase(undefined)));
    },
    "proposals list the search by name and each candidate with why it matched": function () {
        var t = open().root.textContent;
        assert.ok(/Detections already running here/.test(t), t);
        assert.ok(/ESCU - Windows Cmd Exec - Rule/.test(t) && /SplunkEnterpriseSecuritySuite/.test(t), t);
        assert.ok(/same search text/.test(t) && /same title only/.test(t) && /same title and technique/.test(t), t);
        assert.ok(/hashed and never stored/.test(t) && /does not count as deployed/.test(t), t);
        assert.ok(/Search text changed since you accepted it/.test(t) && /no longer found/.test(t), t);
    },
    "accept sends the chosen use case and reject sends none": function () {
        var v = open();
        buttons(v, "Accept")[1].dispatch("click");
        buttons(v, "Reject")[0].dispatch("click");
        var posts = v.calls.filter(function (c) { return c.method === "POST"; });
        assert.deepStrictEqual(posts[0].params, { id: "xm_" + "a".repeat(40), decision: "accept", content_key: "k2" });
        assert.deepStrictEqual(posts[1].params, { id: "xm_" + "a".repeat(40), decision: "reject", content_key: "" });
    },
    "accepted rows offer reset and mark the chosen use case": function () {
        var done = Object.assign({}, EXT.items[0], { state: "accepted", content_key: "k1" });
        var v = open({ external: { counts: EXT.counts, has_more: false, items: [done] } });
        assert.strictEqual(buttons(v, "Accept").length, 0);
        assert.strictEqual(buttons(v, "Reset").length, 1);
        assert.ok(/accepted/.test(v.root.textContent));
    },
    "a viewer without the capability sees no section": function () {
        var v = open({ external: new Error("forbidden") });
        assert.ok(!/Detections already running here/.test(v.root.textContent));
    }
};

var failed = 0;
Object.keys(tests).forEach(function (name) {
    try { tests[name](); console.log("ok   " + name); } catch (e) { failed++; console.log("FAIL " + name + ": " + (e.stack || e.message).split("\n").slice(0, 5).join("\n")); }
});
process.exit(failed ? 1 : 0);
