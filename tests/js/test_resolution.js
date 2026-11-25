"use strict";
var assert = require("assert");
var fs = require("fs");
var path = require("path");
var runView = require("./fake_dom").runView;

function fixture(name) {
    return JSON.parse(fs.readFileSync(path.join(__dirname, "..", "fixtures", "ui", "usecase_" + name + ".json"), "utf8"));
}

function open(uc, pathname) {
    return runView("ucm_usecase.js", "ucm-usecase", { usecase: uc, "RAW services/authentication/current-context": { entry: [{ content: { capabilities: ["search"] } }] } },
        { search: "?id=" + encodeURIComponent(uc.content_id), pathname: pathname || "/en-US/app/sunavigator/ucm_usecase",
            amd: { "splunkjs/mvc/searchmanager": function () {} } });
}

function withRequirement(type, value, status, code, extra) {
    var uc = fixture("escu_macros");
    uc.requirements = [{ req_id: type + ":" + value, type: type, value: value, level: "required", source: "provider_structured",
        confidence: "high", attributes: (extra && extra.attributes) || {}, notes: "" }];
    uc.readiness.results = [{ req_id: type + ":" + value, type: type, value: value, level: "required", source: "provider_structured",
        confidence: "high", status: status, code: code, detail: "d", observed: (extra && extra.observed) || [], via_mapping: null }];
    return uc;
}

function searchLinks(v) {
    return v.root.find(function (n) { return n.tagName === "A" && /^Open in Search/.test(n.textContent); });
}
function spl(link) { return decodeURIComponent(link.getAttribute("href").split("?q=")[1].split("&")[0]); }

var tests = {
    "an unmet sourcetype gets a hint and a bounded tstats search in a new tab": function () {
        var v = open(withRequirement("sourcetype", "aws:cloudtrail", "not_met", "not_found"));
        var t = v.root.textContent;
        assert.ok(/What to check: No index returned this sourcetype/.test(t));
        var links = searchLinks(v);
        assert.strictEqual(links.length, 1);
        assert.strictEqual(spl(links[0]), '| tstats count where index=* sourcetype="aws:cloudtrail" by index, sourcetype');
        assert.strictEqual(links[0].getAttribute("target"), "_blank");
        assert.strictEqual(links[0].getAttribute("rel"), "noopener noreferrer");
        assert.ok(/^https:\/\/splunk\.test:8000\/en-US\/app\/search\/search\?q=/.test(links[0].getAttribute("href")));
    },
    "a met requirement shows no hint and no link": function () {
        var v = open(withRequirement("sourcetype", "aws:cloudtrail", "met", "present"));
        assert.strictEqual(searchLinks(v).length, 0);
        assert.ok(!/What to check/.test(v.root.textContent));
    },
    "each requirement type has its own search": function () {
        var cases = [
            ["index", "wineventlog", "| tstats count where index=\"wineventlog\" by sourcetype"],
            ["cim_model", "Authentication", "| tstats summariesonly=false count from datamodel=Authentication by sourcetype"],
            ["lookup", "asset_lookup", "| inputlookup asset_lookup | head 20"],
            ["macro", "security_content_ctime(1)", "| rest splunk_server=local /servicesNS/-/-/configs/conf-macros count=0 | search title=\"security_content_ctime(1)\" | table title definition eai:acl.app eai:acl.sharing"]
        ];
        cases.forEach(function (c) {
            var links = searchLinks(open(withRequirement(c[0], c[1], "not_met", "not_found")));
            assert.strictEqual(links.length, 1, c[0]);
            assert.strictEqual(spl(links[0]), c[2], c[0]);
        });
    },
    "event and field searches use the index and sourcetype that discovery observed": function () {
        var ev = open(withRequirement("event_condition", "eventName=DescribeImageScanFindings", "partial", "event_not_seen", {
            attributes: { sourcetype: "aws:cloudtrail", field: "eventName", value: "DescribeImageScanFindings" },
            observed: [{ index: "aws", sourcetype: "aws:cloudtrail" }] }));
        assert.strictEqual(spl(searchLinks(ev)[0]),
            '| search index=aws sourcetype="aws:cloudtrail" "DescribeImageScanFindings" eventName="DescribeImageScanFindings" earliest=-30d | head 20');
        assert.ok(/Normal for a rare event/.test(ev.root.textContent));
        var f = open(withRequirement("field", "src_ip", "not_met", "sampled_absent", { observed: [{ index: "fw", sourcetype: "pan:traffic" }] }));
        assert.strictEqual(spl(searchLinks(f)[0]), '| search index=fw sourcetype="pan:traffic" src_ip=* earliest=-24h | head 20 | table _time src_ip');
        assert.strictEqual(searchLinks(open(withRequirement("field", "src_ip", "unverified", "not_sampled"))).length, 0, "no context, no link");
    },
    "values with quotes, pipes or spaces never produce a link": function () {
        ["a\" | delete", "a b", "a|b", "x'y"].forEach(function (bad) {
            assert.strictEqual(searchLinks(open(withRequirement("sourcetype", bad, "not_met", "not_found"))).length, 0, bad);
        });
        assert.strictEqual(searchLinks(open(withRequirement("index", "a\"b", "not_met", "not_found"))).length, 0);
        assert.strictEqual(searchLinks(open(withRequirement("macro", "m`x", "not_met", "not_found"))).length, 0);
    },
    "no link when the page path has no app segment": function () {
        var v = open(withRequirement("sourcetype", "aws:cloudtrail", "not_met", "not_found"), "/view");
        assert.strictEqual(searchLinks(v).length, 0);
        assert.ok(/What to check/.test(v.root.textContent), "the hint stays");
    },
    "hints are specific to the type and fall back to a general one": function () {
        assert.ok(/ucm_scheduler role access/.test(open(withRequirement("index", "x", "not_met", "index_unavailable")).root.textContent));
        assert.ok(/Splunk Common Information Model add-on/.test(open(withRequirement("cim_model", "Web", "not_met", "model_missing")).root.textContent));
        assert.ok(/Not found by discovery/.test(open(withRequirement("lookup", "x", "not_met", "not_found")).root.textContent));
    }
};

var failed = 0;
Object.keys(tests).forEach(function (name) {
    try { tests[name](); console.log("ok   " + name); } catch (e) { failed++; console.log("FAIL " + name + "\n  " + (e && e.stack || e)); }
});
process.exit(failed ? 1 : 0);
