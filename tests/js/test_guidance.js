"use strict";
var assert = require("assert");
var fs = require("fs");
var path = require("path");
var runView = require("./fake_dom").runView;

function fixture(name) {
    return JSON.parse(fs.readFileSync(path.join(__dirname, "..", "fixtures", "ui", "usecase_" + name + ".json"), "utf8"));
}

function open(uc) {
    return runView("ucm_usecase.js", "ucm-usecase", {
        usecase: uc, "RAW services/authentication/current-context": { entry: [{ content: { capabilities: ["search"] } }] }
    }, { search: "?id=" + encodeURIComponent(uc.content_id), amd: { "splunkjs/mvc/searchmanager": function () {} } });
}

function enriched() {
    var uc = fixture("escu_macros");
    uc.provider_extras.status = "experimental";
    uc.provider_extras.supportedTA = [{ name: "Splunk Add-on for AWS", url: "https://splunkbase.splunk.com/app/1876", version: "7.0" },
        { name: "Unsafe", url: "javascript:alert(1)", version: "" }];
    uc.provider_extras.dataSourceDetails = [{ name: "AWS CloudTrail DescribeImageScanFindings", sourcetype: "aws:cloudtrail",
        source: "aws_cloudtrail", separator: "eventName", separatorValue: "DescribeImageScanFindings", supportedTA: [] }];
    uc.provider_extras.riskEntities = [{ field: "user", type: "user", score: 20, message: "m" }];
    uc.provider_extras.drilldowns = [{ name: "View risk for $user$", search: "| from datamodel:Risk.All_Risks" }];
    uc.provider_extras.tests = [{ name: "t", type: "unit", attackData: [
        { url: "https://media.githubusercontent.com/x.log", sourcetype: "aws:cloudtrail", source: "s" },
        { url: "http://insecure.example/x.log", sourcetype: "a", source: "b" }] }];
    uc.provider_extras.macroDefinitions = { o365_management_activity: "sourcetype=o365:management:activity" };
    return uc;
}

function links(v) { return v.root.find(function (n) { return n.tagName === "A" && n.getAttribute("target") === "_blank"; }); }

var tests = {
    "enriched record shows add-ons, data sources, risk entities, drilldowns and test-data references": function () {
        var t = open(enriched()).root.textContent;
        assert.ok(/Provider guidance/.test(t));
        assert.ok(/Provider status: experimental/.test(t));
        assert.ok(/Splunk Add-on for AWS/.test(t) && /tested with 7\.0/.test(t));
        assert.ok(/sourcetype=aws:cloudtrail\s+where eventName=DescribeImageScanFindings/.test(t));
        assert.ok(/risk score 20/.test(t));
        assert.ok(/Drilldown searches \(1\)/.test(t) && /datamodel:Risk\.All_Risks/.test(t));
        assert.ok(/Test data references \(2\)/.test(t) && /never downloads them/.test(t));
    },
    "only https links are anchors; others are plain text": function () {
        var hrefs = links(open(enriched())).map(function (a) { return a.getAttribute("href"); });
        assert.ok(hrefs.indexOf("https://splunkbase.splunk.com/app/1876") >= 0);
        assert.ok(hrefs.indexOf("https://media.githubusercontent.com/x.log") >= 0);
        assert.ok(hrefs.every(function (h) { return /^https:\/\//.test(h); }), hrefs.join(","));
        var t = open(enriched()).root.textContent;
        assert.ok(t.indexOf("Unsafe") >= 0 && t.indexOf("http://insecure.example") >= 0);
    },
    "a deprecated record shows a warning": function () {
        var uc = enriched();
        uc.provider_extras.status = "deprecated";
        uc.quality_flags = ["deprecated_upstream"];
        var t = open(uc).root.textContent;
        assert.ok(/The provider has marked this detection deprecated/.test(t));
        assert.ok(/deprecated upstream/.test(t));
    },
    "a production record without other guidance shows no section": function () {
        var uc = fixture("escu_macros");
        uc.provider_extras.status = "production";
        assert.ok(!/Provider guidance/.test(open(uc).root.textContent));
    },
    "guided fields are not repeated under other provider fields": function () {
        var t = open(enriched()).root.textContent;
        assert.ok(!/macroDefinitions|dataSourceDetails|riskEntities/.test(t));
    },
    "macro help shows the provider's reference definition when there is one": function () {
        var uc = enriched();
        uc.readiness.results.forEach(function (r) { if (r.type === "macro" && r.value === "o365_management_activity") { r.status = "not_met"; r.code = "not_found"; } });
        var t = open(uc).root.textContent;
        assert.ok(/How to create this macro/.test(t));
        assert.ok(/the provider's reference definition is shown below/.test(t));
        assert.ok(t.indexOf("sourcetype=o365:management:activity") >= 0);
        var plain = fixture("escu_macros");
        plain.readiness.results.forEach(function (r) { if (r.type === "macro" && r.value === "o365_management_activity") { r.status = "not_met"; r.code = "not_found"; } });
        assert.ok(/The content provider does not supply it/.test(open(plain).root.textContent));
    }
};

var failed = 0;
Object.keys(tests).forEach(function (name) {
    try { tests[name](); console.log("ok   " + name); } catch (e) { failed++; console.log("FAIL " + name + "\n  " + (e && e.stack || e)); }
});
process.exit(failed ? 1 : 0);
