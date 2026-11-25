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
        usecase: uc, "POST deployment/draft": uc.deployment,
        "RAW services/authentication/current-context": { entry: [{ content: { capabilities: ["search"] } }] }
    }, { search: "?id=" + encodeURIComponent(uc.content_id), amd: { "splunkjs/mvc/searchmanager": function () {} } });
}

function button(v, label) {
    var b = v.root.find(function (n) { return n.tagName === "BUTTON" && n.textContent === label; });
    assert.strictEqual(b.length, 1, "button " + label + " x" + b.length);
    return b[0];
}

function withPolicy(policy) {
    var uc = fixture("fenre_plain");
    uc.deployment.settings.actions = policy;
    return uc;
}

var OPEN = { enabled: true, email_domains: ["example.com"], webhook_hosts: ["hooks.example.com"], require_suppression: true };

var tests = {
    "draft form lists the permitted destinations and sends the chosen actions": function () {
        var v = open(withPolicy(OPEN));
        var t = v.root.textContent;
        assert.ok(/Notifications/.test(t) && /Email allowed to: example\.com/.test(t) && /Webhooks allowed to: hooks\.example\.com/.test(t), t);
        assert.ok(/never attached/.test(t));
        var boxes = v.root.find(function (n) { return n.tagName === "INPUT" && n.getAttribute("type") === "checkbox"; });
        assert.strictEqual(boxes.length, 2);
        boxes.forEach(function (b) { assert.strictEqual(b.disabled, false); });
        boxes[0].checked = true;
        var texts = v.root.find(function (n) { return n.tagName === "INPUT" && n.placeholder === "soc@example.com"; });
        assert.strictEqual(texts.length, 1);
        texts[0].value = "a@example.com, b@example.com";
        button(v, "Save draft").dispatch("click");
        var post = v.calls.filter(function (c) { return c.method === "POST" && /deployment\/draft/.test(c.path); })[0];
        assert.ok(post, "draft posted");
        assert.deepStrictEqual(post.params.actions, { email: { to: "a@example.com, b@example.com", subject: "", message: "", include_link: true } });
    },
    "with no destinations listed the options are off and say why": function () {
        var v = open(withPolicy({ enabled: true, email_domains: [], webhook_hosts: [] }));
        var t = v.root.textContent;
        assert.ok(/Email is off: an administrator has not listed permitted mail domains/.test(t), t);
        assert.ok(/Webhooks are off: an administrator has not listed permitted hosts/.test(t), t);
        v.root.find(function (n) { return n.tagName === "INPUT" && n.getAttribute("type") === "checkbox"; })
            .forEach(function (b) { assert.strictEqual(b.disabled, true); });
        button(v, "Save draft").dispatch("click");
        var post = v.calls.filter(function (c) { return c.method === "POST"; })[0];
        assert.deepStrictEqual(post.params.actions, {});
    },
    "turned off by the administrator: no form fields, a statement instead": function () {
        var v = open(withPolicy({ enabled: false, email_domains: ["example.com"], webhook_hosts: [] }));
        assert.ok(/Alert actions are turned off by an administrator/.test(v.root.textContent));
        assert.strictEqual(v.root.find(function (n) { return n.tagName === "INPUT" && n.getAttribute("type") === "checkbox"; }).length, 0);
    },
    "a revision with notifications shows every recipient and whether it was acknowledged": function () {
        var uc = fixture("fenre_deployed");
        var dep = uc.deployment.deployment;
        dep.state = "pending_approval";
        var rev = dep.revisions[dep.revisions.length - 1];
        rev.actions = { email: { to: ["soc@example.com", "lead@example.com"], subject: "Alert $name$", message: "Look", include_link: true },
            webhook: { url: "https://hooks.example.com/x/y" } };
        uc.deployment.allowed_actions = ["approve", "reject"];
        var t = open(uc).root.textContent;
        assert.ok(/Notifications on this revision/.test(t), t);
        assert.ok(/An email to soc@example\.com, lead@example\.com, subject "Alert \$name\$", message "Look", with a link to the results\. Results are never attached\./.test(t), t);
        assert.ok(/A webhook call to https:\/\/hooks\.example\.com\/x\/y\./.test(t), t);
        assert.ok(/Not yet acknowledged by an approver/.test(t), t);
        rev.actions_acknowledged_by = "bob";
        assert.ok(/Acknowledged by bob/.test(open(uc).root.textContent));
    },
    "a revision without notifications shows no box": function () {
        var uc = fixture("fenre_deployed");
        assert.ok(!/Notifications on this revision/.test(open(uc).root.textContent));
    }
};

var failed = 0;
Object.keys(tests).forEach(function (name) {
    try { tests[name](); console.log("ok   " + name); } catch (e) { failed++; console.log("FAIL " + name + "\n  " + (e && e.stack || e)); }
});
process.exit(failed ? 1 : 0);
