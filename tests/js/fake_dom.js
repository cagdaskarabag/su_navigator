/*
 * Minimal DOM and AMD stubs so the app's vanilla AMD modules can be exercised under plain Node
 * (no dependencies). Only what ucm_common.js and the view helpers use is implemented.
 */
"use strict";
var fs = require("fs");
var path = require("path");

function FakeNode() { this.childNodes = []; this.parentNode = null; this.listeners = {}; }
Object.defineProperty(FakeNode.prototype, "firstChild", { get: function () { return this.childNodes[0] || null; } });
FakeNode.prototype.appendChild = function (c) { c.parentNode = this; this.childNodes.push(c); return c; };
FakeNode.prototype.removeChild = function (c) {
    this.childNodes.splice(this.childNodes.indexOf(c), 1); c.parentNode = null; return c;
};
FakeNode.prototype.addEventListener = function (type, fn) { (this.listeners[type] = this.listeners[type] || []).push(fn); };
FakeNode.prototype.dispatch = function (type) {
    var self = this;
    (this.listeners[type] || []).forEach(function (fn) { fn.call(self, { type: type, target: self }); });
};

function FakeText(text) { FakeNode.call(this); this.data = text; }
FakeText.prototype = Object.create(FakeNode.prototype);

function FakeElement(tag) {
    FakeNode.call(this);
    this.tagName = tag.toUpperCase();
    this.attrs = {};
    this.checked = false; this.disabled = false; this.indeterminate = false; this.value = "";
}
FakeElement.prototype = Object.create(FakeNode.prototype);
FakeElement.prototype.setAttribute = function (k, v) { this.attrs[k] = String(v); if (k === "disabled") { this.disabled = true; } };
FakeElement.prototype.removeAttribute = function (k) { delete this.attrs[k]; if (k === "disabled") { this.disabled = false; } };
FakeElement.prototype.getAttribute = function (k) { return Object.prototype.hasOwnProperty.call(this.attrs, k) ? this.attrs[k] : null; };
Object.defineProperty(FakeElement.prototype, "textContent", {
    get: function () {
        return this.childNodes.map(function (c) { return c instanceof FakeText ? c.data : c.textContent; }).join("");
    },
    set: function (v) { this.childNodes = [new FakeText(String(v))]; }
});
/* innerHTML is deliberately unavailable: assigning it must fail a test loudly. */
Object.defineProperty(FakeElement.prototype, "innerHTML", {
    get: function () { throw new Error("innerHTML read"); },
    set: function () { throw new Error("innerHTML must never be used"); }
});
FakeElement.prototype.walk = function (fn) {
    fn(this);
    this.childNodes.forEach(function (c) { if (c instanceof FakeElement) { c.walk(fn); } });
};
FakeElement.prototype.find = function (pred) {
    var out = [];
    this.walk(function (n) { if (pred(n)) { out.push(n); } });
    return out;
};

global.Node = FakeNode;
global.document = {
    createElement: function (t) { return new FakeElement(t); },
    createTextNode: function (t) { return new FakeText(t); }
};

var jq = function () { throw new Error("jQuery call not stubbed"); };
jq.isArray = Array.isArray;
jq.param = function (o) {
    return Object.keys(o || {}).map(function (k) { return k + "=" + o[k]; }).join("&");
};
jq.Deferred = function () { throw new Error("Deferred not stubbed"); };

var splunkUtilStub = {
    make_url: function (p) { return p; },
    getFormKey: function () { return "key"; },
    getConfigValue: function () { return ""; }
};

/* Load an AMD module from appserver/static with stubbed dependencies. */
function loadAmd(file, deps) {
    var src = fs.readFileSync(path.join(__dirname, "..", "..", "sunavigator", "appserver", "static", file), "utf8");
    var exported;
    var map = Object.assign({ jquery: jq, "splunk.util": splunkUtilStub }, deps || {});
    function define(names, factory) {
        exported = factory.apply(null, names.map(function (n) {
            if (!(n in map)) { throw new Error("unstubbed AMD dependency " + n); }
            return map[n];
        }));
    }
    new Function("define", src)(define);
    return exported;
}

/* Synchronous stand-in for a jQuery promise; enough for .done/.fail/.always chains. */
function resolved(value) {
    var p = { done: function (f) { f(value); return p; }, fail: function () { return p; }, always: function (f) { f(); return p; } };
    return p;
}
function rejected(err) {
    var p = { done: function () { return p; }, fail: function (f) { f(err); return p; }, always: function (f) { f(); return p; } };
    return p;
}

/*
 * Run a view script (require([...], ucmViewMain) style) against the real ucm_common.js with a
 * scripted API. routes maps "path" to a value or function(params) returning a value; a value that
 * is an Error becomes a rejected request. Returns the root element and the calls made.
 */
function runView(file, rootId, routes, opts) {
    opts = opts || {};
    var ucm = loadAmd("ucm_common.js");
    var calls = [];
    function api(method) {
        return function (p, params, body) {
            calls.push({ method: method, path: p, params: params || {}, body: body });
            var r = routes[method + " " + p] !== undefined ? routes[method + " " + p] : routes[p];
            if (typeof r === "function") { r = r(params || {}, body); }
            if (r === undefined) { return rejected({ status: 404, message: "no route " + p }); }
            return r instanceof Error ? rejected({ status: 500, message: r.message }) : resolved(JSON.parse(JSON.stringify(r)));
        };
    }
    ucm.get = api("GET");
    ucm.rawGet = function (p, params) { calls.push({ method: "RAW", path: p, params: params || {} }); return routes["RAW " + p] !== undefined ? resolved(routes["RAW " + p]) : rejected({ status: 404, message: "no raw route" }); };
    ucm.post = api("POST");
    var root = new FakeElement("div");
    global.document.getElementById = function (id) { return id === rootId ? root : null; };
    global.document.querySelectorAll = function () { return []; };
    var windowListeners = {};
    global.window = { location: { search: opts.search || "" },
        addEventListener: function (t, f) { (windowListeners[t] = windowListeners[t] || []).push(f); } };
    var $ = Object.assign(function () { throw new Error("jQuery call not stubbed"); }, jq, {
        when: function () {
            var args = Array.prototype.slice.call(arguments);
            var ok = true, err = null, vals = [];
            args.forEach(function (a) { a.done(function (v) { vals.push(v); }).fail(function (e) { ok = false; err = e; }); });
            return ok ? { done: function (f) { f.apply(null, vals); return this; }, fail: function () { return this; } }
                : { done: function () { return this; }, fail: function (f) { f(err); return this; } };
        }
    });
    var src = fs.readFileSync(path.join(__dirname, "..", "..", "sunavigator", "appserver", "static", file), "utf8");
    var captured;
    var fakeRequire = function (deps, fn, errFn) {
        if (deps.length === 1 && opts.amd && opts.amd[deps[0]] !== undefined) { fn(opts.amd[deps[0]]); return; }
        if (deps.length === 1 && opts.amd) { if (errFn) { errFn(new Error("no module " + deps[0])); } return; }
        captured = fn;
    };
    new Function("require", src + "\n;return ucmViewMain;")(fakeRequire)($, ucm);
    return { root: root, ucm: ucm, calls: calls, windowListeners: windowListeners };
}

module.exports = { loadAmd: loadAmd, FakeElement: FakeElement, jq: jq, runView: runView };
