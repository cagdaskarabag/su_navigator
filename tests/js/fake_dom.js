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

module.exports = { loadAmd: loadAmd, FakeElement: FakeElement, jq: jq };
