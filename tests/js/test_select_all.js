"use strict";
var assert = require("assert");
var loadAmd = require("./fake_dom").loadAmd;
var ucm = loadAmd("ucm_common.js");

function boxes(n, disabledIdx) {
    var out = [];
    for (var i = 0; i < n; i++) {
        var b = ucm.el("input", { type: "checkbox", value: String(i) });
        if (disabledIdx && disabledIdx.indexOf(i) >= 0) { b.disabled = true; }
        out.push(b);
    }
    return out;
}
function toggle(box, value) { box.checked = value; box.dispatch("change"); }
function checked(bs) { return bs.map(function (b) { return b.checked; }); }

var tests = {
    "none selected": function () {
        var bs = boxes(3), s = ucm.selectAll(bs, "categories");
        assert.strictEqual(s.header.checked, false);
        assert.strictEqual(s.header.indeterminate, false);
        assert.strictEqual(s.count.textContent, "0 of 3 categories selected");
        assert.strictEqual(s.deselectAllButton.disabled, true);
        assert.strictEqual(s.selectAllButton.disabled, false);
    },
    "some selected is indeterminate": function () {
        var bs = boxes(3), s = ucm.selectAll(bs, "categories");
        toggle(bs[1], true);
        assert.strictEqual(s.header.indeterminate, true);
        assert.strictEqual(s.header.checked, false);
        assert.strictEqual(s.count.textContent, "1 of 3 categories selected");
    },
    "all selected": function () {
        var bs = boxes(3), s = ucm.selectAll(bs, "categories");
        bs.forEach(function (b) { toggle(b, true); });
        assert.strictEqual(s.header.checked, true);
        assert.strictEqual(s.header.indeterminate, false);
        assert.strictEqual(s.selectAllButton.disabled, true);
    },
    "header toggles everything on and off": function () {
        var bs = boxes(4), s = ucm.selectAll(bs, "categories");
        s.header.checked = true; s.header.dispatch("change");
        assert.deepStrictEqual(checked(bs), [true, true, true, true]);
        s.header.checked = false; s.header.dispatch("change");
        assert.deepStrictEqual(checked(bs), [false, false, false, false]);
    },
    "buttons": function () {
        var bs = boxes(2), s = ucm.selectAll(bs, "categories");
        s.selectAllButton.dispatch("click");
        assert.deepStrictEqual(checked(bs), [true, true]);
        s.deselectAllButton.dispatch("click");
        assert.deepStrictEqual(checked(bs), [false, false]);
    },
    "disabled boxes are never changed": function () {
        var bs = boxes(3, [1]), s = ucm.selectAll(bs, "categories");
        s.selectAllButton.dispatch("click");
        assert.deepStrictEqual(checked(bs), [true, false, true]);
        assert.strictEqual(s.header.indeterminate, true);
        bs[1].checked = true; bs[1].disabled = true; s.sync();
        s.deselectAllButton.dispatch("click");
        assert.deepStrictEqual(checked(bs), [false, true, false]);
    },
    "all boxes disabled disables the header": function () {
        var bs = boxes(2, [0, 1]), s = ucm.selectAll(bs, "categories");
        assert.strictEqual(s.header.disabled, true);
    },
    "preselected state is respected when re-rendered": function () {
        var bs = boxes(3); bs[0].checked = true; bs[2].checked = true;
        var s = ucm.selectAll(bs, "categories");
        assert.strictEqual(s.header.indeterminate, true);
        assert.strictEqual(s.count.textContent, "2 of 3 categories selected");
        var again = ucm.selectAll(bs, "categories");
        assert.deepStrictEqual(checked(bs), [true, false, true]);
        assert.strictEqual(again.count.textContent, s.count.textContent);
    },
    "onChange receives the selected count": function () {
        var bs = boxes(2), seen = [];
        ucm.selectAll(bs, "categories", function (n) { seen.push(n); });
        toggle(bs[0], true);
        assert.deepStrictEqual(seen, [0, 1]);
    },
    "no boxes": function () {
        var s = ucm.selectAll([], "categories");
        assert.strictEqual(s.header.checked, false);
        assert.strictEqual(s.header.disabled, true);
        assert.strictEqual(s.count.textContent, "0 of 0 categories selected");
    }
};

var failed = 0;
Object.keys(tests).forEach(function (name) {
    try { tests[name](); console.log("ok   " + name); } catch (e) { failed++; console.log("FAIL " + name + ": " + e.message); }
});
process.exit(failed ? 1 : 0);
