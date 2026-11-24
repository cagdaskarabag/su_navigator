"use strict";
/* Reads a JSON array of SPL strings on stdin, prints what the browser guard finds for each. */
var loadAmd = require("./fake_dom").loadAmd;
var ucm = loadAmd("ucm_common.js");
var input = "";
process.stdin.on("data", function (d) { input += d; });
process.stdin.on("end", function () {
    var out = JSON.parse(input).map(function (spl) {
        var p = ucm.splPolicy(spl);
        return { commands: p.commands, side: p.sideEffects, indirect: p.indirect, nested: p.nested, hidden: p.hidden, macros: p.hasMacros };
    });
    process.stdout.write(JSON.stringify(out));
});
