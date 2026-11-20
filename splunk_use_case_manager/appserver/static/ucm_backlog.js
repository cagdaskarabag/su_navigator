require([
    "jquery",
    "../app/splunk_use_case_manager/ucm_common",
    "splunkjs/mvc/simplexml/ready!"
], function ($, ucm) {
    "use strict";
    var el = ucm.el;
    var root = document.getElementById("ucm-backlog");

    function load() {
        ucm.get("selections", { intent: "backlog", count: 200 }).done(function (data) {
            render(data.items || []);
        }).fail(function (err) {
            ucm.clear(root).appendChild(ucm.stateBox("error", "Could not load backlog.", err.message));
        });
    }

    function render(items) {
        ucm.clear(root);
        root.appendChild(el("div", { "class": "ucm-header" }, el("h2", { text: "Backlog" }),
            el("div", { "class": "ucm-sub", text: "Use cases you have selected or deferred. Bookmarks are not listed here." })));
        if (!items.length) {
            root.appendChild(ucm.stateBox("empty", "Your backlog is empty.",
                "Open a use case from the catalogue and choose Select or Defer."));
            return;
        }
        var head = el("tr", {});
        ["Priority", "Use case", "Intent", "Readiness", "Notes", ""].forEach(function (h) {
            head.appendChild(el("th", { text: h }));
        });
        var body = el("tbody", {});
        items.forEach(function (it) {
            body.appendChild(el("tr", {},
                el("td", { text: String(it.priority) }),
                el("td", { "class": "ucm-title" },
                    el("a", { href: "ucm_usecase?id=" + encodeURIComponent(it.content_id), text: it.title || it.content_id }),
                    el("div", { "class": "ucm-sub ucm-mono", text: it.content_id }),
                    ucm.criticalityBadge(it.criticality)),
                el("td", {}, ucm.badge(it.intent, it.intent === "select" ? "ok" : "warn")),
                el("td", {}, it.readiness_state ? ucm.readinessBadge(it.readiness_state) : ucm.badge("not assessed", "neutral")),
                el("td", { "class": "ucm-sub", text: it.notes || "" }),
                el("td", {}, el("button", { "class": "btn", type: "button", text: "Remove", onclick: function () {
                    ucm.post("selections/delete", { id: it.content_id }).done(load);
                } }))));
        });
        root.appendChild(el("table", { "class": "ucm-table" }, el("thead", {}, head), body));
    }

    load();
});
