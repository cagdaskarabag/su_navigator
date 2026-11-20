require([
    "jquery",
    "../app/sunavigator/ucm_common",
    "splunkjs/mvc/simplexml/ready!"
], function ($, ucm) {
    "use strict";
    var el = ucm.el;
    var root = document.getElementById("ucm-dashboards");
    var data = { templates: [], dashboards: [] };
    var form = { template: "", params: {} };

    function notice(target, kind, title, message) {
        ucm.clear(target).appendChild(ucm.stateBox(kind, title, message || ""));
    }

    function load() {
        ucm.get("dashboards").done(function (d) {
            data = d;
            if (!form.template && d.templates.length) { form.template = d.templates[0].id; }
            render();
        }).fail(function (err) { notice(root, "error", "Could not load dashboards.", err.message); });
    }

    function paramInputs(tpl) {
        return (tpl.params || []).map(function (p) {
            var s = el("select", { "class": "ucm-input", onchange: function () { form.params[p.name] = s.value; } },
                p.required ? null : el("option", { value: "", text: "All domains" }),
                (p.choices || []).map(function (c) { return el("option", { value: c, text: c.replace("_", " ") }); }));
            if (form.params[p.name] === undefined) { form.params[p.name] = p.required ? (p.choices || [""])[0] : ""; }
            s.value = form.params[p.name];
            return el("div", {}, el("label", { "class": "ucm-sub", text: p.name + (p.required ? " (required)" : "") }), s);
        });
    }

    function render() {
        ucm.clear(root);
        root.appendChild(el("div", { "class": "ucm-header" }, el("h2", { text: "Generated dashboards" }),
            el("div", { "class": "ucm-sub", text: "Create Simple XML dashboards from fixed templates. Dashboards are written into this app, marked as generated, and can be regenerated or removed here. Creating or removing one needs the deployment capability." })));
        var tpl = data.templates.filter(function (t) { return t.id === form.template; })[0];
        var status = el("div", {});
        var previewBox = el("div", {});
        var templateSelect = el("select", { "class": "ucm-input", onchange: function () {
            form.template = templateSelect.value; form.params = {}; render();
        } }, data.templates.map(function (t) { return el("option", { value: t.id, text: t.title }); }));
        templateSelect.value = form.template;
        root.appendChild(el("div", { "class": "ucm-panel ucm-form" },
            el("h3", { text: "New dashboard" }),
            el("div", {}, el("label", { "class": "ucm-sub", text: "Template" }), templateSelect),
            tpl ? el("div", { "class": "ucm-sub", text: tpl.description }) : null,
            tpl ? paramInputs(tpl) : null,
            el("div", { "class": "ucm-toolbar" },
                el("button", { "class": "btn", type: "button", text: "Preview", onclick: function () {
                    ucm.post("dashboards/preview", { template: form.template, params: form.params }).done(function (p) {
                        ucm.clear(previewBox).appendChild(el("div", {},
                            el("div", { "class": "ucm-sub" }, "View name ", el("span", { "class": "ucm-mono", text: p.name })),
                            el("pre", { "class": "ucm-pre ucm-mono", text: p.xml })));
                    }).fail(function (err) { notice(status, "error", "Preview failed.", err.message); });
                } }),
                el("button", { "class": "btn btn-primary", type: "button", text: "Create or regenerate", onclick: function () {
                    ucm.post("dashboards/create", { template: form.template, params: form.params }).done(function (r) {
                        notice(status, "ok", "Dashboard " + r.dashboard.name + " saved.", "");
                        load();
                    }).fail(function (err) { notice(status, "error", "Could not save the dashboard.", err.message); });
                } })),
            status, previewBox));
        if (!data.dashboards.length) {
            root.appendChild(ucm.stateBox("empty", "No generated dashboards yet.", "Pick a template above and create one."));
            return;
        }
        var body = el("tbody", {});
        data.dashboards.forEach(function (d) {
            body.appendChild(el("tr", {},
                el("td", { "class": "ucm-title" }, el("a", { href: d.name, text: d.label }), el("div", { "class": "ucm-sub ucm-mono", text: d.name })),
                el("td", { text: d.template }),
                el("td", { text: (d.updated_at || "") + " by " + (d.updated_by || "") }),
                el("td", {}, el("button", { "class": "btn", type: "button", text: "Regenerate", onclick: function () {
                    ucm.post("dashboards/create", { template: d.template, params: d.params || {} }).done(load)
                        .fail(function (err) { notice(status, "error", "Could not regenerate.", err.message); });
                } }), " ", el("button", { "class": "btn", type: "button", text: "Delete", onclick: function () {
                    if (!window.confirm("Delete dashboard " + d.name + "?")) { return; }
                    ucm.post("dashboards/delete", { name: d.name }).done(load)
                        .fail(function (err) { notice(status, "error", "Could not delete.", err.message); });
                } }))));
        });
        root.appendChild(el("h3", { text: "Existing generated dashboards" }));
        root.appendChild(el("table", { "class": "ucm-table" }, el("thead", {}, el("tr", {},
            ["Dashboard", "Template", "Updated (UTC)", ""].map(function (h) { return el("th", { text: h }); }))), body));
    }

    load();
});
