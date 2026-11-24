require([
    "jquery",
    "../app/sunavigator/ucm_common",
    "splunkjs/mvc/simplexml/ready!"
], function ($, ucm) {
    "use strict";
    var el = ucm.el;
    var root = document.getElementById("ucm-catalogue");
    var PAGE = 25;
    var initial = ucm.queryParams();
    var state = {
        q: initial.q || "", domain: initial.domain || "", category: initial.category || "",
        criticality: initial.criticality || "", difficulty: initial.difficulty || "",
        sourcetype: initial.sourcetype || "", mitre: initial.mitre || "", sort: initial.sort || "id",
        offset: parseInt(initial.offset || "0", 10) || 0
    };
    var categories = [];
    var selections = {};
    var requestSeq = 0;
    var results = el("div", { "class": "ucm-results" });

    function select(name, label, options, value) {
        var sel = el("select", { name: name, "aria-label": label,
            onchange: function () { state[name] = sel.value; state.offset = 0; load(); } },
            el("option", { value: "", text: "All" }));
        options.forEach(function (opt) {
            var o = el("option", { value: opt.value, text: opt.label });
            if (opt.value === value) { o.selected = true; }
            sel.appendChild(o);
        });
        return el("div", { "class": "ucm-field" }, el("label", { text: label }), sel);
    }

    function textInput(name, label, placeholder, cls) {
        var input = el("input", { type: "text", name: name, value: state[name], placeholder: placeholder,
            "class": cls || "", maxlength: "200", "aria-label": label });
        input.addEventListener("input", ucm.debounce(function () {
            state[name] = input.value.trim(); state.offset = 0; load();
        }, 350));
        return el("div", { "class": "ucm-field" }, el("label", { text: label }), input);
    }

    function opts(values) { return values.map(function (v) { return { value: v, label: v }; }); }

    function toolbar() {
        var sortSel = select("sort", "Sort", [
            { value: "criticality", label: "Criticality" }, { value: "title", label: "Title" },
            { value: "imported", label: "Recently imported" }], state.sort);
        sortSel.querySelector("option").textContent = "ID";
        sortSel.querySelector("option").value = "id";
        return el("div", { "class": "ucm-toolbar" },
            textInput("q", "Search", "Title, id, sourcetype, MITRE id…", "ucm-search"),
            select("domain", "Domain", opts(ucm.DOMAINS), state.domain),
            select("category", "Category", categories.map(function (c) {
                return { value: c._key, label: c.category_id + ". " + c.name };
            }), state.category),
            select("criticality", "Criticality", opts(ucm.CRITICALITY), state.criticality),
            select("difficulty", "Difficulty", opts(ucm.DIFFICULTY), state.difficulty),
            textInput("sourcetype", "Sourcetype (exact)", "e.g. WinEventLog:Security"),
            textInput("mitre", "MITRE ATT&CK id", "e.g. T1110"),
            sortSel);
    }

    function row(item) {
        var href = "ucm_usecase?id=" + encodeURIComponent(item._key);
        return el("tr", {},
            el("td", { "class": "ucm-mono", text: item.record_id }),
            el("td", { "class": "ucm-title" },
                el("a", { href: href, text: item.title }),
                el("div", { "class": "ucm-sub", text: item.summary || "" })),
            el("td", {}, ucm.chips(item.domains, 3)),
            el("td", {}, el("div", { text: item.category_name || "" }),
                el("div", { "class": "ucm-sub", text: item.subcategory || "" })),
            el("td", {}, ucm.criticalityBadge(item.criticality)),
            el("td", { text: item.difficulty || "" }),
            el("td", { "class": "ucm-mono" }, ucm.chips(item.sourcetypes, 3)),
            el("td", { "class": "ucm-mono" }, ucm.chips(item.mitre_ids, 3)),
            el("td", {}, ucm.badge(item.review_status || "unknown", "info")),
            el("td", {},
                selections[item.content_id] ? ucm.badge(selections[item.content_id].intent, "ok") : null,
                el("button", { "class": "btn", type: "button", text: "Select", onclick: function (e) {
                    e.preventDefault();
                    ucm.post("selections", { id: item.content_id, intent: "select" }).done(function () {
                        loadSelections().done(load);
                    }).fail(function (err) { ucm.notify(err.message); });
                } })));
    }

    function renderResults(data) {
        ucm.clear(results);
        if (!data.items.length) {
            var filtered = state.q || state.domain || state.category || state.criticality ||
                state.difficulty || state.sourcetype || state.mitre;
            results.appendChild(filtered
                ? ucm.stateBox("empty", "No use cases match these filters.", "Clear one or more filters to widen the search.")
                : el("div", {}, ucm.stateBox("empty", "No content has been imported yet.",
                    "Synchronize categories from the provider or import an offline bundle."),
                    el("a", { href: "ucm_content_admin", "class": "btn btn-primary", text: "Open Content Administration" })));
            return;
        }
        var total = data.total === null ? "" : data.total + " use cases";
        results.appendChild(el("div", { "class": "ucm-summary-line", text: total }));
        var head = el("tr", {});
        ["ID", "Use case", "Domains", "Category", "Criticality", "Difficulty", "Sourcetypes (from SPL)", "MITRE", "Review", "Backlog"]
            .forEach(function (h) { head.appendChild(el("th", { text: h })); });
        var body = el("tbody", {});
        data.items.forEach(function (item) { body.appendChild(row(item)); });
        results.appendChild(el("table", { "class": "ucm-table" }, el("thead", {}, head), body));
        results.appendChild(ucm.pager(data.offset, data.count, data.total, data.has_more, function (offset) {
            state.offset = offset; load(); window.scrollTo(0, 0);
        }));
    }

    function load() {
        var seq = ++requestSeq;
        ucm.setQueryParams(state);
        ucm.clear(results).appendChild(el("div", { "class": "ucm-loading", text: "Loading…" }));
        var params = { offset: state.offset, count: PAGE, sort: state.sort };
        ["q", "domain", "category", "criticality", "difficulty", "sourcetype", "mitre"].forEach(function (k) {
            if (state[k]) { params[k] = state[k]; }
        });
        ucm.get("catalog", params).done(function (data) {
            if (seq === requestSeq) { renderResults(data); }
        }).fail(function (err) {
            if (seq !== requestSeq) { return; }
            ucm.clear(results).appendChild(ucm.stateBox("error", "The catalogue could not be loaded.", err.message));
        });
    }

    function loadSelections() {
        return ucm.get("selections", { count: 500 }).done(function (data) {
            selections = {};
            (data.items || []).forEach(function (s) { selections[s.content_id] = s; });
        });
    }

    ucm.get("categories").always(function (data) {
        categories = (data && data.categories) || [];
        ucm.clear(root);
        root.appendChild(toolbar());
        root.appendChild(results);
        loadSelections().always(load);
    });
});
