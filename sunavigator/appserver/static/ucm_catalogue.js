/*
 * ucm_common.js is requested from the same static directory as ucm.css, which the dashboard
 * XML loads under /static/@<build>.<push>-<app build>/... and so carries the app build.
 * A relative module id ("../app/sunavigator/ucm_common") or splunk.util.make_url (which
 * always writes app build 0) would leave it cached for a year across upgrades.
 */
var ucmCommonUrl = (function () {
    var links = document.querySelectorAll('link[href*="/app/sunavigator/ucm.css"]');
    return links.length ? links[0].href.replace(/ucm\.css([?#].*)?$/, "ucm_common.js") : "../app/sunavigator/ucm_common";
}());

require(["jquery", ucmCommonUrl, "splunkjs/mvc/simplexml/ready!"], ucmViewMain);

function ucmViewMain($, ucm) {
    "use strict";
    var el = ucm.el;
    var root = document.getElementById("ucm-catalogue");
    var PAGE = 25;
    var initial = ucm.queryParams();
    var MULTI = ["provider", "domain", "category", "wave", "criticality", "difficulty", "availability", "review", "quality",
        "exclude_quality", "regulation", "story", "data_source"];
    var FILTER_NAMES = { story: "analytic story", data_source: "data source", exclude_quality: "hide quality flag" };
    var NUMBERED_PROVIDERS = ["fenre"];
    var WAVES = ["crawl", "walk", "run"];
    var LONG_LISTS = ["story", "data_source"];
    var TEXT = ["q", "sourcetype", "mitre"];
    var AVAILABILITY = ucm.READINESS_STATES.concat(["not_assessed"]);
    var state = { sort: initial.sort || "id", offset: parseInt(initial.offset || "0", 10) || 0,
        bookmarked: initial.bookmarked === "1" };
    MULTI.forEach(function (k) { state[k] = initial[k] ? initial[k].split(",").filter(Boolean) : []; });
    TEXT.forEach(function (k) { state[k] = initial[k] || ""; });
    var categories = [];
    var facets = { review_statuses: [], regulations: [], quality_flags: [], domains: {}, categories: {}, criticality: {},
        difficulty: {}, providers: {}, waves: {}, analytic_stories: [], data_sources: [], summary: null, active: 0 };
    var assessment = null;
    var selections = {};
    var requestSeq = 0;
    var results = el("div", { "class": "ucm-results" });
    var activeBar = el("div", { "class": "ucm-active-filters" });
    var boxes = [];
    var textInputs = [];
    var summaries = [];

    function countText(n) { return n === undefined || n === null ? "" : " (" + n + ")"; }

    function options(key) {
        function fromMap(values, map) {
            return values.map(function (v) { return { value: v, label: v, count: (map || {})[v] || 0 }; });
        }
        function fromList(list, selected) {
            var out = (list || []).map(function (r) { return { value: r.id, label: r.id, count: r.count }; });
            selected.forEach(function (v) {
                if (!out.some(function (o) { return o.value === v; })) { out.push({ value: v, label: v, count: 0 }); }
            });
            return out;
        }
        if (key === "provider") {
            var ids = Object.keys(facets.providers || {});
            categories.forEach(function (c) { if (c.provider && ids.indexOf(c.provider) < 0) { ids.push(c.provider); } });
            state.provider.forEach(function (p) { if (ids.indexOf(p) < 0) { ids.push(p); } });
            return ids.sort().map(function (p) {
                return { value: p, label: ucm.providerLabel(p), count: (facets.providers || {})[p] || 0 };
            });
        }
        if (key === "wave") { return fromMap(WAVES, facets.waves); }
        if (key === "story") { return fromList(facets.analytic_stories, state.story); }
        if (key === "data_source") { return fromList(facets.data_sources, state.data_source); }
        if (key === "exclude_quality") {
            return Object.keys(ucm.QUALITY_FLAGS).map(function (k) {
                var f = (facets.quality_flags || []).filter(function (q) { return q.id === k; })[0];
                return { value: k, label: ucm.QUALITY_FLAGS[k][0], count: f ? f.count : 0, title: ucm.QUALITY_FLAGS[k][1] };
            });
        }
        if (key === "domain") { return fromMap(ucm.DOMAINS, facets.domains); }
        if (key === "criticality") { return fromMap(ucm.CRITICALITY, facets.criticality); }
        if (key === "difficulty") { return fromMap(ucm.DIFFICULTY, facets.difficulty); }
        if (key === "review") {
            return (facets.review_statuses || []).map(function (r) { return { value: r.id, label: r.id, count: r.count }; });
        }
        if (key === "regulation") {
            return (facets.regulations || []).map(function (r) { return { value: r.id, label: r.label, count: r.count }; });
        }
        if (key === "quality") {
            return Object.keys(ucm.QUALITY_FLAGS).map(function (k) {
                var f = (facets.quality_flags || []).filter(function (q) { return q.id === k; })[0];
                return { value: k, label: ucm.QUALITY_FLAGS[k][1], count: f ? f.count : 0 };
            });
        }
        if (key === "availability") {
            var by = assessment && assessment.by_state;
            var assessed = 0;
            if (by) { ucm.READINESS_STATES.forEach(function (s) { assessed += by[s] || 0; }); }
            return AVAILABILITY.map(function (v) {
                var n;
                if (by) { n = v === "not_assessed" ? Math.max(0, (facets.active || 0) - assessed) : (by[v] || 0); }
                return { value: v, label: v.replace(/_/g, " "), count: n,
                    title: ucm.READINESS_HELP[v] || "No readiness result is stored for this use case yet." };
            });
        }
        return [];
    }

    function providersPresent() {
        var ids = Object.keys(facets.providers || {}).filter(function (p) { return facets.providers[p] > 0; });
        if (!ids.length) {
            categories.forEach(function (c) { if (c.provider && ids.indexOf(c.provider) < 0) { ids.push(c.provider); } });
        }
        return ids;
    }

    /* "Fenre · 9. Identity & Access Management", "ESCU · Endpoint": the provider is named only when the catalogue holds several. */
    function categoryLabel(cat, qualify) {
        var numbered = cat.category_id && (!qualify || NUMBERED_PROVIDERS.indexOf(cat.provider) >= 0);
        var plain = (numbered ? cat.category_id + ". " : "") + cat.name;
        return qualify && cat.provider ? ucm.providerLabel(cat.provider) + " \u00b7 " + plain : plain;
    }

    function categoryGroups() {
        var groups = {};
        var qualify = providersPresent().length > 1;
        categories.slice().sort(function (a, b) {
            var pa = a.provider || "", pb = b.provider || "";
            return pa < pb ? -1 : pa > pb ? 1 : (parseInt(a.category_id, 10) || 0) - (parseInt(b.category_id, 10) || 0);
        }).forEach(function (cat) {
            var key = cat._key || cat.key;
            var domain = (cat.domains && cat.domains[0]) || "other";
            (groups[domain] = groups[domain] || []).push({ value: key, label: categoryLabel(cat, qualify),
                count: (facets.categories || {})[key] || 0 });
        });
        var order = ucm.DOMAINS.concat(Object.keys(groups).filter(function (d) { return ucm.DOMAINS.indexOf(d) < 0; }));
        return order.filter(function (d) { return groups[d]; }).map(function (d) {
            return { domain: d, total: (facets.domains || {})[d], items: groups[d] };
        });
    }

    function labelFor(key, value) {
        var all = key === "category"
            ? [].concat.apply([], categoryGroups().map(function (g) { return g.items; })) : options(key);
        var found = all.filter(function (o) { return o.value === value; })[0];
        return found ? found.label : value;
    }

    function toggle(key, value, on) {
        var i = state[key].indexOf(value);
        if (on && i < 0) { state[key].push(value); }
        if (!on && i >= 0) { state[key].splice(i, 1); }
        changed();
    }

    function changed() {
        state.offset = 0;
        refreshFilters();
        load();
    }

    function checkbox(key, o) {
        var box = el("input", { type: "checkbox", value: o.value, "aria-label": o.label });
        box.checked = state[key].indexOf(o.value) >= 0;
        box.addEventListener("change", function () { toggle(key, o.value, box.checked); });
        boxes.push({ key: key, value: o.value, node: box });
        return el("label", { "class": "ucm-check", title: o.title || null }, box, " ", o.label,
            o.count === undefined ? null : el("span", { "class": "ucm-sub", text: countText(o.count) }));
    }

    function facetGroup(key, label, help) {
        var summary = el("summary", {});
        var details = el("details", { "class": "ucm-facet" }, summary);
        var body = el("div", { "class": "ucm-facet-body" });
        details.appendChild(body);
        if (help) { body.appendChild(el("div", { "class": "ucm-sub", text: help })); }
        if (key === "category") {
            var groups = categoryGroups();
            if (!groups.length) { body.appendChild(el("div", { "class": "ucm-sub", text: "No categories imported." })); }
            groups.forEach(function (g) {
                body.appendChild(el("div", { "class": "ucm-facet-group", text: g.domain + countText(g.total) }));
                g.items.forEach(function (o) { body.appendChild(checkbox(key, o)); });
            });
        } else {
            var rows = options(key).map(function (o) { return { option: o, node: checkbox(key, o) }; });
            if (LONG_LISTS.indexOf(key) >= 0 && rows.length > 12) {
                var finder = el("input", { type: "text", "class": "ucm-facet-find", placeholder: "Filter this list…",
                    "aria-label": "Filter the " + label + " list", maxlength: "100" });
                finder.addEventListener("input", function () {
                    var needle = finder.value.trim().toLowerCase();
                    rows.forEach(function (r) {
                        var show = !needle || r.option.label.toLowerCase().indexOf(needle) >= 0 || state[key].indexOf(r.option.value) >= 0;
                        if (show) { r.node.removeAttribute("hidden"); } else { r.node.setAttribute("hidden", "hidden"); }
                    });
                });
                body.appendChild(finder);
            }
            rows.forEach(function (r) { body.appendChild(r.node); });
            if (!rows.length) { body.appendChild(el("div", { "class": "ucm-sub", text: "No values yet." })); }
        }
        function update() {
            var n = state[key].length;
            summary.textContent = label + (n ? " (" + n + " selected)" : "");
            if (n) { details.setAttribute("open", "open"); }
        }
        summaries.push(update);
        update();
        return details;
    }

    function textInput(name, label, placeholder, cls) {
        var input = el("input", { type: "text", name: name, value: state[name], placeholder: placeholder,
            "class": cls || "", maxlength: "200", "aria-label": label });
        input.addEventListener("input", ucm.debounce(function () {
            state[name] = input.value.trim();
            changed();
        }, 350));
        textInputs.push({ name: name, node: input });
        return el("div", { "class": "ucm-field" }, el("label", { text: label }), input);
    }

    function sortSelect() {
        var sel = el("select", { name: "sort", "aria-label": "Sort", onchange: function () {
            state.sort = sel.value; state.offset = 0; load();
        } });
        [["id", "ID"], ["criticality", "Criticality"], ["title", "Title"], ["imported", "Recently imported"]].forEach(function (o) {
            var opt = el("option", { value: o[0], text: o[1] });
            if (o[0] === state.sort) { opt.selected = true; }
            sel.appendChild(opt);
        });
        return el("div", { "class": "ucm-field" }, el("label", { text: "Sort" }), sel);
    }

    function bookmarkToggle() {
        var box = el("input", { type: "checkbox", name: "bookmarked", "aria-label": "Only my bookmarks" });
        box.checked = state.bookmarked;
        box.addEventListener("change", function () { state.bookmarked = box.checked; changed(); });
        boxes.push({ key: "bookmarked", node: box });
        return el("label", { "class": "ucm-check ucm-bookmark-filter",
            title: "Shows only the use cases you bookmarked. Other users' bookmarks are never included." },
            box, " Only my bookmarks");
    }

    function summaryOutdated() {
        var sm = facets.summary;
        return sm && sm.outdated > 0 ? sm : null;
    }

    function reindexHint() {
        return ucm.reindexHint(facets.summary, facets.active,
            el("div", {}, el("a", { href: "ucm_content_admin", text: "Open Content Administration" }),
                el("span", { "class": "ucm-sub", text: " (Reindex needs the ucm_content_manager role)" })));
    }

    function toolbar() {
        return el("div", {},
            el("div", { "class": "ucm-toolbar" },
                textInput("q", "Search", "Title, description, id, sourcetype, MITRE id…", "ucm-search"),
                textInput("sourcetype", "Sourcetype (exact)", "e.g. WinEventLog:Security"),
                textInput("mitre", "MITRE ATT&CK id", "e.g. T1110"),
                sortSelect(), bookmarkToggle()),
            reindexHint(),
            el("div", { "class": "ucm-facets" },
                facetGroup("provider", "Provider", "Where the use case comes from. A twin has the same primary SPL in another provider."),
                facetGroup("domain", "Domain"),
                facetGroup("category", "Category", "Grouped by domain; a category is listed under its first domain. " +
                    "Category ids are the providers' own: Fenre numbers 1 to 25, ESCU categories are Endpoint, Network, Threat, " +
                    "Identity, Access, Audit and Unassigned. Use Analytic story or Data source to find ESCU detections in Unassigned."),
                facetGroup("wave", "Maturity wave", "Fenre rollout order: crawl first, then walk, then run. ESCU has no wave."),
                facetGroup("criticality", "Criticality"),
                facetGroup("difficulty", "Difficulty"),
                facetGroup("availability", "Availability",
                    "Readiness state from the last assessment. Not assessed means no result is stored yet."),
                facetGroup("review", "Review status"),
                facetGroup("quality", "Quality flag"),
                facetGroup("exclude_quality", "Hide quality flag", "Leaves out use cases that carry the flag. Nothing is hidden by default."),
                facetGroup("regulation", "Regulation"),
                facetGroup("story", "Analytic story", "ESCU analytic stories. Fenre use cases have none."),
                facetGroup("data_source", "Data source", "ESCU data sources, as named by the content update. Fenre use cases have none.")),
            el("div", { "class": "ucm-sub", text: "Counts next to each value are for the whole catalogue, not for the other filters you chose." }),
            activeBar);
    }

    function activeFilters() {
        var out = [];
        MULTI.forEach(function (k) {
            state[k].forEach(function (v) { out.push({ key: k, value: v, label: (FILTER_NAMES[k] || k) + ": " + labelFor(k, v) }); });
        });
        TEXT.forEach(function (k) { if (state[k]) { out.push({ key: k, label: k + ": " + state[k], text: true }); } });
        if (state.bookmarked) { out.push({ key: "bookmarked", label: "only my bookmarks", flag: true }); }
        return out;
    }

    function refreshFilters() {
        summaries.forEach(function (u) { u(); });
        boxes.forEach(function (b) {
            b.node.checked = b.key === "bookmarked" ? state.bookmarked : state[b.key].indexOf(b.value) >= 0;
        });
        textInputs.forEach(function (t) { if (t.node.value.trim() !== state[t.name]) { t.node.value = state[t.name]; } });
        ucm.clear(activeBar);
        var list = activeFilters();
        if (!list.length) { return; }
        list.forEach(function (f) {
            activeBar.appendChild(el("button", { "class": "ucm-chip-button", type: "button", title: "Remove this filter",
                onclick: function () {
                    if (f.text) { state[f.key] = ""; changed(); }
                    else if (f.flag) { state.bookmarked = false; changed(); }
                    else { toggle(f.key, f.value, false); }
                } }, f.label + " ×"));
        });
        activeBar.appendChild(el("button", { "class": "btn", type: "button", text: "Clear all filters", onclick: function () {
            MULTI.forEach(function (k) { state[k] = []; });
            TEXT.forEach(function (k) { state[k] = ""; });
            state.bookmarked = false;
            changed();
        } }));
    }

    function saveSelection(item, intent) {
        ucm.post("selections", { id: item.content_id, intent: intent }).done(function () {
            loadSelections().done(load);
        }).fail(function (err) { ucm.notify(err.message); });
    }

    function removeSelection(item) {
        ucm.post("selections/delete", { id: item.content_id }).done(function () {
            loadSelections().done(load);
        }).fail(function (err) { ucm.notify(err.message); });
    }

    function actions(item) {
        var current = selections[item.content_id];
        return el("td", {},
            current ? ucm.badge(current.intent, "ok") : null,
            current && current.intent === "bookmark"
                ? el("button", { "class": "btn", type: "button", text: "Remove bookmark", onclick: function (e) {
                    e.preventDefault(); removeSelection(item);
                } }) : null,
            current ? null : el("button", { "class": "btn", type: "button", text: "Bookmark", onclick: function (e) {
                e.preventDefault(); saveSelection(item, "bookmark");
            } }),
            el("button", { "class": "btn", type: "button", text: "Select", onclick: function (e) {
                e.preventDefault(); saveSelection(item, "select");
            } }));
    }

    function row(item) {
        var href = "ucm_usecase?id=" + encodeURIComponent(item._key);
        return el("tr", {},
            el("td", { "class": "ucm-mono" }, ucm.providerBadge(item.provider), " ", item.record_id),
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
            el("td", {}, ucm.badge(item.review_status || "unknown", "info"), ucm.qualityBadges(item.quality_flags)),
            actions(item));
    }

    function renderResults(data) {
        ucm.clear(results);
        if (!data.items.length) {
            var filtered = activeFilters().length > 0;
            var degraded = summaryOutdated() && (state.wave.length || state.story.length || state.data_source.length);
            if (degraded) {
                results.appendChild(ucm.stateBox("warn", "Some use cases cannot match this filter yet",
                    "Use cases summarised before 0.9.0 carry no wave, analytic story or data source until Reindex runs " +
                    "(" + summaryOutdated().outdated + " of " + (facets.active || 0) + " are affected)."));
            }
            results.appendChild(filtered
                ? ucm.stateBox("empty", state.bookmarked && activeFilters().length === 1
                    ? "You have not bookmarked any use case yet." : "No use cases match these filters.",
                    state.bookmarked && activeFilters().length === 1
                        ? "Use Bookmark on a row to keep a use case here."
                        : "Clear one or more filters to widen the search.")
                : el("div", {}, ucm.stateBox("empty", "No content has been imported yet.",
                    "Synchronize categories from the provider or import an offline bundle."),
                    el("a", { href: "ucm_content_admin", "class": "btn btn-primary", text: "Open Content Administration" })));
            return;
        }
        var total = data.total === null ? "" : data.total + (data.total_capped ? " or more" : "") + " use cases";
        results.appendChild(el("div", { "class": "ucm-summary-line", text: total }));
        if (data.total_capped) {
            results.appendChild(ucm.stateBox("warn", "This total is a lower bound",
                "The KV Store returns at most " + data.total + " rows per query, so the catalogue may hold more " +
                "use cases than are counted. See Administration and the operator guide, section 12."));
        }
        var head = el("tr", {});
        ["ID", "Use case", "Domains", "Category", "Criticality", "Difficulty", "Sourcetypes (from SPL)", "MITRE", "Review and quality", "Your selection"]
            .forEach(function (h) { head.appendChild(el("th", { text: h })); });
        var body = el("tbody", {});
        data.items.forEach(function (item) { body.appendChild(row(item)); });
        results.appendChild(el("table", { "class": "ucm-table" }, el("thead", {}, head), body));
        results.appendChild(ucm.pager(data.offset, data.count, data.total, data.has_more, function (offset) {
            state.offset = offset; load(); window.scrollTo(0, 0);
        }));
    }

    function persist() {
        var out = { sort: state.sort, offset: state.offset, bookmarked: state.bookmarked ? "1" : "" };
        MULTI.forEach(function (k) { out[k] = state[k].join(","); });
        TEXT.forEach(function (k) { out[k] = state[k]; });
        ucm.setQueryParams(out);
    }

    function load() {
        var seq = ++requestSeq;
        persist();
        ucm.clear(results).appendChild(el("div", { "class": "ucm-loading", text: "Loading…" }));
        var params = { offset: state.offset, count: PAGE, sort: state.sort };
        MULTI.forEach(function (k) { if (state[k].length) { params[k] = state[k].join(","); } });
        TEXT.forEach(function (k) { if (state[k]) { params[k] = state[k]; } });
        if (state.bookmarked) { params.bookmarked = "1"; }
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

    ucm.get("categories").done(function (data) { categories = (data && data.categories) || []; }).always(function () {
        ucm.get("catalog/facets").done(function (f) {
            Object.keys(f || {}).forEach(function (k) { if (f[k] !== null && f[k] !== undefined) { facets[k] = f[k]; } });
        }).always(function () {
            ucm.get("readiness/summary").done(function (s) { assessment = s; }).always(function () {
                ucm.clear(root);
                root.appendChild(toolbar());
                root.appendChild(results);
                refreshFilters();
                loadSelections().always(load);
            });
        });
    });
}
