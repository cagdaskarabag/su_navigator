require([
    "jquery",
    "../app/sunavigator/ucm_common",
    "splunkjs/mvc/simplexml/ready!"
], function ($, ucm) {
    "use strict";
    var el = ucm.el;
    var root = document.getElementById("ucm-lantern");
    var LANTERN = "https://lantern.splunk.com/";
    var stepsBox = el("ol", { "class": "ucm-steps" });
    var formBox = el("div", { "class": "ucm-section" });
    var sessionBox = el("div", { "class": "ucm-section" });
    var previewBox = el("div", {});
    var confirmBox = el("div", {});
    var importedBox = el("div", { "class": "ucm-section" });
    var historyBox = el("div", { "class": "ucm-section" });
    var pollTimer = null;
    var session = null;
    var selected = {};
    var updates = {};
    var categoryFilter = "";

    var ERROR_TITLES = {
        invalid_lantern_url: "Invalid URL", lantern_not_found: "Page unavailable",
        lantern_unavailable: "Splunk Lantern unavailable", lantern_timeout: "Request timed out",
        lantern_robots_disallowed: "Not allowed by Lantern's robots.txt",
        lantern_redirect_rejected: "Redirect refused", lantern_not_html: "Not an HTML page",
        lantern_too_large: "Page too large", lantern_network_blocked: "Blocked network destination",
        lantern_tls_error: "TLS verification failed", lantern_rate_limited: "Rate limited by Lantern",
        lantern_parse_failed: "Parse failure", lantern_unsupported_page: "Unsupported page",
        lantern_request_limit: "Request limit reached", cancelled: "Cancelled", permission_denied: "Not permitted",
        conflict: "Busy or conflicting request", not_found: "Session not found or expired"
    };
    var STATUS_BADGES = {
        listed: ["not fetched", "neutral"], queued: ["queued", "info"], "new": ["new", "ok"],
        unchanged: ["already in SUN, unchanged", "neutral"], updated: ["update available", "warn"],
        collection: ["collection", "info"], error: ["error", "error"], imported: ["imported", "ok"],
        duplicate: ["duplicate", "neutral"], expanded: ["expanded", "info"]
    };

    function errorBox(err, fallback) {
        var code = (err && err.message && (err.message.match(/\(([a-z_]+)\)$/) || [])[1]) || err.code || "";
        return ucm.stateBox("error", ERROR_TITLES[code] || fallback || "Request failed", err.message || "");
    }

    function lanternLink(url, text) {
        return el("a", { href: url, target: "_blank", rel: "noopener noreferrer", text: text || url });
    }

    function itemStatus(item) {
        if (item.state === "error" || item.state === "imported" || item.state === "duplicate" ||
                item.state === "queued" || item.state === "expanded") { return item.state; }
        return item.status || "listed";
    }

    function statusBadge(item) {
        var l = STATUS_BADGES[itemStatus(item)] || [itemStatus(item), "neutral"];
        return ucm.badge(l[0], l[1]);
    }

    function renderSteps(active) {
        var labels = ["1. Paste URL", "2. Review page", "3. Select and preview", "4. Confirm import", "5. Done"];
        ucm.clear(stepsBox);
        labels.forEach(function (label, idx) {
            stepsBox.appendChild(el("li", { "class": idx < active ? "ucm-step-done" : (idx === active ? "ucm-step-active" : "") },
                label));
        });
    }

    function setSession(id) {
        var params = ucm.queryParams();
        params.session = id || "";
        ucm.setQueryParams(params);
    }

    // -- step 1: URL ----------------------------------------------------------------------------
    function renderForm(settings, prefill) {
        var input = el("input", { type: "url", "class": "ucm-input", maxlength: "2048", placeholder: LANTERN + "…",
            "aria-label": "Splunk Lantern URL" });
        var message = el("div", {});
        if (prefill) {
            input.value = prefill;
            message.appendChild(ucm.stateBox("info", "Check an imported article for updates",
                "Select Inspect page to retrieve the current version and compare it with the copy in SUN."));
        }
        var button = el("button", { "class": "btn btn-primary", type: "button", text: "Inspect page" });
        function submit() {
            var url = input.value.trim();
            ucm.clear(message);
            if (!/^https:\/\/lantern\.splunk\.com(\/|$)/i.test(url)) {
                message.appendChild(ucm.stateBox("error", "Invalid URL",
                    "Paste an https:// URL on lantern.splunk.com, for example " + LANTERN + "Splunk_and_Cisco_Use_Cases."));
                return;
            }
            button.disabled = true;
            ucm.post("lantern/inspect", { url: url }).done(function (res) {
                input.value = "";
                openSession(res.session);
            }).fail(function (err) {
                message.appendChild(errorBox(err, "The URL was not accepted"));
            }).always(function () { button.disabled = false; });
        }
        button.addEventListener("click", submit);
        input.addEventListener("keydown", function (ev) { if (ev.key === "Enter") { submit(); } });
        ucm.clear(formBox).appendChild(el("div", {},
            el("h3", { text: "Paste a Splunk Lantern URL" }),
            el("div", { "class": "ucm-sub", text: "Accepted: an article or a collection page on https://lantern.splunk.com. " +
                "SUN validates the address first, then the background worker retrieves the page (at most one request every " +
                settings.min_request_interval_seconds + " seconds, honouring Lantern's robots.txt). No credentials are needed." }),
            el("div", { "class": "ucm-actions" }, input, button), message));
        if (!settings.enabled || !settings.remote_fetch_enabled) {
            formBox.appendChild(ucm.stateBox("warn", "Lantern retrieval is disabled on this deployment.",
                "An administrator can enable it in ucm.conf [provider:lantern]. Previously imported Lantern content stays available."));
            button.disabled = true;
        }
    }

    // -- session ----------------------------------------------------------------------------------
    function openSession(s) {
        session = s;
        selected = {};
        updates = {};
        categoryFilter = "";
        setSession(s.session_id);
        ucm.clear(previewBox);
        ucm.clear(confirmBox);
        renderSession();
        schedulePoll();
    }

    function schedulePoll() {
        clearTimeout(pollTimer);
        if (session && (session.status === "queued" || session.status === "running")) {
            pollTimer = setTimeout(function () {
                ucm.get("lantern/session", { id: session.session_id }).done(function (res) {
                    session = res.session;
                    renderSession();
                    schedulePoll();
                    if (session.status !== "queued" && session.status !== "running") { renderHistory(); }
                }).fail(function (err) {
                    ucm.clear(sessionBox).appendChild(errorBox(err, "The import session could not be loaded"));
                });
            }, 3000);
        }
    }

    function renderProgress() {
        var p = session.progress || {};
        var pct = p.total ? Math.round(100 * (p.done || 0) / p.total) : 0;
        var phase = { inspect: "Retrieving and classifying the page", article: "Retrieving and extracting the selected articles",
            expand: "Listing the articles of the selected sub-collections" }[session.phase] || "Working";
        return el("div", { "class": "ucm-state ucm-state-info" },
            el("strong", { text: phase + "… " + (p.done || 0) + " of " + (p.total || 0) }),
            el("div", { "class": "ucm-progress" }, el("span", { style: "width:" + pct + "%" })),
            el("div", { "class": "ucm-sub", text: session.status === "queued"
                ? "Waiting for the background worker (it runs about once a minute)."
                : "Current page: " + (p.current || "") }),
            el("button", { "class": "btn", type: "button", text: "Cancel", onclick: function () {
                ucm.post("lantern/cancel", { id: session.session_id }).done(function (res) {
                    session = res.session; renderSession(); schedulePoll();
                });
            } }));
    }

    function renderSession() {
        ucm.clear(sessionBox);
        if (!session) { renderSteps(0); return; }
        var busy = session.status === "queued" || session.status === "running";
        var page = session.page;
        sessionBox.appendChild(el("h3", { text: "Import session" }));
        if (busy) { sessionBox.appendChild(renderProgress()); }
        if (session.inspect_error && !page) {
            renderSteps(1);
            sessionBox.appendChild(ucm.stateBox("error", ERROR_TITLES[session.inspect_error.code] || "The page could not be inspected",
                session.inspect_error.message + " (" + session.start_url + ")"));
            return;
        }
        if (!page) { renderSteps(1); return; }
        sessionBox.appendChild(el("div", { "class": "ucm-card" },
            el("div", {}, ucm.badge("Splunk Lantern", "lantern"), " ",
                ucm.badge(page.kind === "article" ? "Article" : page.kind === "collection" ? "Collection" : "Unsupported page",
                    page.kind === "unsupported" ? "error" : "info"),
                " ", el("strong", { text: page.title || page.url })),
            el("div", {}, lanternLink(page.url, page.url)),
            page.breadcrumbs && page.breadcrumbs.length
                ? el("div", { "class": "ucm-sub", text: page.breadcrumbs.map(function (b) { return b.title; }).join(" › ") }) : null,
            page.redirects && page.redirects.length
                ? el("div", { "class": "ucm-sub", text: "Redirected to " + page.redirects[page.redirects.length - 1] }) : null,
            page.description ? el("div", { "class": "ucm-sub", text: page.description }) : null));
        if (page.kind === "unsupported") {
            renderSteps(1);
            sessionBox.appendChild(ucm.stateBox("error", "Unsupported page", page.reason));
            return;
        }
        if (page.empty) {
            renderSteps(1);
            sessionBox.appendChild(ucm.stateBox("empty", "No articles found",
                "The collection page contains no article links SUN can import. Try one of its sub-pages or an article URL."));
            return;
        }
        if (page.truncated) {
            sessionBox.appendChild(ucm.stateBox("warn", "Partial listing",
                "The page lists more articles than the configured limit; only the first ones are shown."));
        }
        renderSteps(session.last_import ? 4 : 2);
        sessionBox.appendChild(renderItems(busy));
        if (session.last_import) { sessionBox.appendChild(renderImportResult(session.last_import)); }
        var errs = (session.errors || []).filter(function (e) { return e.code !== "cancelled"; });
        if (errs.length) {
            sessionBox.appendChild(el("details", {}, el("summary", { text: errs.length + " retrieval error(s) in this session" }),
                el("ul", {}, errs.slice(-10).map(function (e) {
                    return el("li", { text: (ERROR_TITLES[e.code] || e.code) + ": " + e.message + " — " + (e.url || "") });
                }))));
        }
    }

    function visibleItems() {
        return (session.items || []).filter(function (i) { return !categoryFilter || i.category === categoryFilter; });
    }

    function renderItems(busy) {
        var items = session.items || [];
        var box = el("div", {});
        var categories = [];
        items.forEach(function (i) { if (categories.indexOf(i.category) < 0) { categories.push(i.category); } });
        var filter = el("select", { "aria-label": "Category filter", onchange: function () {
            categoryFilter = filter.value; ucm.clear(previewBox); renderSession(); } },
            el("option", { value: "", text: "All categories (" + items.length + ")" }),
            categories.map(function (c) {
                var n = items.filter(function (i) { return i.category === c; }).length;
                var opt = el("option", { value: c, text: c + " (" + n + ")" });
                if (c === categoryFilter) { opt.selected = true; }
                return opt;
            }));
        var counts = { "new": 0, updated: 0, unchanged: 0, error: 0, listed: 0 };
        items.forEach(function (i) { var s = itemStatus(i); if (counts[s] !== undefined) { counts[s] += 1; } });
        var selectedItems = items.filter(function (i) { return selected[i.url]; });
        var toFetch = selectedItems.filter(function (i) {
            return i.kind !== "collection" && (i.state === "listed" || i.state === "error" || i.state === "fetched");
        });
        var toExpand = selectedItems.filter(function (i) {
            return (i.kind === "collection" || (!i.kind && i.kind_guess === "collection")) && i.state !== "expanded";
        });
        var toImport = selectedItems.filter(function (i) {
            return i.state === "fetched" && i.kind === "article" && (i.status === "new" || i.status === "updated");
        });
        box.appendChild(el("div", { "class": "ucm-toolbar" },
            el("div", { "class": "ucm-field" }, el("label", { text: "Category" }), filter),
            el("button", { "class": "btn", type: "button", text: "Select all", onclick: function () {
                visibleItems().forEach(function (i) { if (i.state !== "duplicate" && i.state !== "imported") { selected[i.url] = true; } });
                renderSession(); } }),
            el("button", { "class": "btn", type: "button", text: "Deselect all", onclick: function () {
                selected = {}; renderSession(); } }),
            el("button", { "class": "btn btn-primary", type: "button", disabled: busy || !toFetch.length ? "disabled" : null,
                text: "Fetch and preview selected (" + toFetch.length + ")", onclick: function () {
                    requestStep("lantern/fetch", toFetch); } }),
            toExpand.length ? el("button", { "class": "btn", type: "button", disabled: busy ? "disabled" : null,
                text: "List articles in selected sub-collections (" + toExpand.length + ")", onclick: function () {
                    requestStep("lantern/expand", toExpand); } }) : null,
            el("button", { "class": "btn btn-primary", type: "button", disabled: busy || !toImport.length ? "disabled" : null,
                text: "Review import (" + toImport.length + ")", onclick: function () { renderConfirm(toImport); } })));
        box.appendChild(el("div", { "class": "ucm-summary-line", text: items.length + " item(s): " + counts["new"] + " new, " +
            counts.updated + " with updates, " + counts.unchanged + " unchanged, " + counts.listed + " not fetched yet, " +
            counts.error + " error(s). Selected: " + selectedItems.length + "." }));
        box.appendChild(el("div", { "class": "ucm-sub", text: "Selecting an article does not import it. Fetch the selection to " +
            "preview each extraction and to see whether it is new or already in SUN, then review and confirm the import." }));

        var head = el("tr", {}, el("th", {}), el("th", { text: "Title" }), el("th", { text: "Subcategory" }),
            el("th", { text: "Type" }), el("th", { text: "In SUN" }), el("th", { text: "Status" }),
            el("th", { text: "Extraction" }), el("th", {}));
        var body = el("tbody", {});
        var lastGroup = null;
        visibleItems().forEach(function (item) {
            if (item.category !== lastGroup) {
                lastGroup = item.category;
                body.appendChild(el("tr", { "class": "ucm-group-row" }, el("td", { colspan: "8", text: item.category || "Uncategorised" })));
            }
            var box = el("input", { type: "checkbox", "aria-label": item.title });
            box.checked = !!selected[item.url];
            box.disabled = item.state === "duplicate" || item.state === "imported" || item.state === "queued";
            box.addEventListener("change", function () {
                if (box.checked) { selected[item.url] = true; } else { delete selected[item.url]; }
                renderSession();
            });
            var ex = item.extraction;
            var update = null;
            if (item.status === "updated" && item.state === "fetched") {
                var upd = el("input", { type: "checkbox", "aria-label": "Apply update" });
                upd.checked = !!updates[item.url];
                upd.addEventListener("change", function () { if (upd.checked) { updates[item.url] = true; } else { delete updates[item.url]; } });
                update = el("label", { "class": "ucm-sub" }, upd, " apply update");
            }
            body.appendChild(el("tr", {},
                el("td", {}, box),
                el("td", {}, lanternLink(item.url, item.title || item.url),
                    item.description ? el("div", { "class": "ucm-sub", text: item.description.substring(0, 160) }) : null,
                    item.also_in && item.also_in.length ? el("div", { "class": "ucm-sub",
                        text: "Also listed under: " + item.also_in.map(function (p) { return p.category + (p.subcategory ? " › " + p.subcategory : ""); }).join("; ") }) : null,
                    item.error ? el("div", { "class": "ucm-sub", text: (ERROR_TITLES[item.error.code] || item.error.code) + ": " + item.error.message }) : null,
                    item.duplicate_of ? el("div", { "class": "ucm-sub", text: "Same article as " + item.duplicate_of }) : null,
                    item.changes && item.changes.length ? el("details", {}, el("summary", { "class": "ucm-sub", text: "What changed (" + item.changes.length + ")" }),
                        el("ul", { "class": "ucm-changes" }, item.changes.map(function (c) {
                            return el("li", { text: c.field + (c.before_count !== undefined ? ": " + c.before_count + " → " + c.after_count + " entries"
                                : (c.after !== undefined ? ": “" + (c.before || "") + "” → “" + (c.after || "") + "”" : "")) });
                        }))) : null),
                el("td", { text: item.subcategory || "" }),
                el("td", { text: item.kind || item.kind_guess || "" }),
                el("td", {}, item.in_sun ? el("a", { href: "ucm_usecase?id=" + encodeURIComponent("lantern:" + item.record_id) }, ucm.badge("yes", "ok"))
                    : ucm.badge("no", "neutral")),
                el("td", {}, statusBadge(item), update),
                el("td", {}, ex ? [ucm.badge(ex.confidence + " confidence", ex.confidence === "high" ? "ok" : ex.confidence === "medium" ? "warn" : "error"),
                    ex.needs_review ? ucm.badge("needs review", "warn") : null,
                    el("div", { "class": "ucm-sub", text: ex.spl_count + " SPL, " + ex.block_count + " blocks" })] : ""),
                el("td", {}, item.stage_key ? el("button", { "class": "btn btn-small", type: "button", text: "Preview",
                    onclick: function () { showPreview(item); } }) : null)));
        });
        box.appendChild(el("table", { "class": "ucm-table" }, el("thead", {}, head), body));
        return box;
    }

    function requestStep(path, items) {
        ucm.post(path, { id: session.session_id, urls: items.map(function (i) { return i.url; }) }).done(function (res) {
            session = res.session; renderSession(); schedulePoll();
        }).fail(function (err) {
            sessionBox.insertBefore(errorBox(err, "The request was not accepted"), sessionBox.firstChild.nextSibling);
        });
    }

    // -- step 3: preview ------------------------------------------------------------------------
    function renderBlocks(blocks) {
        var box = el("div", { "class": "ucm-article" });
        (blocks || []).forEach(function (b) {
            if (b.type === "heading") {
                box.appendChild(el(b.level <= 2 ? "h4" : "h5", { text: b.text }));
            } else if (b.type === "paragraph") {
                box.appendChild(el("p", { "class": b.note ? "ucm-note" : null, text: b.text }));
            } else if (b.type === "list") {
                box.appendChild(el(b.ordered ? "ol" : "ul", {}, b.items.map(function (t) { return el("li", { text: t }); })));
            } else if (b.type === "table") {
                box.appendChild(el("table", { "class": "ucm-table" },
                    b.header && b.header.length ? el("thead", {}, el("tr", {}, b.header.map(function (h) { return el("th", { text: h }); }))) : null,
                    el("tbody", {}, b.rows.map(function (r) { return el("tr", {}, r.map(function (c) { return el("td", { text: c }); })); }))));
            } else if (b.type === "code") {
                box.appendChild(el("div", { "class": "ucm-sub", text: b.is_spl ? "SPL" : (b.language || "code") }));
                box.appendChild(el("pre", { "class": b.is_spl ? "ucm-spl" : null, text: b.text }));
            }
        });
        return box;
    }

    function list(label, values) {
        if (!values || !values.length) { return [el("dt", { text: label }), el("dd", { "class": "ucm-sub", text: "not stated in the article" })]; }
        return [el("dt", { text: label }), el("dd", {}, el("ul", {}, values.map(function (v) { return el("li", { text: v }); })))];
    }

    function showPreview(item) {
        ucm.clear(previewBox).appendChild(el("div", { "class": "ucm-loading", text: "Loading extraction preview…" }));
        ucm.get("lantern/staged", { id: session.session_id, url: item.url }).done(function (res) {
            var raw = res.raw, uc = res.usecase, ex = raw.extraction || {};
            var reqBody = el("tbody", {}, (uc.requirements || []).map(function (r) {
                return el("tr", {}, el("td", { text: r.type }), el("td", { "class": "ucm-mono", text: r.value }), el("td", { text: r.level }),
                    el("td", { text: r.source }), el("td", { text: r.confidence }));
            }));
            ucm.clear(previewBox).appendChild(el("div", { "class": "ucm-preview" },
                el("div", { "class": "ucm-actions" }, el("h3", { text: "Extraction preview: " + raw.title }),
                    el("button", { "class": "btn", type: "button", text: "Close", onclick: function () { ucm.clear(previewBox); } })),
                el("div", { "class": "ucm-provenance" }, "Content from Splunk Lantern, extracted by SUN. Original: ", lanternLink(raw.source_url),
                    el("div", { "class": "ucm-sub", text: "Last updated on Lantern: " + (raw.modified || "unknown") + " · retrieved " + raw.retrieved_at +
                        " · extractor " + raw.extraction_version })),
                el("div", {}, ucm.badge(ex.confidence + " confidence", ex.confidence === "high" ? "ok" : "warn"),
                    ex.needs_review ? ucm.badge("flagged for manual review", "warn") : null,
                    item.status ? statusBadge(item) : null),
                ex.warnings && ex.warnings.length ? el("ul", { "class": "ucm-changes" }, ex.warnings.map(function (w) { return el("li", { text: w }); })) : null,
                el("dl", { "class": "ucm-kv" },
                    el("dt", { text: "SUN category" }), el("dd", { text: uc.category_name + (uc.subcategory ? " › " + uc.subcategory : "") }),
                    el("dt", { text: "Domains" }), el("dd", {}, ucm.chips(uc.domains)),
                    el("dt", { text: "Description" }), el("dd", { text: raw.description || "not stated" }),
                    el("dt", { text: "Business value" }), el("dd", { text: raw.business_value || "not stated in the article" }),
                    list("Prerequisites", raw.prerequisites), list("Data sources", raw.data_sources),
                    list("Products", raw.products), list("Add-ons and apps", (raw.addons || []).map(function (a) {
                        return a.name + (a.splunkbase_id ? " (Splunkbase " + a.splunkbase_id + ")" : "") + " — " + a.role; })),
                    list("Dashboards", (raw.dashboards || []).map(function (d) { return d.title; })),
                    list("Related articles", (raw.related_articles || []).map(function (r) { return r.title; })),
                    el("dt", { text: "SPL searches" }), el("dd", { text: (raw.spl_blocks || []).length + " (shown as code below; never executed)" })),
                el("h4", { text: "Requirements SUN will assess" }),
                uc.requirements && uc.requirements.length ? el("table", { "class": "ucm-table" }, el("thead", {}, el("tr", {},
                    el("th", { text: "Type" }), el("th", { text: "Value" }), el("th", { text: "Level" }), el("th", { text: "Source" }),
                    el("th", { text: "Confidence" }))), reqBody) : ucm.stateBox("empty", "No requirements could be derived from this article."),
                el("details", { open: "open" }, el("summary", { text: "Article content as extracted (" + (raw.blocks || []).length + " blocks)" }),
                    renderBlocks(raw.blocks))));
            previewBox.scrollIntoView({ behavior: "smooth" });
        }).fail(function (err) { ucm.clear(previewBox).appendChild(errorBox(err, "Preview unavailable")); });
    }

    // -- step 4: confirmation ---------------------------------------------------------------------
    function renderConfirm(items) {
        var fresh = items.filter(function (i) { return i.status === "new"; });
        var changed = items.filter(function (i) { return i.status === "updated"; });
        var applied = changed.filter(function (i) { return updates[i.url]; });
        var selectedAll = (session.items || []).filter(function (i) { return selected[i.url]; });
        var unchanged = selectedAll.filter(function (i) { return i.status === "unchanged"; });
        var errors = selectedAll.filter(function (i) { return i.state === "error"; });
        var notFetched = selectedAll.filter(function (i) { return i.state === "listed"; });
        var lowConf = items.filter(function (i) { return i.extraction && i.extraction.needs_review; });
        var agree = el("input", { type: "checkbox", id: "ucm-lantern-confirm" });
        var go = el("button", { "class": "btn btn-primary", type: "button", disabled: "disabled",
            text: "Import " + fresh.length + " new and update " + applied.length + " existing" });
        agree.addEventListener("change", function () { go.disabled = !agree.checked || !(fresh.length + applied.length); });
        go.addEventListener("click", function () {
            go.disabled = true;
            var payload = fresh.map(function (i) { return { url: i.url, action: "import" }; })
                .concat(changed.map(function (i) { return { url: i.url, action: updates[i.url] ? "update" : "skip" }; }));
            ucm.post("lantern/import", { id: session.session_id, items: payload, confirm: true }).done(function (res) {
                session = res.session;
                selected = {};
                updates = {};
                ucm.clear(confirmBox);
                renderSession();
                renderImported();
                renderHistory();
            }).fail(function (err) {
                ucm.clear(confirmBox).appendChild(errorBox(err, "Import failure"));
            });
        });
        renderSteps(3);
        ucm.clear(confirmBox).appendChild(el("div", { "class": "ucm-confirm" },
            el("h3", { text: "Confirm import" }),
            el("dl", { "class": "ucm-kv" },
                el("dt", { text: "Selected articles" }), el("dd", { text: String(selectedAll.length) }),
                el("dt", { text: "New articles to import" }), el("dd", { text: String(fresh.length) }),
                el("dt", { text: "Existing articles, unchanged (skipped)" }), el("dd", { text: String(unchanged.length) }),
                el("dt", { text: "Existing articles with updates" }), el("dd", { text: changed.length + " (" + applied.length + " selected to apply)" }),
                el("dt", { text: "Parse or retrieval errors (skipped)" }), el("dd", { text: String(errors.length) }),
                el("dt", { text: "Not fetched yet (skipped)" }), el("dd", { text: String(notFetched.length) }),
                el("dt", { text: "Flagged for manual review" }), el("dd", { text: String(lowConf.length) })),
            el("div", { "class": "ucm-sub", text: "Imported articles join the catalogue as provider \"lantern\" with a link to the original. " +
                "Updates replace only the Lantern content; your notes, backlog selections, priorities, readiness history, " +
                "mappings, local SPL, deployments and approvals are kept." }),
            el("div", { "class": "ucm-actions" }, el("label", {}, agree, " I reviewed the selection and want to write it to the SUN catalogue"),
                go, el("button", { "class": "btn", type: "button", text: "Back", onclick: function () { ucm.clear(confirmBox); renderSession(); } }))));
        confirmBox.scrollIntoView({ behavior: "smooth" });
    }

    function renderImportResult(result) {
        var c = result.counts || {};
        var ok = !c.failed && !c.conflict;
        return el("div", { "class": "ucm-section" },
            ucm.stateBox(ok ? "info" : "warn", ok ? "Import completed." : "Import completed with problems.",
                (c.imported || 0) + " imported, " + (c.updated || 0) + " updated, " + (c.skipped || 0) + " skipped, " +
                (c.conflict || 0) + " update conflict(s), " + (c.failed || 0) + " failed — " + result.at + " by " + result.by + "."),
            el("table", { "class": "ucm-table" }, el("thead", {}, el("tr", {}, el("th", { text: "Article" }),
                el("th", { text: "Outcome" }), el("th", { text: "Details" }))),
                el("tbody", {}, (result.results || []).map(function (r) {
                    var kind = { imported: "ok", updated: "ok", skipped: "neutral", conflict: "warn", failed: "error" }[r.outcome] || "neutral";
                    return el("tr", {},
                        el("td", {}, r.content_id ? el("a", { href: "ucm_usecase?id=" + encodeURIComponent(r.content_id), text: r.title || r.url })
                            : (r.title || r.url)),
                        el("td", {}, ucm.badge(r.outcome, kind)),
                        el("td", { "class": "ucm-sub", text: r.message || "" }));
                }))));
    }

    // -- provider management ----------------------------------------------------------------------
    function renderImported() {
        ucm.get("catalog", { provider: "lantern", sort: "imported", count: 50 }).done(function (data) {
            ucm.clear(importedBox).appendChild(el("h3", { text: "Imported Lantern content (" + (data.total || 0) + ")" }));
            if (!data.items.length) { importedBox.appendChild(ucm.stateBox("empty", "No Lantern articles imported yet.")); return; }
            importedBox.appendChild(el("table", { "class": "ucm-table" },
                el("thead", {}, el("tr", {}, el("th", { text: "Use case" }), el("th", { text: "SUN category" }),
                    el("th", { text: "Imported (UTC)" }), el("th", { text: "SPL" }), el("th", {}))),
                el("tbody", {}, data.items.map(function (row) {
                    return el("tr", {},
                        el("td", {}, el("a", { href: "ucm_usecase?id=" + encodeURIComponent(row.content_id), text: row.title }),
                            row.needs_review ? [" ", ucm.badge("needs review", "warn")] : null,
                            row.source_url ? el("div", { "class": "ucm-sub" }, lanternLink(row.source_url, "original on Lantern")) : null),
                        el("td", { text: row.category_name + (row.subcategory ? " › " + row.subcategory : "") }),
                        el("td", { text: row.imported_at }),
                        el("td", { text: row.has_spl ? "yes" : "no" }),
                        el("td", {}, row.source_url ? el("button", { "class": "btn btn-small", type: "button", text: "Check for updates",
                            onclick: function () {
                                ucm.post("lantern/inspect", { url: row.source_url }).done(function (res) { openSession(res.session); })
                                    .fail(function (err) { importedBox.insertBefore(errorBox(err), importedBox.firstChild.nextSibling); });
                            } }) : null));
                }))));
        }).fail(function (err) { ucm.clear(importedBox).appendChild(errorBox(err, "Imported Lantern content unavailable")); });
    }

    function renderHistory(sessions) {
        if (!sessions) {
            ucm.get("lantern").done(function (data) { renderHistory(data.sessions || []); });
            return;
        }
        ucm.clear(historyBox).appendChild(el("h3", { text: "Recent import sessions" }));
        if (!sessions.length) { historyBox.appendChild(ucm.stateBox("empty", "No import sessions yet.")); return; }
        historyBox.appendChild(el("table", { "class": "ucm-table" },
            el("thead", {}, el("tr", {}, el("th", { text: "Updated (UTC)" }), el("th", { text: "Page" }), el("th", { text: "Status" }),
                el("th", { text: "Items" }), el("th", { text: "Last import" }), el("th", { text: "By" }), el("th", {}))),
            el("tbody", {}, sessions.map(function (s) {
                var c = (s.last_import || {}).counts || {};
                return el("tr", {},
                    el("td", { text: s.updated_at }),
                    el("td", {}, el("div", { text: (s.page && s.page.title) || s.start_url }), el("div", { "class": "ucm-sub", text: s.start_url })),
                    el("td", {}, ucm.badge(s.status, { ready: "ok", failed: "error", queued: "info", running: "info" }[s.status] || "neutral")),
                    el("td", { text: s.item_count + (s.error_count ? " (" + s.error_count + " errors)" : "") }),
                    el("td", { text: s.last_import ? (c.imported || 0) + " imported, " + (c.updated || 0) + " updated" : "—" }),
                    el("td", { text: s.requested_by }),
                    el("td", {}, el("button", { "class": "btn btn-small", type: "button", text: "Open", onclick: function () {
                        ucm.get("lantern/session", { id: s.session_id }).done(function (res) { openSession(res.session); });
                    } }), " ", el("button", { "class": "btn btn-small", type: "button", text: "Discard", onclick: function () {
                        ucm.post("lantern/discard", { id: s.session_id }).done(function () {
                            if (session && session.session_id === s.session_id) { session = null; setSession(""); renderSession(); }
                            renderHistory();
                        });
                    } })));
            }))));
    }

    ucm.clear(root);
    root.appendChild(el("div", { "class": "ucm-header" }, el("h2", { text: "Import use cases from Splunk Lantern" }),
        el("div", { "class": "ucm-sub", text: "Lantern is a secondary content provider. Imported articles keep their Lantern provenance " +
            "and never replace or merge with Fenre content." })));
    root.appendChild(stepsBox);
    root.appendChild(formBox);
    root.appendChild(sessionBox);
    root.appendChild(previewBox);
    root.appendChild(confirmBox);
    root.appendChild(importedBox);
    root.appendChild(historyBox);
    renderSteps(0);
    ucm.get("lantern").done(function (data) {
        renderForm(data.settings, ucm.queryParams().inspect || "");
        renderHistory(data.sessions || []);
        renderImported();
        var id = ucm.queryParams().session;
        if (id) {
            ucm.get("lantern/session", { id: id }).done(function (res) { openSession(res.session); })
                .fail(function () { setSession(""); });
        }
    }).fail(function (err) {
        ucm.clear(formBox).appendChild(err.status === 403
            ? ucm.stateBox("error", "Not permitted", "Importing from Splunk Lantern requires the ucm_manage_content capability (role ucm_content_manager).")
            : errorBox(err, "Lantern import is unavailable"));
    });
});
