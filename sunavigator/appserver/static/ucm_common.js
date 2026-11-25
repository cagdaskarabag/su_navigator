/*
 * Shared UI helpers for SUNavigator views.
 * All content is untrusted: DOM is built with textContent / attributes only,
 * never innerHTML with data.
 */
define(["jquery", "splunk.util"], function ($, splunkUtil) {
    "use strict";

    var API_BASE = "/splunkd/__raw/services/ucm/";

    function apiUrl(path, params) {
        var url = splunkUtil.make_url(API_BASE + path);
        var query = $.param(params || {}, true);
        return query ? url + "?" + query : url;
    }

    function errorMessage(xhr) {
        try {
            var body = JSON.parse(xhr.responseText);
            if (body && body.error) {
                return body.error.message + (body.error.code ? " (" + body.error.code + ")" : "");
            }
        } catch (e) { /* not JSON */ }
        if (xhr.status === 0) { return "Splunk could not be reached."; }
        return "Request failed with HTTP " + xhr.status + ".";
    }

    function request(method, path, params, body, contentType) {
        var deferred = $.Deferred();
        $.ajax({
            url: apiUrl(path, params),
            type: method,
            data: body === undefined ? undefined : body,
            processData: false,
            contentType: contentType || "application/json",
            dataType: "json",
            headers: { "X-Splunk-Form-Key": splunkUtil.getFormKey(), "X-Requested-With": "XMLHttpRequest" }
        }).done(function (data) {
            deferred.resolve(data);
        }).fail(function (xhr) {
            deferred.reject({ status: xhr.status, message: errorMessage(xhr) });
        });
        return deferred.promise();
    }

    function get(path, params) { return request("GET", path, params); }
    function post(path, json, params) {
        return request("POST", path, params, json === undefined ? "{}" : JSON.stringify(json));
    }
    function postRaw(path, text, params) { return request("POST", path, params, text, "application/json"); }

    /* el("div", {class: "x", href: "..."}, child, "text", [children]) */
    function el(tag, attrs) {
        var node = document.createElement(tag);
        var key;
        attrs = attrs || {};
        for (key in attrs) {
            if (!Object.prototype.hasOwnProperty.call(attrs, key) || attrs[key] === undefined || attrs[key] === null) {
                continue;
            }
            if (key === "text") {
                node.textContent = String(attrs[key]);
            } else if (key.indexOf("on") === 0 && typeof attrs[key] === "function") {
                node.addEventListener(key.substring(2), attrs[key]);
            } else if (key === "href") {
                if (isSafeHref(attrs[key])) { node.setAttribute("href", attrs[key]); }
            } else {
                node.setAttribute(key, attrs[key]);
            }
        }
        for (var i = 2; i < arguments.length; i++) { append(node, arguments[i]); }
        return node;
    }

    function append(node, child) {
        if (child === undefined || child === null || child === false) { return; }
        if ($.isArray(child)) {
            child.forEach(function (c) { append(node, c); });
        } else if (child instanceof Node) {
            node.appendChild(child);
        } else {
            node.appendChild(document.createTextNode(String(child)));
        }
    }

    function isSafeHref(href) {
        if (typeof href !== "string") { return false; }
        if (href.charAt(0) === "?" || href.charAt(0) === "#") { return true; }
        if (/^[a-z_]+(\?|$)/i.test(href)) { return true; } /* app-relative view link */
        return /^https?:\/\//i.test(href);
    }

    function clear(node) {
        while (node.firstChild) { node.removeChild(node.firstChild); }
        return node;
    }

    function badge(text, kind) {
        return el("span", { "class": "ucm-badge ucm-badge-" + (kind || "neutral"), text: text });
    }

    function criticalityBadge(value) {
        var kinds = { critical: "critical", high: "high", medium: "medium", low: "low" };
        return badge(value || "unknown", kinds[value] || "neutral");
    }

    function chips(values, limit, kind) {
        values = values || [];
        var shown = values.slice(0, limit || values.length).map(function (v) { return badge(v, kind || "chip"); });
        if (limit && values.length > limit) {
            shown.push(el("span", { "class": "ucm-more", text: "+" + (values.length - limit) }));
        }
        return shown;
    }

    function stateBox(kind, title, message) {
        return el("div", { "class": "ucm-state ucm-state-" + kind },
            el("strong", { text: title }), message ? el("div", { text: message }) : null);
    }

    function queryParams() {
        var out = {};
        var search = window.location.search.replace(/^\?/, "");
        if (!search) { return out; }
        search.split("&").forEach(function (pair) {
            var parts = pair.split("=");
            var k = decodeURIComponent(parts[0] || "");
            var v = decodeURIComponent((parts[1] || "").replace(/\+/g, " "));
            if (k) { out[k] = v; }
        });
        return out;
    }

    function setQueryParams(params) {
        var clean = {};
        Object.keys(params).forEach(function (k) {
            if (params[k] !== "" && params[k] !== undefined && params[k] !== null) { clean[k] = params[k]; }
        });
        var query = $.param(clean);
        window.history.replaceState(null, "", window.location.pathname + (query ? "?" + query : ""));
    }

    /* "n of d" as a percentage; null when there is nothing to divide by. Values under 10% keep one decimal. */
    function percent(n, d) {
        if (!d) { return null; }
        var p = 100 * n / d;
        return (p > 0 && p < 10 ? p.toFixed(1) : String(Math.round(p))) + "%";
    }

    /*
     * One KPI card. Every card states the figures it is made of (detail) and how it is calculated (how),
     * so that a percentage never stands alone. A null value renders as a dash with the reason in detail.
     */
    function kpiCard(k) {
        var value = k.value === null || k.value === undefined ? "–" : k.value;
        return el("div", { "class": "ucm-card ucm-kpi", title: k.how },
            el("div", { "class": "ucm-sub", text: k.label }),
            el("div", { "class": "ucm-big", text: value }),
            el("div", { "class": "ucm-sub", text: k.detail || "" }),
            el("div", { "class": "ucm-sub ucm-kpi-how", text: k.how }));
    }

    function kpiStrip(list) {
        return el("div", { "class": "ucm-cards ucm-kpis" }, list.map(kpiCard));
    }

    /*
     * The readiness KPIs shared by Overview and Readiness so both pages use the same terms and figures.
     * activeTotal is the number of active use cases in the catalogue (null when it could not be read);
     * summary is the readiness/summary response.
     */
    function readinessKpis(activeTotal, summary) {
        var by = (summary && summary.by_state) || {};
        var assessed = 0;
        ["ready", "partially_ready", "not_ready", "blocked", "insufficient_evidence"].forEach(function (s) { assessed += by[s] || 0; });
        var ready = by.ready || 0;
        var partial = by.partially_ready || 0;
        var known = activeTotal !== null && activeTotal !== undefined;
        return [
            { label: "Assessed", value: known ? percent(assessed, activeTotal) : null,
                detail: known ? assessed + " of " + activeTotal + " active use cases" : assessed + " assessed; catalogue size unavailable",
                how: "Use cases with a stored readiness result ÷ active use cases in the catalogue. Not assessed means no result is stored yet." },
            { label: "Ready", value: percent(ready, assessed),
                detail: ready + " of " + assessed + " assessed" + (assessed ? "" : " (nothing assessed yet)"),
                how: "Use cases whose readiness state is ready ÷ assessed use cases. Ready means no blockers, a score at or above the ready threshold and enough coverage. Not verified requirements are left out." },
            { label: "Ready or partially ready", value: percent(ready + partial, assessed),
                detail: (ready + partial) + " of " + assessed + " assessed",
                how: "Use cases in state ready or partially ready ÷ assessed use cases." },
            { label: "Not ready, blocked or insufficient evidence",
                value: percent(assessed - ready - partial, assessed),
                detail: (assessed - ready - partial) + " of " + assessed + " assessed",
                how: "Assessed use cases that are neither ready nor partially ready ÷ assessed use cases." }
        ];
    }

    function pager(offset, count, total, hasMore, onPage) {
        var from = total === 0 ? 0 : offset + 1;
        var to = offset + count;
        if (total !== null && total !== undefined) { to = Math.min(to, total); }
        var label = total === null || total === undefined
            ? from + "–" + to
            : from + "–" + to + " of " + total;
        return el("div", { "class": "ucm-pager" },
            el("button", { "class": "btn", type: "button", disabled: offset <= 0 ? "disabled" : null,
                onclick: function () { onPage(Math.max(0, offset - count)); } }, "‹ Previous"),
            el("span", { "class": "ucm-pager-label", text: label }),
            el("button", { "class": "btn", type: "button", disabled: hasMore ? null : "disabled",
                onclick: function () { onPage(offset + count); } }, "Next ›"));
    }

    function debounce(fn, ms) {
        var timer = null;
        return function () {
            var args = arguments, self = this;
            clearTimeout(timer);
            timer = setTimeout(function () { fn.apply(self, args); }, ms);
        };
    }

    function shortSha(value) { return value ? String(value).substring(0, 12) : ""; }

    var READINESS_LABELS = { ready: ["Ready", "ok"], partially_ready: ["Partially ready", "warn"],
        not_ready: ["Not ready", "high"], blocked: ["Blocked", "critical"],
        insufficient_evidence: ["Insufficient evidence", "neutral"] };
    var STATUS_LABELS = { met: ["met", "ok"], partial: ["partial", "warn"], not_met: ["not met", "error"],
        unknown: ["unknown", "neutral"], unverified: ["not verified", "info"], not_applicable: ["n/a", "neutral"] };

    /*
     * Keys match splunk_ucm.readiness.scoring.STATES and evaluators.STATUSES (checked by a unit test).
     * Wording follows scoring.py: a missing check is never described as missing data.
     */
    var READINESS_HELP = {
        ready: "Score at or above the ready threshold, coverage at or above the minimum, and no unmet critical or required requirement.",
        partially_ready: "Score at or above the partial threshold, but below the ready threshold or with at least one unmet required requirement.",
        not_ready: "Score below the partial threshold.",
        blocked: "At least one critical requirement was checked and is not met. Blocked wins over any score.",
        insufficient_evidence: "Too little could be decided: coverage is below the minimum, or no requirement could be scored."
    };
    var STATUS_HELP = {
        met: "Checked against the inventory and satisfied.",
        partial: "Satisfied with a caveat, for example data older than the freshness threshold, an object shared only " +
            "inside its app, an add-on below the documented minimum version, or SPL that needs review. Counts half in the score.",
        not_met: "Checked and not satisfied, for example no events for the sourcetype in the discovery window, add-on not " +
            "installed, or SPL rejected by Splunk's parser. Unmet critical requirements block the use case.",
        unknown: "An evaluator ran but could not decide, for example the Splunk version was not recorded. Counts as 0 in the " +
            "score and lowers coverage.",
        unverified: "Not checked yet: the inventory cannot evaluate it (fields not sampled, event conditions, free-text sources, " +
            "SPL not parsed, internal indexes that discovery did not scan, or index access that could not be fully verified). Left out of score and coverage. It is not a failure and does not mean the data is absent.",
        not_applicable: "Does not apply to this deployment. Left out of score and coverage."
    };

    function readinessBadge(value) {
        var l = READINESS_LABELS[value] || [value || "not assessed", "neutral"];
        var b = badge(l[0], l[1]);
        if (READINESS_HELP[value]) { b.setAttribute("title", READINESS_HELP[value]); }
        return b;
    }

    function statusBadge(value) {
        var l = STATUS_LABELS[value] || [value || "not assessed", "neutral"];
        var b = badge(l[0], l[1]);
        if (STATUS_HELP[value]) { b.setAttribute("title", STATUS_HELP[value]); }
        return b;
    }

    var RESULT_ORDER = ["met", "partial", "not_met", "unknown", "unverified", "not_applicable"];

    function resultCount(counts, status, unverified) {
        var n = counts && counts[status];
        if (status === "unverified" && (n === undefined || n === null)) { n = unverified; }
        return n || 0;
    }

    /* One sentence with the stored per-status counts, in the same words as the status badges. */
    function resultSummary(counts, unverified) {
        var parts = ["met", "partial", "not_met", "unknown", "unverified"].map(function (st) {
            return resultCount(counts, st, unverified) + " " + STATUS_LABELS[st][0];
        });
        var na = resultCount(counts, "not_applicable", unverified);
        return parts.join(", ") + (na ? ", " + na + " " + STATUS_LABELS.not_applicable[0] : "");
    }

    /* The non-zero stored counts as status badges, each explained on hover. */
    function resultBadges(counts, unverified) {
        var box = el("span", { "class": "ucm-results-badges" });
        RESULT_ORDER.forEach(function (st) {
            var n = resultCount(counts, st, unverified);
            if (!n) { return; }
            var b = badge(n + " " + STATUS_LABELS[st][0], STATUS_LABELS[st][1]);
            b.setAttribute("title", STATUS_HELP[st]);
            box.appendChild(b);
        });
        if (!box.firstChild) { box.appendChild(el("span", { "class": "ucm-sub", text: "–" })); }
        return box;
    }

    /* Table header with an explanation shown on hover and focus. */
    function helpHeader(label, help) {
        return el("th", { "class": "ucm-help", title: help, tabindex: "0" }, label);
    }

    /* Collapsible legend: one row per status or state, badge plus explanation. */
    function legend(title, keys, badgeFn, help) {
        return el("details", { "class": "ucm-details ucm-legend-box" }, el("summary", { text: title }),
            el("dl", { "class": "ucm-kv" }, keys.map(function (k) {
                return [el("dt", {}, badgeFn(k)), el("dd", { text: help[k] })];
            })));
    }

    /*
     * Tri-state "select all" over a fixed list of checkboxes. Only the boxes passed in change,
     * disabled boxes are left alone, and individual changes keep the header and count in step.
     */
    function selectAll(boxes, noun, onChange) {
        var header = el("input", { type: "checkbox", "aria-label": "Select all " + noun });
        var count = el("span", { "class": "ucm-sub", "aria-live": "polite" });
        var allBtn = el("button", { "class": "btn", type: "button", text: "Select all" });
        var noneBtn = el("button", { "class": "btn", type: "button", text: "Deselect all" });
        function enabled() { return boxes.filter(function (b) { return !b.disabled; }); }
        function sync() {
            var n = boxes.filter(function (b) { return b.checked; }).length;
            var open = enabled();
            var openChecked = open.filter(function (b) { return b.checked; }).length;
            header.checked = n > 0 && n === boxes.length;
            header.indeterminate = n > 0 && n < boxes.length;
            header.disabled = !open.length;
            allBtn.disabled = openChecked === open.length;
            noneBtn.disabled = openChecked === 0;
            count.textContent = n + " of " + boxes.length + " " + noun + " selected";
            if (onChange) { onChange(n); }
        }
        function setAll(value) {
            enabled().forEach(function (b) { b.checked = value; });
            sync();
        }
        header.addEventListener("change", function () { setAll(header.checked); });
        allBtn.addEventListener("click", function () { setAll(true); });
        noneBtn.addEventListener("click", function () { setAll(false); });
        boxes.forEach(function (b) { b.addEventListener("change", sync); });
        sync();
        return { header: header, selectAllButton: allBtn, deselectAllButton: noneBtn, count: count, sync: sync };
    }

    /*
     * Modal dialog used instead of the browser's alert, confirm and prompt dialogs, which
     * browsers may suppress and which cannot validate input. Text is set with textContent only.
     * opts: title, message, confirmLabel, cancelLabel (null hides Cancel), danger,
     *       input: {label, value, minLength, maxLength, multiline, required}
     * onConfirm(value) runs on confirm; value is the trimmed input text or true.
     */
    function modal(opts, onConfirm) {
        opts = opts || {};
        var previous = document.activeElement;
        var input = null, error = el("div", { "class": "ucm-modal-error", role: "alert" });
        var titleId = "ucm-modal-title-" + new Date().getTime();
        var field = null;
        if (opts.input) {
            input = el(opts.input.multiline ? "textarea" : "input", {
                "class": "ucm-modal-input", type: opts.input.multiline ? null : "text",
                maxlength: opts.input.maxLength || 1000, "aria-label": opts.input.label || opts.title });
            input.value = opts.input.value || "";
            field = el("label", { "class": "ucm-modal-label" },
                el("span", { text: opts.input.label || "" }), input,
                opts.input.minLength ? el("span", { "class": "ucm-sub",
                    text: "At least " + opts.input.minLength + " characters." }) : null);
        }
        var ok = el("button", { "class": "btn " + (opts.danger ? "btn-danger" : "btn-primary"), type: "button",
            text: opts.confirmLabel || "OK" });
        var cancel = opts.cancelLabel === null ? null
            : el("button", { "class": "btn", type: "button", text: opts.cancelLabel || "Cancel" });
        var dialog = el("div", { "class": "ucm-modal", role: "dialog", "aria-modal": "true", "aria-labelledby": titleId },
            el("h3", { id: titleId, text: opts.title || "" }),
            opts.message ? el("p", { "class": "ucm-modal-message", text: opts.message }) : null,
            field, error,
            el("div", { "class": "ucm-actions" }, ok, cancel));
        var backdrop = el("div", { "class": "ucm-modal-backdrop" }, dialog);

        function close() {
            document.removeEventListener("keydown", onKey, true);
            if (backdrop.parentNode) { backdrop.parentNode.removeChild(backdrop); }
            if (previous && previous.focus) { previous.focus(); }
        }
        function submit() {
            var value = true;
            if (input) {
                value = input.value.replace(/^\s+|\s+$/g, "");
                var min = opts.input.minLength || (opts.input.required ? 1 : 0);
                if (value.length < min) {
                    error.textContent = min > 1 ? "Enter at least " + min + " characters." : "A value is required.";
                    input.focus();
                    return;
                }
            }
            close();
            if (onConfirm) { onConfirm(value); }
        }
        function onKey(e) {
            if (e.key === "Escape" || e.keyCode === 27) {
                e.preventDefault();
                close();
            } else if ((e.key === "Enter" || e.keyCode === 13) && e.target === input && !opts.input.multiline) {
                e.preventDefault();
                submit();
            } else if (e.key === "Tab" || e.keyCode === 9) {
                var focusable = [input, ok, cancel].filter(function (n) { return n; });
                var i = focusable.indexOf(document.activeElement);
                var next = e.shiftKey ? (i <= 0 ? focusable.length - 1 : i - 1) : (i + 1) % focusable.length;
                e.preventDefault();
                focusable[next].focus();
            }
        }
        ok.addEventListener("click", submit);
        if (cancel) { cancel.addEventListener("click", close); }
        document.addEventListener("keydown", onKey, true);
        document.body.appendChild(backdrop);
        (input || ok).focus();
    }

    function notify(message, title) {
        modal({ title: title || "Request failed", message: message, cancelLabel: null });
    }

    function confirmAction(title, message, confirmLabel, onConfirm, danger) {
        modal({ title: title, message: message, confirmLabel: confirmLabel, danger: danger },
            function () { onConfirm(); });
    }

    function askText(title, message, input, confirmLabel, onConfirm) {
        modal({ title: title, message: message, input: input, confirmLabel: confirmLabel || "OK" }, onConfirm);
    }

    /*
     * Shown while stored catalogue summaries are older than the app (facets.summary, D-066). Provider and the other
     * existing filters work on old summaries; wave, analytic story and data source need Reindex.
     */
    function reindexHint(summary, active, action) {
        if (!summary || !(summary.outdated > 0)) { return null; }
        var box = stateBox("warn", "Reindex needed to enable the wave, analytic story and data source filters",
            summary.outdated + " of " + (active || 0) + " active use cases were summarised by an earlier version, so they have no wave, " +
            "analytic story or data source yet and those three filters skip them. The provider filter and the other filters work. " +
            "Reindex re-reads the stored records (no download).");
        if (action) { box.appendChild(action); }
        return box;
    }

    /* Display names of the providers the app knows; any other provider id is shown as it is. */
    var PROVIDER_LABELS = { fenre: "Fenre", escu: "ESCU" };

    function providerLabel(provider) {
        return PROVIDER_LABELS[provider] || provider || "";
    }

    function providerBadge(provider) {
        if (!provider) { return null; }
        var b = badge(providerLabel(provider), "provider");
        b.setAttribute("title", "Content provider: " + provider);
        return b;
    }

    /* Keys match splunk_ucm.catalog.quality.QUALITY_FLAGS (checked by a unit test). */
    var QUALITY_FLAGS = {
        unreviewed: ["unreviewed", "No review status, or draft"],
        reviewer_na: ["reviewer N/A", "Reviewer recorded as N/A"],
        ai_reviewed: ["AI reviewer", "Reviewer is an automated or AI agent"],
        sme_review_pending: ["SME review pending", "Compliance mapping awaits SME review"],
        unbounded_index: ["index=*", "Primary SPL searches index=* or no index"],
        es_required: ["needs ES", "Requires Splunk Enterprise Security"],
        duplicate_spl: ["duplicate SPL", "Primary SPL is identical to another use case"],
        provider_twin: ["twin in other provider", "Primary SPL is identical to a use case from another provider", "info"]
    };

    function qualityBadges(flags) {
        return (flags || []).filter(function (f) { return QUALITY_FLAGS[f]; }).map(function (f) {
            var b = badge(QUALITY_FLAGS[f][0], QUALITY_FLAGS[f][2] || "warn");
            b.setAttribute("title", QUALITY_FLAGS[f][1]);
            return b;
        });
    }

    /*
     * Client-side guard for the interactive search (D-058, D-062). It mirrors splunk_ucm.spl: the lists equal
     * analysis.SIDE_EFFECT_COMMANDS, policy.INDIRECT_COMMANDS and policy.HIDDEN_SPL_COMMANDS, and the segmentation
     * equals analysis._split_pipeline (both checked by unit tests, including a parity run over the fixtures).
     * It is a convenience guard for the user's own search, not a security boundary: Splunk enforces
     * the user's permissions, and macros are only checked through the stored server-side parse.
     */
    var SIDE_EFFECT_COMMANDS = ["outputlookup", "outputcsv", "collect", "mcollect", "meventcollect", "tscollect",
        "sendemail", "sendalert", "delete", "script", "run", "sendresults", "summaryindex",
        "dbxoutput", "runshellscript", "deletemodel", "dump", "crawl", "outputtelemetry"];
    var INDIRECT_COMMANDS = ["map", "savedsearch", "loadjob", "rest", "dbxquery", "dbxlookup", "dbxinputs"];
    var HIDDEN_SPL_COMMANDS = ["savedsearch", "loadjob", "dbxquery"];
    var GENERATING_COMMANDS = ["tstats", "mstats", "inputlookup", "rest", "datamodel", "from", "makeresults",
        "metadata", "metasearch", "dbinspect", "eventcount", "pivot", "search", "loadjob",
        "savedsearch", "dbxquery", "inputcsv", "mcatalog", "walklex", "union", "multisearch"];
    var LEADING_COMMANDS = SIDE_EFFECT_COMMANDS.concat(INDIRECT_COMMANDS);
    var SUB_LEADING_COMMANDS = LEADING_COMMANDS.concat(GENERATING_COMMANDS);
    var SUBPIPELINE_HOSTS = ["appendpipe"];
    var MAX_NESTING = 3;
    var FIT_INTO = /(?:^|[|\[])\s*fit\b[^|\]]*?\binto\b/i;
    var SAVEDSEARCH_DATASET = /(?:^|[^\w.:])savedsearch:/i;
    var MACRO = /`\s*([A-Za-z0-9_\-.:]+)\s*(\(([^`]*)\))?\s*`/;
    var MAP_SEARCH = /(?:^|[^\w.])search\s*=\s*"((?:[^"\\]|\\.)*)"/ig;
    var MAP_SAVED = /(?:^|[^\w.])savedsearch\s*=/i;
    var ESCAPED = /\\(["\\])/g;

    function maskQuotes(spl) {
        return spl.replace(/"(?:[^"\\]|\\.)*"/g, function (m) { return '"' + new Array(m.length - 1).join("\u0001") + '"'; });
    }

    function uniq(list) { return list.filter(function (c, i) { return list.indexOf(c) === i; }); }

    /* [start, end, kind] per segment, the way analysis._split_pipeline cuts them. */
    function splitSegments(masked) {
        var segments = [];
        var starts = [[0, "level"]];
        var inMacro = false;
        var i, ch, top;
        for (i = 0; i < masked.length; i++) {
            ch = masked.charAt(i);
            if (ch === "`") {
                inMacro = !inMacro;
            } else if (inMacro) {
                continue;
            } else if (ch === "[") {
                top = starts[starts.length - 1];
                segments.push([top[0], i, top[1]]);
                starts[starts.length - 1] = [i, "cont"];
                starts.push([i + 1, "sub"]);
            } else if (ch === "]" && starts.length > 1) {
                top = starts.pop();
                segments.push([top[0], i, top[1]]);
                starts[starts.length - 1] = [i + 1, "cont"];
            } else if (ch === "|") {
                top = starts[starts.length - 1];
                segments.push([top[0], i, top[1]]);
                starts[starts.length - 1] = [i + 1, "pipe"];
            }
        }
        top = starts[starts.length - 1];
        segments.push([top[0], masked.length, top[1]]);
        return segments.filter(function (seg) { return masked.substring(seg[0], seg[1]).trim(); });
    }

    /*
     * The command a segment runs (analysis._segment_command): a leading command name in a bracket,
     * an unprefixed search or a map string is the command Splunk runs, and appendpipe's bracket
     * always starts with a command (D-068).
     */
    function segmentCommand(text, kind, host) {
        if (kind === "cont") { return null; }
        var word = /^\s*([A-Za-z_][A-Za-z0-9_]*)/.exec(text);
        if (kind === "pipe") { return word ? word[1].toLowerCase() : null; }
        if (!word || /^\s*(?:!=|[=<>])/.test(text.substring(word[0].length))) { return "search"; }
        var name = word[1].toLowerCase();
        if (kind === "sub" && (SUBPIPELINE_HOSTS.indexOf(host) >= 0 || SUB_LEADING_COMMANDS.indexOf(name) >= 0)) { return name; }
        return LEADING_COMMANDS.indexOf(name) >= 0 ? name : "search";
    }

    /* [start, end, kind, command] per segment, as analysis.segment_commands returns them. */
    function segmentCommands(masked) {
        var segments = splitSegments(masked);
        var byEnd = {};
        segments.forEach(function (seg) { byEnd[seg[1]] = seg; });
        return segments.map(function (seg) {
            var host = "";
            var holder = seg[2] === "sub" ? byEnd[seg[0] - 1] : null;
            if (holder && holder[2] === "pipe") {
                var hw = /^\s*([A-Za-z_][A-Za-z0-9_]*)/.exec(masked.substring(holder[0], seg[0] - 1));
                host = hw ? hw[1].toLowerCase() : "";
            }
            return [seg[0], seg[1], seg[2], segmentCommand(masked.substring(seg[0], seg[1]), seg[2], host)];
        });
    }

    /* Commands in pipeline order, found the way analysis.analyze finds them. */
    function splCommands(spl) {
        var commands = [];
        segmentCommands(maskQuotes(spl || "")).forEach(function (seg) {
            if (seg[3]) { commands.push(seg[3]); }
        });
        return commands;
    }

    /* The quoted search="..." of every map command, and how many map calls have no readable one. */
    function mapCalls(spl) {
        var masked = maskQuotes(spl);
        var searches = [];
        var opaque = 0;
        segmentCommands(masked).forEach(function (seg) {
            if (seg[3] !== "map") { return; }
            var maskedSeg = masked.substring(seg[0], seg[1]);
            var found = [];
            var m;
            MAP_SEARCH.lastIndex = 0;
            var raw = spl.substring(seg[0], seg[1]);
            while ((m = MAP_SEARCH.exec(raw)) !== null) { found.push(m[1].replace(ESCAPED, "$1")); }
            if (!found.length || MAP_SAVED.test(maskedSeg)) { opaque += 1; }
            searches = searches.concat(found);
        });
        return { searches: searches, opaque: opaque };
    }

    /* Searches carried inside map strings, analysed recursively (D-062). */
    function scanNested(spl, depth, out) {
        var calls = mapCalls(spl);
        if (calls.opaque) { out.hidden.push("map (search not readable)"); }
        calls.searches.forEach(function (inner) {
            if (depth > MAX_NESTING) { out.hidden.push("map (nested too deeply)"); return; }
            var masked = maskQuotes(inner);
            out.commands = out.commands.concat(splCommands(inner));
            if (MACRO.test(masked)) { out.hidden.push("map (macro in nested search)"); }
            if (FIT_INTO.test(masked)) { out.side.push("fit into"); }
            if (SAVEDSEARCH_DATASET.test(masked)) { out.indirect.push("savedsearch: dataset"); }
            scanNested(inner, depth + 1, out);
        });
        return out;
    }

    function splPolicy(spl) {
        var masked = maskQuotes(spl || "");
        var commands = uniq(splCommands(spl));
        var nested = scanNested(spl || "", 1, { commands: [], side: [], indirect: [], hidden: [] });
        var nestedCommands = uniq(nested.commands);
        var every = uniq(commands.concat(nestedCommands));
        var sidePatterns = FIT_INTO.test(masked) ? ["fit into"] : [];
        var indirectPatterns = SAVEDSEARCH_DATASET.test(masked) ? ["savedsearch: dataset"] : [];
        var side = uniq(every.filter(function (c) { return SIDE_EFFECT_COMMANDS.indexOf(c) >= 0; }).concat(sidePatterns, nested.side));
        var indirect = uniq(every.filter(function (c) { return INDIRECT_COMMANDS.indexOf(c) >= 0; }).concat(indirectPatterns, nested.indirect));
        var hidden = uniq(every.filter(function (c) { return HIDDEN_SPL_COMMANDS.indexOf(c) >= 0; })
            .concat(indirect.indexOf("savedsearch: dataset") >= 0 ? ["savedsearch: dataset"] : [], nested.hidden));
        return { commands: splCommands(spl), sideEffects: side, indirect: indirect, nested: nestedCommands, hidden: hidden,
            hasMacros: MACRO.test(masked) };
    }

    /* The form Splunk's parser needs: a leading search term needs the search command. */
    function searchableSpl(spl) {
        var text = (spl || "").trim();
        var lowered = text.toLowerCase();
        if (!text || lowered.charAt(0) === "|" || lowered.indexOf("search ") === 0 || lowered.indexOf("search\n") === 0) { return text; }
        return "search " + text;
    }

    /*
     * Decide whether the interactive search may be offered for this SPL. `validation` is the stored
     * server-side parse; it only describes the primary search of the current content version.
     */
    function searchGuard(spl, validation, sourceHash, isPrimary) {
        if (!spl || !spl.trim()) { return { ok: false, reason: "This use case has no SPL to run.", warnings: [] }; }
        var p = splPolicy(spl);
        var v = isPrimary && validation && validation.source_hash === sourceHash ? validation : null;
        var side = p.sideEffects.slice();
        if (v) { (v.side_effects || []).forEach(function (c) { if (side.indexOf(c) < 0) { side.push(c); } }); }
        if (side.length) {
            var inside = side.filter(function (c) { return p.nested.indexOf(c) >= 0; });
            return { ok: false, warnings: [], reason: "Not offered: the search contains side-effect commands (" + side.join(", ") +
                ")" + (inside.length ? ", some inside a map search," : "") +
                ". These write or send data and are refused here as they are in the preview." };
        }
        var hidden = p.hidden.slice();
        if (v) { (v.indirect_commands || []).forEach(function (c) { if (HIDDEN_SPL_COMMANDS.indexOf(c) >= 0 && hidden.indexOf(c) < 0) { hidden.push(c); } }); }
        if (hidden.length) {
            return { ok: false, warnings: [], reason: "Not offered: the search runs SPL or reaches data that this text does not show (" +
                hidden.join(", ") + "), so it cannot be checked for side effects here. Review the referenced search or the map search yourself and run it in Search." };
        }
        if (p.hasMacros && !(v && v.parse_ok)) {
            return { ok: false, warnings: [], reason: isPrimary
                ? "Not offered yet: the search uses macros, and macros could hide side-effect commands. Use \"Parse and sample fields\" so Splunk expands them and the result can be checked."
                : "Not offered: the search uses macros, and the macro check is only available for the primary search." };
        }
        var warnings = [];
        var indirect = p.indirect.slice();
        if (v) { (v.indirect_commands || []).concat(v.unknown_commands || []).forEach(function (c) { if (indirect.indexOf(c) < 0) { indirect.push(c); } }); }
        if (indirect.length) {
            warnings.push("The search uses commands that can run other searches or reach data this text does not show (" +
                indirect.join(", ") + "). They run with your permissions.");
        }
        return { ok: true, reason: "", warnings: warnings };
    }

    /* GET against a native splunkd endpoint through Splunk Web (the user's own session). */
    function rawGet(path, params) {
        var deferred = $.Deferred();
        $.ajax({ url: splunkUtil.make_url("/splunkd/__raw/" + path), type: "GET", data: $.extend({ output_mode: "json" }, params || {}),
            dataType: "json", headers: { "X-Requested-With": "XMLHttpRequest" } })
            .done(function (data) { deferred.resolve(data); })
            .fail(function (xhr) { deferred.reject({ status: xhr.status, message: errorMessage(xhr) }); });
        return deferred.promise();
    }

    var ACCESS_LABELS = { met: ["scheduler access: met", "ok"], partial: ["scheduler access: partial", "warn"],
        not_met: ["scheduler access: not met", "error"], unverified: ["scheduler access: not verified", "info"],
        not_applicable: ["scheduler access: n/a", "neutral"] };

    function accessBadge(access) {
        if (!access) { return null; }
        var l = ACCESS_LABELS[access.status] || [access.status, "neutral"];
        var b = badge(l[0], l[1]);
        b.setAttribute("title", access.detail || "");
        return b;
    }

    /* Warning shown on the deployment panel; a search that cannot see its data reports success with no results. */
    function accessBox(access) {
        if (!access || access.status === "met" || access.status === "not_applicable") { return null; }
        if (access.status === "unverified") {
            return stateBox("info", "Scheduler index access is not verified", access.detail);
        }
        return stateBox("warn", "The scheduler account may not see this search's data", access.detail +
            " Enabling needs an audited override reason.");
    }

    /* Messages of a sync or import job, its own first and then those of its failed categories. */
    function jobErrors(job) {
        var out = ((job && job.errors) || []).map(function (e) { return e.message || e.code || "failed"; });
        ((job && job.results) || []).forEach(function (r) {
            if (r.status === "failed") {
                out.push("category " + r.category_id + ": " + (((r.errors || [])[0] || {}).message || "failed"));
            }
        });
        return out;
    }

    /* A failed latest job is the first thing the administrator needs; the history table carries the rest. */
    function jobFailureBox(jobs) {
        var latest = (jobs || [])[0];
        if (!latest || latest.status !== "failed") { return null; }
        var first = (latest.errors || [])[0] || {};
        var detail = jobErrors(latest)[0] || "No error message was recorded for this job.";
        return stateBox("error", "The latest synchronization failed" + (first.code ? " (" + first.code + ")" : ""),
            detail + " Requested " + (latest.requested_at || "") + (latest.requested_by ? " by " + latest.requested_by : "") + ".");
    }

    function yesNo(value) { return value === true ? "yes" : (value === false ? "no" : "unknown"); }

    /* Overview card for the account that runs deployed searches (D-063). */
    function schedulerCard(s) {
        var card = el("div", { "class": "ucm-card ucm-scheduler" }, el("h3", { text: "Scheduler account" }));
        if (!s) { card.appendChild(el("div", { "class": "ucm-sub", text: "Not available." })); return card; }
        var owner = s.owner ? el("span", { "class": "ucm-mono", text: s.owner }) : "not configured";
        if (s.status === "no_owner") {
            card.appendChild(stateBox("warn", "No scheduled owner is configured.",
                "Deployed searches cannot be written until [deployment] scheduled_owner names a user with the ucm_scheduler role (local/ucm.conf)."));
        } else if (s.status === "user_not_found") {
            card.appendChild(stateBox("warn", "The scheduled owner was not found.", s.reason));
        } else if (s.status !== "ok") {
            card.appendChild(stateBox("info", "The scheduler account's roles could not be read.",
                (s.reason || "") + " Index access is shown as not verified; this does not block deployment."));
        }
        var rows = [["Owner configured", owner]];
        if (s.status === "ok") {
            rows.push(["Roles found", (s.roles || []).length ? (s.roles || []).join(", ") : "none"]);
            rows.push(["Can search internal indexes (_internal, _audit)", yesNo(s.internal_access)]);
            rows.push(["Default indexes", String(s.default_indexes || 0)]);
        }
        rows.push(["Discovery scans internal indexes", yesNo(s.discovery_include_internal)]);
        var list = el("dl", { "class": "ucm-kv" });
        rows.forEach(function (r) { list.appendChild(el("dt", { text: r[0] })); list.appendChild(el("dd", {}, r[1])); });
        card.appendChild(list);
        if (s.status === "ok" && s.internal_access === false) {
            card.appendChild(el("div", { "class": "ucm-sub", text: "Deployed searches that read _internal or _audit would run as this account, return no events and still report success. " +
                "A role needs _* (or the index name) in srchIndexesAllowed; * does not include internal indexes." }));
        }
        if (s.has_filter) {
            card.appendChild(el("div", { "class": "ucm-sub", text: "A search filter (srchFilter) applies to this account and can hide events even where an index is searchable." }));
        }
        if (s.has_disallowed) {
            card.appendChild(el("div", { "class": "ucm-sub", text: "The account's roles disallow some indexes (srchIndexesDisallowed wins over allowed)." }));
        }
        if (s.discovery_include_internal === false) {
            card.appendChild(el("div", { "class": "ucm-sub", text: "Discovery runs without internal indexes ([discovery] include_internal = false), so readiness shows internal indexes as not verified rather than present." }));
        }
        return card;
    }

    /* The KV Store returns at most max_rows_per_query rows per query (issue #14); a total near it is shown, not hidden. */
    function rowBoundNote(rows, limit) {
        limit = limit || 50000;
        if (!rows || rows < Math.floor(limit * 0.9)) { return null; }
        return stateBox("warn", rows >= limit ? "The catalogue reached the KV Store row bound" : "The catalogue is close to the KV Store row bound",
            "The catalogue holds " + rows + " active use cases and the KV Store returns at most " + limit +
            " rows per query (limits.conf [kvstore] max_rows_per_query). Totals at that number are lower bounds, and filters " +
            "that join readiness or bookmarks refuse above it. Raise the platform setting and set [catalog] kv_row_limit to " +
            "the same value (operator guide, section 12).");
    }

    /* Advisory lint findings (spl/lint.py). Dismissing only hides an item until the page is rendered again; nothing is stored. */
    function lintBox(findings, intro) {
        var items = (findings || []).filter(function (f) { return f && f.rule && f.message; });
        if (!items.length) { return null; }
        var list = el("ul", { "class": "ucm-lint-list" });
        var box = stateBox("warn", "SPL lint (advisory): " + items.length + (items.length === 1 ? " finding" : " findings"),
            intro || "These do not change readiness, approval or deployment. Dismiss hides a finding until the page is reloaded.");
        function dismiss(item) {
            list.removeChild(item);
            if (!list.childNodes.length && box.parentNode) { box.parentNode.removeChild(box); }
        }
        items.forEach(function (f) {
            var where = "segment " + f.segment + " (" + f.command + ")" +
                (f.in_map ? ", inside a map search" : "") + (f.search === "cim" ? ", CIM search" : "") +
                (f.count > 1 ? ", " + f.count + " times" : "");
            var item = el("li", { "class": "ucm-lint-item" },
                badge(f.rule, "warn"), " ", el("span", { text: f.message }),
                el("div", { "class": "ucm-sub" }, where + ": ", el("span", { "class": "ucm-mono", text: f.call || "" })),
                f.suggestion ? el("div", { "class": "ucm-sub", text: "Suggested rewrite: " + f.suggestion }) : null);
            item.appendChild(el("button", { "class": "btn btn-link ucm-lint-dismiss", type: "button", text: "Dismiss",
                onclick: function () { dismiss(item); } }));
            list.appendChild(item);
        });
        box.appendChild(list);
        return box;
    }

    return {
        accessBadge: accessBadge, accessBox: accessBox, lintBox: lintBox, rowBoundNote: rowBoundNote, jobErrors: jobErrors, jobFailureBox: jobFailureBox, schedulerCard: schedulerCard,
        modal: modal, qualityBadges: qualityBadges, QUALITY_FLAGS: QUALITY_FLAGS, providerBadge: providerBadge, providerLabel: providerLabel, reindexHint: reindexHint, notify: notify, confirmAction: confirmAction, askText: askText,
        get: get, post: post, postRaw: postRaw, el: el, clear: clear, badge: badge,
        criticalityBadge: criticalityBadge, chips: chips, stateBox: stateBox, queryParams: queryParams,
        setQueryParams: setQueryParams, pager: pager, debounce: debounce, shortSha: shortSha,
        readinessBadge: readinessBadge, statusBadge: statusBadge, resultSummary: resultSummary, resultBadges: resultBadges, helpHeader: helpHeader, legend: legend,
        selectAll: selectAll, percent: percent, readinessKpis: readinessKpis, kpiCard: kpiCard, kpiStrip: kpiStrip, rawGet: rawGet, splCommands: splCommands, splPolicy: splPolicy,
        searchableSpl: searchableSpl, searchGuard: searchGuard, SIDE_EFFECT_COMMANDS: SIDE_EFFECT_COMMANDS,
        INDIRECT_COMMANDS: INDIRECT_COMMANDS, HIDDEN_SPL_COMMANDS: HIDDEN_SPL_COMMANDS, READINESS_HELP: READINESS_HELP, STATUS_HELP: STATUS_HELP,
        STATUSES: ["met", "partial", "not_met", "unknown", "unverified", "not_applicable"],
        READINESS_STATES: ["ready", "partially_ready", "not_ready", "blocked", "insufficient_evidence"],
        DOMAINS: ["security", "infrastructure", "network", "application", "database", "cloud", "endpoint",
            "identity", "ot_ics", "observability", "compliance", "business", "other"],
        CRITICALITY: ["critical", "high", "medium", "low", "unknown"],
        DIFFICULTY: ["beginner", "intermediate", "advanced", "expert", "unknown"]
    };
});
