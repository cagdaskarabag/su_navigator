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
        unverified: "Not checked yet: the inventory cannot evaluate it (fields not sampled, event conditions, permissions, " +
            "free-text sources, SPL not parsed). Left out of score and coverage. It is not a failure and does not mean the data is absent.",
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

    /* Keys match splunk_ucm.catalog.quality.QUALITY_FLAGS (checked by a unit test). */
    var QUALITY_FLAGS = {
        unreviewed: ["unreviewed", "No review status, or draft"],
        reviewer_na: ["reviewer N/A", "Reviewer recorded as N/A"],
        ai_reviewed: ["AI reviewer", "Reviewer is an automated or AI agent"],
        sme_review_pending: ["SME review pending", "Compliance mapping awaits SME review"],
        unbounded_index: ["index=*", "Primary SPL searches index=* or no index"],
        es_required: ["needs ES", "Requires Splunk Enterprise Security"],
        duplicate_spl: ["duplicate SPL", "Primary SPL is identical to another use case"]
    };

    function qualityBadges(flags) {
        return (flags || []).filter(function (f) { return QUALITY_FLAGS[f]; }).map(function (f) {
            var b = badge(QUALITY_FLAGS[f][0], "warn");
            b.setAttribute("title", QUALITY_FLAGS[f][1]);
            return b;
        });
    }

    return {
        modal: modal, qualityBadges: qualityBadges, QUALITY_FLAGS: QUALITY_FLAGS, notify: notify, confirmAction: confirmAction, askText: askText,
        get: get, post: post, postRaw: postRaw, el: el, clear: clear, badge: badge,
        criticalityBadge: criticalityBadge, chips: chips, stateBox: stateBox, queryParams: queryParams,
        setQueryParams: setQueryParams, pager: pager, debounce: debounce, shortSha: shortSha,
        readinessBadge: readinessBadge, statusBadge: statusBadge, helpHeader: helpHeader, legend: legend,
        selectAll: selectAll, READINESS_HELP: READINESS_HELP, STATUS_HELP: STATUS_HELP,
        STATUSES: ["met", "partial", "not_met", "unknown", "unverified", "not_applicable"],
        READINESS_STATES: ["ready", "partially_ready", "not_ready", "blocked", "insufficient_evidence"],
        DOMAINS: ["security", "infrastructure", "network", "application", "database", "cloud", "endpoint",
            "identity", "ot_ics", "observability", "compliance", "business", "other"],
        CRITICALITY: ["critical", "high", "medium", "low", "unknown"],
        DIFFICULTY: ["beginner", "intermediate", "advanced", "expert", "unknown"]
    };
});
