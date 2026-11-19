/*
 * Shared UI helpers for Use Case Manager views.
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

    return {
        get: get, post: post, postRaw: postRaw, el: el, clear: clear, badge: badge,
        criticalityBadge: criticalityBadge, chips: chips, stateBox: stateBox, queryParams: queryParams,
        setQueryParams: setQueryParams, pager: pager, debounce: debounce, shortSha: shortSha,
        DOMAINS: ["security", "infrastructure", "network", "application", "database", "cloud", "endpoint",
            "identity", "ot_ics", "observability", "compliance", "business", "other"],
        CRITICALITY: ["critical", "high", "medium", "low", "unknown"],
        DIFFICULTY: ["beginner", "intermediate", "advanced", "expert", "unknown"]
    };
});
