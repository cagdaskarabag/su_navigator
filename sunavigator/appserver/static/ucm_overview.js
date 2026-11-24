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
    var root = document.getElementById("ucm-overview-kpis");

    function deploymentKpi(data) {
        var s = (data && data.summary) || {};
        var by = s.by_state || {};
        var live = s.by_live || {};
        return { label: "Deployed", value: String(by.deployed || 0),
            detail: (live.enabled || 0) + " enabled; " + (s.total || 0) + " deployments recorded",
            how: "Deployments whose workflow state is deployed. Enabled is the number of those whose saved search is enabled in Splunk at the last check." };
    }

    var hint = el("div", {});

    function render(activeTotal, summary, deployments) {
        var kpis = ucm.readinessKpis(activeTotal, summary);
        if (deployments) { kpis.push(deploymentKpi(deployments)); }
        ucm.clear(root).appendChild(el("div", {}, hint,
            ucm.kpiStrip(kpis),
            el("div", { "class": "ucm-sub", text: "These figures come from the stored catalogue, readiness and deployment records. " +
                "Open Readiness for the per-use-case detail behind them." }),
            summary && summary.scheduler ? ucm.schedulerCard(summary.scheduler) : null));
    }

    ucm.get("catalog/facets").done(function (f) {
        var note = ucm.reindexHint(f && f.summary, f && f.active,
            el("div", {}, el("a", { href: "ucm_content_admin", text: "Open Content Administration to run Reindex" })));
        if (note) { hint.appendChild(note); }
    });

    $.when(ucm.get("catalog", { count: 1 }), ucm.get("readiness/summary")).done(function (catalog, summary) {
        var activeTotal = catalog.total;
        ucm.get("deployments", { summary: 1, count: 1 }).done(function (d) { render(activeTotal, summary, d); })
            .fail(function () { render(activeTotal, summary, null); });
    }).fail(function (err) {
        ucm.clear(root).appendChild(ucm.stateBox("error", "The key figures could not be loaded.", err.message));
    });
}
