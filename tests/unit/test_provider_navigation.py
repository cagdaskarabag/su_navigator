"""Sprint 11 (D-066): provider, wave, analytic story and data source facets, twin lineage, quality options."""

import copy
import json
import unittest

import helpers  # noqa: F401  (sets sys.path)
from splunk_ucm import __version__
from splunk_ucm.audit import AuditService
from splunk_ucm.catalog.derived import FACETS_KEY, FACETS_VERSION, compute_facets, get_facets, refresh_derived
from splunk_ucm.catalog.detail import UseCaseDetailService
from splunk_ucm.catalog.lineage import AUTHORITY, find_twins
from splunk_ucm.catalog.query import AVAILABILITY, SORTS, CatalogFilter, CatalogQueryService, build_query
from splunk_ucm.catalog.quality import FLAG_ORDER
from splunk_ucm.catalog.summary import SUMMARY_VERSION, catalog_summary
from splunk_ucm.content.escu.package import build_bundle
from splunk_ucm.content.importer import BundleImportService
from splunk_ucm.content.reindex import ReindexService
from splunk_ucm.content.sync import SyncService
from splunk_ucm.errors import ValidationError
from splunk_ucm.maintenance.migrations import MIGRATIONS, STATE_KEY, MigrationRunner
from splunk_ucm.storage import collections as C
from splunk_ucm.storage.kvstore import InMemoryStore
from splunk_ucm.storage.repositories import CategoryRepository, ContentRepository
from splunk_ucm.util import git_blob_sha
from unit.test_api_worker import call, make_ctx
from unit.test_escu import DEFENDER, FIXTURE, LOGONS, POWERSHELL, SCANNING

TWIN_FENRE = "fenre:UC-10.4.24"
STATES = ("ready", "partially_ready", "not_ready", "blocked", "insufficient_evidence")


def escu_defender_spl():
    bundle, _ = build_bundle(FIXTURE)
    for rec in bundle["records"]:
        raw = json.loads(rec["content"])
        if raw["id"].endswith("555555555501"):
            return raw["search"]
    raise AssertionError("fixture changed")


def two_provider_store(twin=True, escu=True):
    """Fenre fixture records plus the ESCU fixture package; with ``twin``, Fenre 10.4.24 carries the SPL of
    the ESCU Defender detection."""
    store = InMemoryStore()
    service = BundleImportService(SyncService(store, AuditService(store)), 5 * 1024 * 1024)
    fenre = helpers.fixture_bundle()
    if twin:
        for rec in fenre["records"]:
            if rec["record_id"] == "10.4.24":
                raw = json.loads(rec["content"])
                raw["spl"] = escu_defender_spl()
                rec["content"] = json.dumps(raw)
                rec["blob_sha"] = git_blob_sha(rec["content"].encode("utf-8"))
    service.import_bundle(fenre, "admin")
    if escu:
        bundle, _ = build_bundle(FIXTURE)
        service.import_bundle(copy.deepcopy(bundle), "admin")
    return store


def detail(store, content_id):
    return UseCaseDetailService(ContentRepository(store), CategoryRepository(store)).get(content_id)


def catalog_docs(store):
    return {d["_key"]: d for d in store.query(C.CATALOG, None)}


def seed_readiness(store):
    keys = sorted(catalog_docs(store))
    store.batch_save(C.READINESS, [{"_key": k, "state": STATES[i % len(STATES)]} for i, k in enumerate(keys[:-3])])


class SummaryFieldsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = two_provider_store()
        cls.docs = catalog_docs(cls.store)

    def test_summary_version_is_six_and_stored(self):
        self.assertEqual(SUMMARY_VERSION, 6)
        self.assertTrue(all(d["summary_version"] == 6 for d in self.docs.values()))

    def test_escu_summary_carries_stories_and_data_sources_from_the_record(self):
        d = self.docs["escu_UC-11111111-2222-4333-8444-555555555503"]
        self.assertEqual(d["analytic_stories"], ["Brute Force", "Windows Account Discovery"])
        self.assertEqual(d["data_sources"], ["Windows Event Log Security 4625"])
        self.assertEqual(d["wave"], "")

    def test_fenre_summary_carries_wave_and_no_stories(self):
        d = self.docs["fenre_UC-1.1.1"]
        self.assertEqual((d["wave"], d["analytic_stories"], d["data_sources"]), ("crawl", [], []))

    def test_escu_record_without_data_sources_has_an_empty_list(self):
        d = self.docs["escu_UC-11111111-2222-4333-8444-555555555505"]
        self.assertEqual((d["analytic_stories"], d["data_sources"]), (["Malicious PowerShell"], []))

    def test_values_are_cleaned_capped_and_comma_free(self):
        from splunk_ucm.catalog import summary as S
        self.assertEqual(S._facet_values(["a, b", "  a  b ", "", 5, "x" * 500]), ["a b", "x" * 199 + "\u2026"])
        self.assertEqual(len(S._facet_values(["s%d" % i for i in range(100)])), S.MAX_FACET_ITEMS)

    def test_the_detail_view_lists_them_too(self):
        d = detail(self.store, LOGONS)
        self.assertEqual((d["analytic_stories"], d["data_sources"]),
                         (["Brute Force", "Windows Account Discovery"], ["Windows Event Log Security 4625"]))


class ProviderAndFacetFilterTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = two_provider_store()
        cls.svc = CatalogQueryService(cls.store, max_page_size=100)
        cls.all = [d for d in catalog_docs(cls.store).values() if d["provider_status"] == "active"]

    def keys(self, **kw):
        return sorted(i["_key"] for i in self.svc.search(CatalogFilter(count=100, **kw))["items"])

    def expect(self, pred):
        return sorted(d["_key"] for d in self.all if pred(d))

    def test_provider_filter_single_and_several(self):
        self.assertEqual(self.keys(providers=["escu"]), self.expect(lambda d: d["provider"] == "escu"))
        self.assertEqual(self.keys(providers=["fenre"]), self.expect(lambda d: d["provider"] == "fenre"))
        self.assertEqual(self.keys(providers=["fenre", "escu"]), self.expect(lambda d: True))
        self.assertEqual(self.keys(providers=["nobody"]), [])

    def test_provider_values_are_validated(self):
        for bad in (["ESCU"], ["a b"], ["x" * 90], ["$ne"]):
            with self.assertRaises(ValidationError):
                self.svc.search(CatalogFilter(providers=bad))

    def test_wave_filter(self):
        waves = {d["wave"] for d in self.all if d.get("wave")}
        self.assertTrue(waves)
        for wave in waves:
            self.assertEqual(self.keys(waves=[wave]), self.expect(lambda d: d.get("wave") == wave), wave)
        self.assertEqual(self.keys(waves=sorted(waves)), self.expect(lambda d: d.get("wave") in waves))
        for bad in (["fast"], ["Crawl"], [""]):
            with self.assertRaises(ValidationError):
                self.svc.search(CatalogFilter(waves=bad))

    def test_story_and_data_source_filters(self):
        self.assertEqual(self.keys(stories=["Brute Force"]), ["escu_UC-11111111-2222-4333-8444-555555555503"])
        self.assertEqual(self.keys(stories=["Brute Force", "Network Scanning"]),
                         sorted(["escu_UC-11111111-2222-4333-8444-555555555503",
                                 "escu_UC-11111111-2222-4333-8444-555555555502"]))
        self.assertEqual(self.keys(data_sources=["Sysmon EventID 13"]), ["escu_UC-11111111-2222-4333-8444-555555555501"])
        self.assertEqual(self.keys(stories=["Brute Force"], data_sources=["Sysmon EventID 13"]), [])
        self.assertEqual(self.keys(stories=["No such story"]), [])
        with self.assertRaises(ValidationError):
            self.svc.search(CatalogFilter(stories=["bad\x00value"]))
        with self.assertRaises(ValidationError):
            self.svc.search(CatalogFilter(data_sources=["x"] * 51))

    def test_unassigned_escu_records_stay_visible_and_filterable(self):
        unassigned = "escu_UC-11111111-2222-4333-8444-555555555505"
        self.assertIn(unassigned, self.keys(category_keys=["escu_cat-unassigned"]))
        self.assertIn(unassigned, self.keys(providers=["escu"], domains=["other"]))
        self.assertEqual(self.keys(stories=["Malicious PowerShell"]), [unassigned])
        self.assertIn(unassigned, self.keys())

    def test_exclude_quality_hides_flagged_records_only_when_asked(self):
        flagged = self.expect(lambda d: "unreviewed" in d["quality_flags"] or "ai_reviewed" in d["quality_flags"])
        self.assertTrue(flagged and len(flagged) < len(self.all), "fixtures must contain both kinds")
        self.assertEqual(self.keys(exclude_quality=["unreviewed", "ai_reviewed"]),
                         sorted(set(self.expect(lambda d: True)) - set(flagged)))
        self.assertEqual(self.keys(), self.expect(lambda d: True))
        only = self.expect(lambda d: "unreviewed" not in d["quality_flags"])
        self.assertEqual(self.keys(exclude_quality=["unreviewed"]), only)
        with self.assertRaises(ValidationError):
            self.svc.search(CatalogFilter(exclude_quality=["nonsense"]))

    def test_filters_combine_with_and_between_facets(self):
        self.assertEqual(self.keys(providers=["fenre"], waves=["crawl"]),
                         self.expect(lambda d: d["provider"] == "fenre" and d.get("wave") == "crawl"))
        self.assertEqual(self.keys(providers=["escu"], waves=["crawl"]), [])
        self.assertEqual(self.keys(providers=["fenre"], stories=["Brute Force"]), [])

    def test_query_shape_uses_in_for_lists_and_ne_for_exclusions(self):
        q = build_query(CatalogFilter(providers=["escu"], exclude_quality=["unreviewed"], provider_status=""))
        self.assertIn({"provider": {"$in": ["escu"]}}, q["$and"])
        self.assertIn({"quality_flags": {"$ne": "unreviewed"}}, q["$and"])


class FacetCountsTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = two_provider_store()
        cls.facets = get_facets(cls.store)
        cls.svc = CatalogQueryService(cls.store, max_page_size=100)

    def total(self, **kw):
        return self.svc.search(CatalogFilter(count=1, **kw))["total"]

    def test_stored_facets_document_is_version_three(self):
        self.assertEqual(self.store.get(C.SYNC_STATE, FACETS_KEY)["facets_version"], FACETS_VERSION)
        self.assertEqual(FACETS_VERSION, 3)

    def test_provider_counts_equal_the_filter_totals(self):
        self.assertEqual(set(self.facets["providers"]), {"fenre", "escu"})
        for provider, count in self.facets["providers"].items():
            self.assertEqual(count, self.total(providers=[provider]), provider)
        self.assertEqual(sum(self.facets["providers"].values()), self.facets["active"])

    def test_wave_counts_equal_the_filter_totals(self):
        self.assertTrue(self.facets["waves"])
        for wave, count in self.facets["waves"].items():
            self.assertEqual(count, self.total(waves=[wave]), wave)

    def test_story_and_data_source_counts_equal_the_filter_totals(self):
        stories = {s["id"]: s["count"] for s in self.facets["analytic_stories"]}
        sources = {s["id"]: s["count"] for s in self.facets["data_sources"]}
        self.assertEqual(stories["Brute Force"], 1)
        self.assertEqual(self.facets["analytic_stories_total"], len(stories))
        self.assertEqual(self.facets["data_sources_total"], len(sources))
        for story, count in stories.items():
            self.assertEqual(count, self.total(stories=[story]), story)
        for source, count in sources.items():
            self.assertEqual(count, self.total(data_sources=[source]), source)

    def test_lists_are_ordered_by_count_then_name(self):
        rows = [{"analytic_stories": ["b", "a"], "provider_status": "active", "summary_version": 6},
                {"analytic_stories": ["a", "c"], "provider_status": "active", "summary_version": 6},
                {"analytic_stories": ["z"], "provider_status": "withdrawn", "summary_version": 6}]
        out = compute_facets(rows)["analytic_stories"]
        self.assertEqual([(s["id"], s["count"]) for s in out], [("a", 2), ("b", 1), ("c", 1)])

    def test_withdrawn_records_are_not_counted(self):
        store = two_provider_store()
        doc = store.get(C.CATALOG, "escu_UC-11111111-2222-4333-8444-555555555503")
        store.upsert(C.CATALOG, dict(doc, provider_status="withdrawn"))
        refresh_derived(store)
        facets = get_facets(store)
        self.assertNotIn("Brute Force", [s["id"] for s in facets["analytic_stories"]])
        self.assertEqual(facets["providers"]["escu"], 3)

    def test_quality_counts_include_the_twin_flag(self):
        flags = {f["id"]: f["count"] for f in self.facets["quality_flags"]}
        self.assertEqual(list(flags), list(FLAG_ORDER))
        self.assertEqual(flags["provider_twin"], 2)
        self.assertEqual(flags["provider_twin"], self.total(quality=["provider_twin"]))

    def test_current_summaries_report_nothing_outdated(self):
        self.assertEqual(self.facets["summary"], {"version": SUMMARY_VERSION, "outdated": 0})


class TwinLineageTest(unittest.TestCase):
    def test_both_records_are_flagged_and_filterable(self):
        store = two_provider_store()
        svc = CatalogQueryService(store, max_page_size=100)
        twins = sorted(i["content_id"] for i in svc.search(CatalogFilter(quality=["provider_twin"], count=100))["items"])
        self.assertEqual(twins, sorted([DEFENDER, TWIN_FENRE]))
        both = sorted(i["content_id"] for i in svc.search(CatalogFilter(quality=["duplicate_spl"], count=100))["items"])
        self.assertEqual(both, twins)

    def test_the_escu_page_links_to_the_fenre_twin(self):
        d = detail(two_provider_store(), DEFENDER)
        self.assertEqual([t["content_id"] for t in d["spl_twins"]], [TWIN_FENRE])
        twin = d["spl_twins"][0]
        self.assertEqual((twin["provider"], twin["key"], twin["record_id"]), ("fenre", "fenre_UC-10.4.24", "10.4.24"))
        self.assertEqual(twin["authority"]["role"], "compliance")
        self.assertEqual(d["authority"]["role"], "detection")
        self.assertIn("provider_twin", d["quality_flags"])
        self.assertEqual(d["spl_duplicates"], [TWIN_FENRE])

    def test_the_fenre_page_links_to_the_escu_twin(self):
        d = detail(two_provider_store(), TWIN_FENRE)
        self.assertEqual([t["content_id"] for t in d["spl_twins"]], [DEFENDER])
        self.assertEqual((d["spl_twins"][0]["authority"]["role"], d["authority"]["role"]), ("detection", "compliance"))
        self.assertEqual(d["spl_twins"][0]["title"], "Disable Windows Defender Real-time Protection")

    def test_without_the_twin_there_is_no_link_and_no_flag(self):
        store = two_provider_store(twin=False)
        for cid in (DEFENDER, TWIN_FENRE, SCANNING):
            d = detail(store, cid)
            self.assertEqual((d["spl_twins"], d["spl_duplicates"]), ([], []), cid)
            self.assertNotIn("provider_twin", d["quality_flags"])
        self.assertIn({"id": "provider_twin", "count": 0}, get_facets(store)["quality_flags"])

    def test_without_the_other_provider_imported(self):
        store = two_provider_store(twin=True, escu=False)
        d = detail(store, TWIN_FENRE)
        self.assertEqual((d["spl_twins"], d["spl_duplicates"]), ([], []))

    def test_a_withdrawn_twin_is_not_linked_and_the_flag_clears(self):
        store = two_provider_store()
        doc = store.get(C.CATALOG, "escu_UC-11111111-2222-4333-8444-555555555501")
        store.upsert(C.CATALOG, dict(doc, provider_status="withdrawn"))
        refresh_derived(store)
        d = detail(store, TWIN_FENRE)
        self.assertEqual(d["spl_twins"], [])
        self.assertNotIn("provider_twin", d["quality_flags"])
        self.assertNotIn("duplicate_spl", d["quality_flags"])

    def test_same_provider_duplicates_are_not_twins(self):
        store = two_provider_store(twin=False)
        for key in ("fenre_UC-9.1.1", "fenre_UC-9.1.2"):
            store.upsert(C.CATALOG, dict(store.get(C.CATALOG, key), spl_hash="e" * 64))
        refresh_derived(store)
        d = detail(store, "fenre:UC-9.1.1")
        self.assertEqual(d["spl_twins"], [])
        self.assertEqual(d["spl_duplicates"], ["fenre:UC-9.1.2"])
        self.assertNotIn("provider_twin", d["quality_flags"])
        self.assertEqual(refresh_derived(store)["twin_groups"], 0)

    def test_a_group_with_duplicates_and_a_twin_lists_each_correctly(self):
        store = two_provider_store()
        for key in ("fenre_UC-9.1.1",):
            store.upsert(C.CATALOG, dict(store.get(C.CATALOG, key),
                                         spl_hash=store.get(C.CATALOG, "fenre_UC-10.4.24")["spl_hash"]))
        refresh_derived(store)
        d = detail(store, "fenre:UC-9.1.1")
        self.assertEqual([t["content_id"] for t in d["spl_twins"]], [DEFENDER])
        self.assertEqual(sorted(d["spl_duplicates"]), sorted([DEFENDER, TWIN_FENRE]))

    def test_twins_are_capped(self):
        store = InMemoryStore()
        for i in range(30):
            store.upsert(C.CATALOG, {"_key": "x_%02d" % i, "content_id": "x:%02d" % i, "provider": "x", "spl_hash": "h",
                                     "provider_status": "active", "sort_key": "%02d" % i})
        self.assertEqual(len(find_twins(store, "h", "other", "o:1")), 20)
        self.assertEqual(find_twins(store, "", "other", "o:1"), [])

    def test_authority_is_data_for_known_providers_only(self):
        self.assertEqual(set(AUTHORITY), {"escu", "fenre"})
        self.assertEqual(detail(two_provider_store(twin=False), DEFENDER)["authority"]["role"], "detection")

    def test_twin_flag_is_idempotent(self):
        store = two_provider_store()
        self.assertEqual(refresh_derived(store)["updated"], 0)
        self.assertEqual(refresh_derived(store)["twin_groups"], 1)


class OldSummaryTest(unittest.TestCase):
    """A catalogue summarised by 0.8.9 (version 5): no wave, story or data source, no twin flag."""

    def old_store(self):
        store = two_provider_store()
        for key, doc in list(store.collections[C.CATALOG].items()):
            doc = {k: v for k, v in doc.items() if k not in ("wave", "analytic_stories", "data_sources")}
            doc["summary_version"] = 5
            doc["quality_flags"] = [f for f in doc["quality_flags"] if f != "provider_twin"]
            store.collections[C.CATALOG][key] = doc
        store.delete(C.SYNC_STATE, FACETS_KEY)
        return store

    def test_facets_report_how_many_summaries_are_old_and_degrade_to_empty_lists(self):
        store = self.old_store()
        facets = get_facets(store)
        self.assertEqual(facets["summary"], {"version": SUMMARY_VERSION, "outdated": facets["active"]})
        self.assertEqual((facets["waves"], facets["analytic_stories"], facets["data_sources"]), ({}, [], []))
        self.assertEqual(set(facets["providers"]), {"fenre", "escu"})

    def test_new_filters_return_nothing_without_an_error_and_old_filters_work(self):
        store = self.old_store()
        svc = CatalogQueryService(store, max_page_size=100)
        for kw in ({"waves": ["crawl"]}, {"stories": ["Brute Force"]}, {"data_sources": ["Sysmon EventID 13"]}):
            out = svc.search(CatalogFilter(count=100, **kw))
            self.assertEqual((out["items"], out["total"]), ([], 0), kw)
        self.assertEqual(svc.search(CatalogFilter(providers=["escu"]))["total"], 4)
        self.assertEqual(svc.search(CatalogFilter(exclude_quality=["unreviewed"]))["total"],
                         svc.search(CatalogFilter(exclude_quality=["unreviewed"], provider_status="active"))["total"])

    def test_the_api_answers_200_for_every_new_parameter_on_old_summaries(self):
        ctx = make_ctx(self.old_store(), [])
        for query in ({"wave": "walk"}, {"story": "Brute Force"}, {"data_source": "x"}, {"provider": "escu"},
                      {"exclude_quality": "ai_reviewed"}):
            status, body = call(ctx, "GET", "catalog", query=query)
            self.assertEqual(status, 200, (query, body))
        status, body = call(ctx, "GET", "catalog/facets")
        self.assertEqual((status, body["summary"]["outdated"] > 0), (200, True))

    def test_twins_still_link_before_reindex_because_duplicate_spl_is_old(self):
        store = self.old_store()
        d = detail(store, DEFENDER)
        self.assertEqual([t["content_id"] for t in d["spl_twins"]], [TWIN_FENRE])

    def test_reindex_fills_the_new_fields_and_is_idempotent(self):
        store = self.old_store()
        ReindexService(store).reindex()
        after = catalog_docs(store)
        self.assertTrue(all(d["summary_version"] == SUMMARY_VERSION for d in after.values()))
        self.assertEqual(after["fenre_UC-1.1.1"]["wave"], "crawl")
        self.assertEqual(after["escu_UC-11111111-2222-4333-8444-555555555503"]["analytic_stories"][0], "Brute Force")
        self.assertIn("provider_twin", after["fenre_UC-10.4.24"]["quality_flags"])
        facets = get_facets(store)
        self.assertEqual(facets["summary"]["outdated"], 0)
        svc = CatalogQueryService(store, max_page_size=100)
        self.assertEqual(svc.search(CatalogFilter(stories=["Brute Force"]))["total"], 1)
        snapshot = json.dumps(after, sort_keys=True)
        second = ReindexService(store).reindex()
        self.assertEqual((second["reindexed"], second["twin_groups"]), (len(after), 1))
        self.assertEqual(json.dumps(catalog_docs(store), sort_keys=True), snapshot)

    def test_a_document_without_a_summary_version_counts_as_old(self):
        rows = [{"provider_status": "active"}, {"provider_status": "active", "summary_version": 6}]
        self.assertEqual(compute_facets(rows)["summary"]["outdated"], 1)


class UpgradeFrom089Test(unittest.TestCase):
    """0.8.9 -> 0.9.0 with the worker's migrations: facets are stored, summaries are left for Reindex."""

    def installed_089(self):
        store = OldSummaryTest().old_store()
        for key, doc in list(store.collections[C.CATALOG].items()):
            store.collections[C.CATALOG][key] = dict(doc, normalizer_version=doc["normalizer_version"])
        applied = [m[0] for m in MIGRATIONS if m[0] < "0004"]
        store.upsert(C.SYNC_STATE, {"_key": STATE_KEY, "doc_type": "app_state", "app_version": "0.8.9",
                                    "applied": applied})
        store.upsert(C.SYNC_STATE, {"_key": FACETS_KEY, "doc_type": "catalog_facets", "facets_version": 2,
                                    "review_statuses": [], "regulations": [], "quality_flags": []})
        return store

    def test_only_the_facets_migration_runs_and_no_summary_is_written(self):
        store = self.installed_089()
        before = json.dumps(catalog_docs(store), sort_keys=True)
        runner = MigrationRunner(store, lambda: "2026-11-25T09:00:00Z")
        self.assertEqual(runner.pending(), ["0004_catalog_facets_v3"])
        self.assertTrue(runner.outdated())
        results = runner.run()
        self.assertEqual([r["id"] for r in results], ["0004_catalog_facets_v3"])
        self.assertEqual(json.dumps(catalog_docs(store), sort_keys=True), before)
        self.assertTrue(all(d["summary_version"] == 5 for d in catalog_docs(store).values()))
        facets = store.get(C.SYNC_STATE, FACETS_KEY)
        self.assertEqual(facets["facets_version"], 3)
        self.assertEqual(facets["summary"]["outdated"], facets["active"])
        state = store.get(C.SYNC_STATE, STATE_KEY)
        self.assertEqual((state["app_version"], state["previous_app_version"]), (__version__, "0.8.9"))
        self.assertEqual(runner.run(), [])

    def test_summary_migration_id_is_pinned_and_a_fresh_install_needs_no_migration(self):
        self.assertEqual(MIGRATIONS[0][0], "0001_catalog_summary_v5")
        store = InMemoryStore()
        results = MigrationRunner(store, lambda: "t").run()
        self.assertTrue(all(r["details"] == {"not_needed": True} for r in results))

    def test_reindex_after_the_upgrade_completes_the_migration(self):
        store = self.installed_089()
        MigrationRunner(store, lambda: "t").run()
        ReindexService(store).reindex()
        self.assertEqual(store.get(C.SYNC_STATE, FACETS_KEY)["summary"]["outdated"], 0)
        self.assertEqual(MigrationRunner(store, lambda: "t").run(), [])


class ParityTest(unittest.TestCase):
    """D-059: the key join and the scan path return the same pages for every new filter."""

    @classmethod
    def setUpClass(cls):
        cls.store = two_provider_store()
        seed_readiness(cls.store)
        cls.join = CatalogQueryService(cls.store, max_page_size=3, max_join_keys=1000)
        cls.scan = CatalogQueryService(cls.store, max_page_size=3, max_join_keys=1)

    CASES = (
        {"providers": ["escu"]}, {"providers": ["fenre", "escu"]}, {"waves": ["crawl"]}, {"waves": ["crawl", "walk", "run"]},
        {"stories": ["Brute Force", "Malicious PowerShell"]}, {"data_sources": ["Sysmon EventID 13"]},
        {"exclude_quality": ["unreviewed", "ai_reviewed"]}, {"quality": ["provider_twin"]},
        {"providers": ["fenre"], "waves": ["crawl"]}, {"providers": ["escu"], "exclude_quality": ["reviewer_na"]},
    )

    def test_every_new_filter_gives_the_same_pages_on_both_paths(self):
        for case in self.CASES:
            for availability in (["ready", "not_assessed"], list(AVAILABILITY)):
                for sort in SORTS:
                    offset = 0
                    while True:
                        f = CatalogFilter(availability=availability, sort=sort, offset=offset, count=3, **case)
                        a, b = self.join.search(f), self.scan.search(f)
                        self.assertEqual([i["_key"] for i in a["items"]], [i["_key"] for i in b["items"]],
                                         (case, availability, sort, offset))
                        self.assertEqual((a["total"], a["has_more"]), (b["total"], b["has_more"]), (case, sort, offset))
                        if not a["has_more"]:
                            break
                        offset += 3

    def test_filters_agree_with_a_python_evaluation(self):
        docs = [d for d in catalog_docs(self.store).values() if d["provider_status"] == "active"]
        ready = {r["_key"] for r in self.store.query(C.READINESS, {"state": "ready"})}
        for svc in (self.join, self.scan):
            out = svc.search(CatalogFilter(availability=["ready"], providers=["fenre"], count=100))
            expected = sorted(d["_key"] for d in docs if d["provider"] == "fenre" and d["_key"] in ready)
            self.assertEqual(sorted(i["_key"] for i in out["items"]), expected)


class ApiTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.store = two_provider_store()
        cls.ctx = make_ctx(cls.store, [])

    def get(self, **query):
        return call(self.ctx, "GET", "catalog", query=dict({"count": "100"}, **query))

    def test_parameters_map_to_filters(self):
        status, body = self.get(provider="escu")
        self.assertEqual((status, {i["provider"] for i in body["items"]}), (200, {"escu"}))
        status, body = self.get(provider="escu,fenre")
        self.assertEqual((status, body["total"]), (200, 14))
        status, body = self.get(wave="crawl")
        self.assertTrue(body["items"] and all(i["provider"] == "fenre" for i in body["items"]))
        status, body = self.get(story="Brute Force")
        self.assertEqual([i["content_id"] for i in body["items"]], [LOGONS])
        status, body = self.get(data_source="Sysmon EventID 13,Palo Alto Network Threat")
        self.assertEqual(sorted(i["content_id"] for i in body["items"]), sorted([DEFENDER, SCANNING]))
        status, body = self.get(exclude_quality="unreviewed,ai_reviewed")
        self.assertTrue(all("unreviewed" not in i["quality_flags"] for i in body["items"]))
        status, body = self.get(quality="provider_twin")
        self.assertEqual(sorted(i["content_id"] for i in body["items"]), sorted([DEFENDER, TWIN_FENRE]))

    def test_bad_values_are_400_and_old_urls_still_work(self):
        for query in ({"wave": "fast"}, {"provider": "Bad Id"}, {"exclude_quality": "x"}, {"story": "a\x01"}):
            self.assertEqual(self.get(**query)[0], 400, query)
        for query in ({"domain": "security"}, {"category": "fenre_cat-09"}, {"quality": "duplicate_spl"},
                      {"review": "verified"}, {"regulation": "gdpr"}, {"availability": "ready"}, {"q": "brute"}):
            self.assertEqual(self.get(**query)[0], 200, query)

    def test_facets_endpoint_carries_the_new_lists(self):
        status, body = call(self.ctx, "GET", "catalog/facets")
        self.assertEqual(status, 200)
        for key in ("providers", "waves", "analytic_stories", "data_sources", "summary"):
            self.assertIn(key, body)
        self.assertEqual(body["providers"], {"fenre": 10, "escu": 4})

    def test_usecase_endpoint_returns_twins_and_authority(self):
        status, body = call(self.ctx, "GET", "usecase", query={"id": DEFENDER})
        self.assertEqual(status, 200)
        self.assertEqual([t["content_id"] for t in body["spl_twins"]], [TWIN_FENRE])
        self.assertEqual(body["authority"]["role"], "detection")


class SummaryProjectionTest(unittest.TestCase):
    def test_projection_of_an_escu_use_case_has_the_new_fields(self):
        store = two_provider_store(twin=False)
        content = ContentRepository(store)
        from splunk_ucm.content.reindex import StoredNormalizer
        uc = StoredNormalizer(CategoryRepository(store)).normalize(content.get_content("escu_UC-11111111-2222-4333-8444-555555555501"))
        summary = catalog_summary(uc)
        self.assertEqual((summary["summary_version"], summary["wave"], summary["analytic_stories"], summary["data_sources"]),
                         (6, "", ["Windows Defender Tampering"], ["Sysmon EventID 13"]))


if __name__ == "__main__":
    unittest.main()
