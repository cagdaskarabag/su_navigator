"""End-to-end Splunk Lantern import sessions against a fake Lantern site (no network).

Covers the three manual acceptance scenarios: a single article, selecting
articles from the Splunk and Cisco collection, and re-importing an article
(duplicate detection, then an explicit update that keeps customer state).
"""

import copy
import json
import unittest

import helpers  # noqa: F401
import lantern_fakes as LF
from splunk_ucm.api.app import CAP_ADMIN, CAP_MANAGE_CONTENT
from splunk_ucm.audit import AuditService
from splunk_ucm.catalog.detail import UseCaseDetailService
from splunk_ucm.catalog.query import CatalogFilter, CatalogQueryService
from splunk_ucm.config import AppConfig
from splunk_ucm.content.lantern import parser as P
from splunk_ucm.content.lantern.normalizer import content_key
from splunk_ucm.content.lantern.sessions import LanternSessionService, LanternSettings, LanternWorker
from splunk_ucm.content.lantern.urls import LanternUrlError, record_id_for
from splunk_ucm.content.reindex import ReindexService
from splunk_ucm.content.sync import SyncService
from splunk_ucm.errors import ConflictError, NotFoundError, PermissionDenied, ValidationError
from splunk_ucm.readiness.service import ReadinessService
from splunk_ucm.selection.service import SelectionService
from splunk_ucm.storage import collections as C
from splunk_ucm.storage.kvstore import InMemoryStore
from splunk_ucm.storage.repositories import CategoryRepository, ContentRepository
from unit.test_api_worker import call, make_ctx
from unit.test_discovery import APPS, INDEXES, MODELS, ROWS, FakeInventory, FakeSearch, loaded_catalog

ARTICLE_ID = record_id_for(LF.ARTICLE)
ARTICLE_CID = "lantern:" + ARTICLE_ID


class Harness:
    def __init__(self, store=None, site=None, settings=None):
        self.store = store or InMemoryStore()
        self.site = site or LF.standard_site()
        self.clock = LF.FakeClock()
        self.audit = AuditService(self.store)
        self.svc = LanternSessionService(self.store, self.audit, settings or LanternSettings(),
                                         content_store=self.store, clock=self.clock.time)
        self.factory = LF.session_fetcher(self.site, self.clock)
        self.sync = SyncService(self.store, self.audit)

    def run(self):
        return LF.drain(self.svc, self.factory)

    def inspect(self, url, user="alice"):
        session = self.svc.create(user, url)
        self.run()
        return self.svc.get(session["session_id"])

    def fetch(self, session, urls, user="alice"):
        self.svc.request_fetch(user, False, session["session_id"], urls)
        self.run()
        return self.svc.get(session["session_id"])

    def import_(self, session, selections, user="alice", confirm=True):
        return self.svc.import_items(user, False, session["session_id"], selections, confirm, self.sync)

    def item(self, session, url):
        return next(i for i in session["items"] if i["url"] == url)

    def catalog(self, **kw):
        return CatalogQueryService(self.store).search(CatalogFilter(**kw))

    def detail(self, cid):
        return UseCaseDetailService(ContentRepository(self.store), CategoryRepository(self.store)).get(cid)


def changed_article_html():
    return (LF.fixture("article_full.html")
            .replace("where count &gt; 5", "where count &gt; 10")
            .replace("Faster scoping of phishing campaigns", "Much faster scoping of phishing campaigns"))


class SingleArticleTest(unittest.TestCase):
    """Manual test 1: import a single Lantern article."""

    def test_inspect_preview_confirm_import(self):
        h = Harness()
        session = h.inspect(LF.ARTICLE)
        self.assertEqual(session["status"], "ready")
        self.assertEqual(session["page"]["kind"], P.KIND_ARTICLE)
        item = session["items"][0]
        self.assertEqual((item["state"], item["status"], item["record_id"]), ("fetched", "new", ARTICLE_ID))
        self.assertEqual(item["extraction"]["spl_count"], 2)
        self.assertEqual(h.catalog(provider="lantern")["total"], 0, "inspection never imports")

        staged = h.svc.staged("alice", False, session["session_id"], LF.ARTICLE)
        self.assertEqual(staged["raw"]["content_hash"], item["extraction"]["content_hash"])

        with self.assertRaises(ValidationError):
            h.import_(session, [{"url": LF.ARTICLE}], confirm=False)
        self.assertEqual(h.catalog(provider="lantern")["total"], 0)

        result = h.import_(session, [{"url": LF.ARTICLE}])["result"]
        self.assertEqual(result["counts"], {"selected": 1, "imported": 1})
        self.assertEqual(result["results"][0]["content_id"], ARTICLE_CID)

        listing = h.catalog(provider="lantern")
        self.assertEqual(listing["total"], 1)
        row = listing["items"][0]
        self.assertEqual((row["content_id"], row["source_url"]), (ARTICLE_CID, LF.ARTICLE))
        self.assertFalse(row["needs_review"])
        self.assertTrue(row["has_spl"])
        self.assertEqual(h.catalog(q="phishing")["total"], 1)
        self.assertEqual(h.catalog(domains=["security"], provider="lantern")["total"], 1)
        self.assertEqual(h.catalog(provider="fenre")["total"], 0)

        detail = h.detail(ARTICLE_CID)
        lantern = detail["provider_extras"]["lantern"]
        self.assertEqual(lantern["imported_by"], "alice")
        self.assertEqual(lantern["source_content_hash"], item["extraction"]["content_hash"])
        self.assertEqual(lantern["found_in"][0]["url"], LF.ARTICLE)
        self.assertEqual(detail["provenance"]["provider"], "lantern")
        stored = h.store.get(C.CONTENT, content_key(ARTICLE_ID))
        self.assertEqual(stored["provider"], "lantern")
        actions = [r["action"] for r in h.store.query(C.AUDIT, {})]
        for action in ("content.lantern.inspect_requested", "content.lantern.imported"):
            self.assertIn(action, actions)
        state = h.store.get(C.SYNC_STATE, "provider::lantern")
        self.assertTrue(state and state.get("last_success_at"))

    def test_low_confidence_article_is_flagged(self):
        h = Harness()
        session = h.inspect(LF.MINIMAL)
        self.assertTrue(session["items"][0]["extraction"]["needs_review"])
        h.import_(session, [{"url": LF.MINIMAL}])
        row = h.catalog(provider="lantern")["items"][0]
        self.assertTrue(row["needs_review"])
        self.assertFalse(row["has_spl"])

    def test_fetch_uses_robots_and_rate_gate(self):
        h = Harness()
        h.inspect(LF.ARTICLE)
        self.assertEqual(h.site.requests[0][1], "/robots.txt")
        self.assertEqual(h.store.get(C.LANTERN, "robots")["status"], 200)
        self.assertGreater(h.store.get(C.LANTERN, "gate")["last_request_at"], 0)
        h.inspect(LF.SINGLE)
        self.assertEqual([p for _h, p, _x in h.site.requests].count("/robots.txt"), 1, "robots cached")


class CollectionImportTest(unittest.TestCase):
    """Manual test 2: paste the Splunk and Cisco collection and select articles from categories."""

    def test_select_articles_from_categories(self):
        h = Harness()
        session = h.inspect(LF.CISCO)
        page = session["page"]
        self.assertEqual(page["kind"], P.KIND_COLLECTION)
        self.assertEqual([c["name"] for c in page["categories"]],
                         ["Correlate network domains", "Security, identity, and compliance",
                          "Data onboarding and platform operations"])
        self.assertFalse(page["empty"])
        self.assertEqual(len(h.site.page_requests()), 1, "inspection reads only the collection page")
        self.assertTrue(all(i["state"] == "listed" for i in session["items"]))

        chosen = [LF.CISCO_ARTICLES[0], LF.CISCO_ARTICLES[2]]
        session = h.fetch(session, chosen)
        self.assertEqual(len(h.site.page_requests()), 3, "only selected articles are fetched")
        for url in chosen:
            self.assertEqual((h.item(session, url)["state"], h.item(session, url)["status"]), ("fetched", "new"))
        self.assertEqual(h.item(session, LF.CISCO_ARTICLES[1])["state"], "listed")

        result = h.import_(session, [{"url": u} for u in chosen] + [{"url": LF.CISCO_ARTICLES[1]}])["result"]
        self.assertEqual(result["counts"], {"selected": 3, "imported": 2, "skipped": 1})
        skipped = next(r for r in result["results"] if r["outcome"] == "skipped")
        self.assertEqual(skipped["reason"], "not_fetched")
        self.assertEqual(h.catalog(provider="lantern")["total"], 2)
        detail = h.detail("lantern:" + record_id_for(LF.CISCO_ARTICLES[0]))
        found = detail["provider_extras"]["lantern"]["found_in"]
        self.assertEqual(found[0]["url"], LF.CISCO)
        self.assertEqual(found[0]["category"], "Correlate network domains")
        self.assertEqual(found[1]["category"], "Security, identity, and compliance")

        again = h.inspect(LF.CISCO)
        self.assertTrue(h.item(again, LF.CISCO_ARTICLES[0])["in_sun"])
        self.assertFalse(h.item(again, LF.CISCO_ARTICLES[1])["in_sun"])

    def test_partial_failure_keeps_other_articles(self):
        h = Harness()
        missing = LF.BASE_URL + "/Industry_Use_Cases/Retail/Monitoring_facilities_with_differing_applications"
        session = h.inspect(LF.CISCO)
        session = h.fetch(session, [LF.CISCO_ARTICLES[0], missing])
        broken = h.item(session, missing)
        self.assertEqual((broken["state"], broken["error"]["code"]), ("error", "lantern_not_found"))
        self.assertEqual(session["status"], "ready")
        result = h.import_(session, [{"url": LF.CISCO_ARTICLES[0]}, {"url": missing}])["result"]
        self.assertEqual(result["counts"], {"selected": 2, "imported": 1, "skipped": 1})

    def test_expand_sub_collections_with_depth_limit(self):
        h = Harness()
        session = h.inspect(LF.SECURITY)
        self.assertEqual(len(session["items"]), 3)
        h.svc.request_expand("alice", False, session["session_id"], [LF.GUIDE])
        h.run()
        session = h.svc.get(session["session_id"])
        parent = h.item(session, LF.GUIDE)
        self.assertEqual((parent["state"], parent["child_count"]), ("expanded", 3))
        child = h.item(session, LF.ARTICLE)
        self.assertEqual((child["depth"], child["parent_url"], child["subcategory"]), (1, LF.GUIDE,
                                                                                      "Enterprise Security"))
        self.assertEqual(len(session["items"]), 6)
        h.site.add(LF.ARTICLE, LF.fixture("collection_guide.html"))
        with self.assertRaises(ValidationError) as ctx:
            h.svc.request_expand("alice", False, session["session_id"], [LF.ARTICLE])
        self.assertIn(ctx.exception.details.get("reason"), (None, "depth_limit"))
        with self.assertRaises(ValidationError):
            h.svc.request_expand("alice", False, session["session_id"], [LF.GUIDE + "/Unknown"])

    def test_empty_and_unsupported_pages(self):
        h = Harness()
        empty = h.inspect(LF.EMPTY)
        self.assertEqual((empty["status"], empty["page"]["kind"], empty["page"]["empty"]),
                         ("ready", P.KIND_COLLECTION, True))
        home = h.inspect(LF.BASE_URL + "/")
        self.assertEqual(home["page"]["kind"], P.KIND_UNSUPPORTED)
        self.assertIn("home page", home["page"]["reason"])
        self.assertEqual(home["items"], [])

    def test_unavailable_timeout_and_parse_failure(self):
        h = Harness()
        gone = h.inspect(LF.BASE_URL + "/Security_Use_Cases/Nope")
        self.assertEqual((gone["status"], gone["inspect_error"]["code"]), ("failed", "lantern_not_found"))

        def slow():
            raise __import__("socket").timeout("t")
        h.site.add(LF.BASE_URL + "/Slow_page", slow)
        self.assertEqual(h.inspect(LF.BASE_URL + "/Slow_page")["inspect_error"]["code"], "lantern_timeout")

        original = P.parse_collection
        P.parse_collection = lambda *a, **k: 1 / 0
        try:
            failed = h.inspect(LF.CISCO)
        finally:
            P.parse_collection = original
        self.assertEqual(failed["inspect_error"]["code"], "lantern_parse_failed")
        with self.assertRaises(ConflictError):
            h.svc.request_fetch("alice", False, failed["session_id"], [LF.CISCO])

    def test_limits(self):
        h = Harness(settings=LanternSettings(max_articles_per_fetch=1, max_pages_per_session=5))
        session = h.inspect(LF.CISCO)
        with self.assertRaises(ValidationError):
            h.svc.request_fetch("alice", False, session["session_id"], LF.CISCO_ARTICLES[:2])
        with self.assertRaises(ValidationError):
            h.svc.request_fetch("alice", False, session["session_id"], [LF.BASE_URL + "/Not_in_session"])
        for url in LF.CISCO_ARTICLES[:2]:
            session = h.fetch(session, [url])
        with self.assertRaises(ValidationError) as ctx:
            for url in [i["url"] for i in session["items"]][2:]:
                h.fetch(session, [url])
                session = h.svc.get(session["session_id"])
        self.assertEqual(ctx.exception.details.get("reason"), "page_limit")


class UpdateAndDuplicateTest(unittest.TestCase):
    """Manual test 3: import twice, detect the duplicate, then update without losing customer state."""

    def setUp(self):
        self.store = loaded_catalog()
        self.h = Harness(store=self.store)
        session = self.h.inspect(LF.ARTICLE)
        self.h.import_(session, [{"url": LF.ARTICLE}])

    def customer_state(self):
        sel = SelectionService(self.store, AuditService(self.store))
        sel.upsert("alice", ARTICLE_CID, "select", notes="Owner: SOC team", priority=80)
        from splunk_ucm.discovery.service import DiscoveryService, DiscoverySettings, new_job as new_djob
        DiscoveryService(self.store, AuditService(self.store), FakeInventory(INDEXES, APPS, MODELS),
                         FakeSearch(ROWS), DiscoverySettings(include_internal=False),
                         now_epoch=lambda: 1795163600).run(new_djob("alice"))
        ReadinessService(self.store, AuditService(self.store)).assess_one(ARTICLE_CID, "alice")
        key = content_key(ARTICLE_ID)
        self.store.upsert(C.VALIDATION, {"_key": "val::" + key, "content_id": ARTICLE_CID, "status": "passed"})
        self.store.upsert(C.DEPLOYMENTS, {"_key": "dep::" + key, "content_id": ARTICLE_CID, "state": "deployed",
                                          "search_name": "SUN - phishing"})

    def snapshot(self):
        out = {}
        for coll in (C.SELECTIONS, C.READINESS, C.VALIDATION, C.DEPLOYMENTS, C.SOURCE_MAPPINGS):
            out[coll] = sorted((json.dumps(d, sort_keys=True) for d in self.store.query(coll, {})))
        return out

    def test_second_import_is_detected_as_unchanged(self):
        session = self.h.inspect(LF.ARTICLE)
        item = session["items"][0]
        self.assertEqual((item["status"], item["in_sun"]), ("unchanged", True))
        result = self.h.import_(session, [{"url": LF.ARTICLE}])["result"]
        self.assertEqual(result["counts"], {"selected": 1, "skipped": 1})
        self.assertEqual(result["results"][0]["reason"], "unchanged")
        self.assertEqual(self.h.catalog(provider="lantern")["total"], 1)

    def test_same_article_twice_in_one_session_is_a_duplicate(self):
        h = Harness()
        alias = LF.GUIDE + "/Phishing_alias"
        h.site.redirect(alias, LF.ARTICLE)
        guide = LF.fixture("collection_guide.html").replace(
            "Building_a_SOAR_playbook", "Phishing_alias")
        h.site.add(LF.GUIDE, guide)
        session = h.inspect(LF.GUIDE)
        session = h.fetch(session, [LF.ARTICLE, alias])
        dup = next(i for i in session["items"] if i.get("duplicate_of"))
        self.assertEqual((dup["state"], dup["duplicate_of"], dup["record_id"]), ("duplicate", LF.ARTICLE, ARTICLE_ID))
        result = h.import_(session, [{"url": LF.ARTICLE}, {"url": dup["url"]}])["result"]
        self.assertEqual(result["counts"], {"selected": 2, "imported": 1, "skipped": 1})

    def test_update_requires_explicit_action_and_preserves_customer_state(self):
        self.customer_state()
        before_state = self.snapshot()
        fenre_before = sorted(json.dumps(d, sort_keys=True) for d in
                              self.store.query(C.CATALOG, {"provider": "fenre"}))
        old_hash = self.store.get(C.CATALOG, content_key(ARTICLE_ID))["source_hash"]

        self.h.site.add(LF.ARTICLE, changed_article_html())
        session = self.h.inspect(LF.ARTICLE)
        item = session["items"][0]
        self.assertEqual(item["status"], "updated")
        fields = {c["field"] for c in item["changes"]}
        self.assertIn("spl_blocks", fields)
        self.assertIn("business_value", fields)

        skipped = self.h.import_(session, [{"url": LF.ARTICLE}])["result"]
        self.assertEqual(skipped["results"][0]["reason"], "update_not_confirmed")
        self.assertEqual(self.store.get(C.CATALOG, content_key(ARTICLE_ID))["source_hash"], old_hash)

        result = self.h.import_(session, [{"url": LF.ARTICLE, "action": "update"}])["result"]
        self.assertEqual(result["counts"], {"selected": 1, "updated": 1})
        new_hash = self.store.get(C.CATALOG, content_key(ARTICLE_ID))["source_hash"]
        self.assertNotEqual(new_hash, old_hash)
        detail = self.h.detail(ARTICLE_CID)
        self.assertIn("where count > 10", detail["spl_variants"][0]["spl"])
        self.assertTrue(detail["business_value"].startswith("Much faster"))

        self.assertEqual(self.snapshot(), before_state, "customer state is untouched by a content update")
        sel = SelectionService(self.store, AuditService(self.store)).get("alice", ARTICLE_CID)
        self.assertEqual((sel["notes"], sel["intent"], sel["priority"]), ("Owner: SOC team", "select", 80))
        self.assertEqual(sorted(json.dumps(d, sort_keys=True) for d in
                                self.store.query(C.CATALOG, {"provider": "fenre"})), fenre_before)

    def test_update_conflict_when_sun_changed_after_preview(self):
        self.h.site.add(LF.ARTICLE, changed_article_html())
        first = self.h.inspect(LF.ARTICLE)
        second = self.h.inspect(LF.ARTICLE)
        self.h.import_(first, [{"url": LF.ARTICLE, "action": "update"}])
        result = self.h.import_(second, [{"url": LF.ARTICLE, "action": "update"}])["result"]
        self.assertEqual(result["results"][0]["reason"], "already_imported")

        third_html = changed_article_html().replace("where count &gt; 10", "where count &gt; 20")
        self.h.site.add(LF.ARTICLE, LF.fixture("article_full.html"))
        stale = self.h.inspect(LF.ARTICLE)
        self.h.site.add(LF.ARTICLE, third_html)
        newer = self.h.inspect(LF.ARTICLE)
        self.h.import_(newer, [{"url": LF.ARTICLE, "action": "update"}])
        result = self.h.import_(stale, [{"url": LF.ARTICLE, "action": "update"}])["result"]
        self.assertEqual((result["results"][0]["outcome"], result["results"][0]["reason"]),
                         ("conflict", "update_conflict"))

    def test_tampered_stage_is_refused(self):
        self.h.site.add(LF.ARTICLE, changed_article_html())
        session = self.h.inspect(LF.ARTICLE)
        item = session["items"][0]
        doc = self.store.get(C.LANTERN, item["stage_key"])
        raw = json.loads(doc["raw_json"])
        raw["spl_blocks"][0]["spl"] = "| delete"
        doc["raw_json"] = json.dumps(raw)
        self.store.upsert(C.LANTERN, doc)
        result = self.h.import_(session, [{"url": LF.ARTICLE, "action": "update"}])["result"]
        self.assertEqual(result["results"][0]["reason"], "stage_missing")
        self.assertNotIn("| delete", json.dumps(self.h.detail(ARTICLE_CID)))

    def test_reindex_keeps_lantern_content(self):
        result = ReindexService(self.store).reindex()
        self.assertFalse(result.get("errors"))
        self.assertEqual(self.h.catalog(provider="lantern")["total"], 1)
        self.assertGreater(self.h.catalog(provider="fenre")["total"], 0)


class SessionLifecycleTest(unittest.TestCase):
    def test_validation_and_settings(self):
        h = Harness()
        with self.assertRaises(LanternUrlError):
            h.svc.create("alice", "https://lantern.splunk.com.evil.example/")
        with self.assertRaises(LanternUrlError):
            h.svc.create("alice", "http://lantern.splunk.com/Security_Use_Cases")
        self.assertEqual(h.store.query(C.LANTERN, {}), [])
        off = Harness(settings=LanternSettings(remote_fetch_enabled=False))
        with self.assertRaises(ValidationError) as ctx:
            off.svc.create("alice", LF.CISCO)
        self.assertEqual(ctx.exception.details["reason"], "fetch_disabled")
        disabled = Harness(settings=LanternSettings(enabled=False))
        with self.assertRaises(ValidationError):
            disabled.svc.create("alice", LF.CISCO)

    def test_active_session_limit(self):
        h = Harness(settings=LanternSettings(max_active_sessions_per_user=2))
        h.svc.create("alice", LF.CISCO)
        h.svc.create("alice", LF.SECURITY)
        with self.assertRaises(ConflictError):
            h.svc.create("alice", LF.GUIDE)
        h.svc.create("bob", LF.GUIDE)

    def test_ownership(self):
        h = Harness()
        session = h.inspect(LF.ARTICLE)
        sid = session["session_id"]
        with self.assertRaises(PermissionDenied):
            h.svc.get(sid, "mallory", False)
        with self.assertRaises(PermissionDenied):
            h.svc.import_items("mallory", False, sid, [{"url": LF.ARTICLE}], True, h.sync)
        self.assertEqual(h.svc.get(sid, "root", True)["session_id"], sid)
        self.assertEqual(h.svc.list_sessions("mallory", False), [])
        self.assertEqual(len(h.svc.list_sessions("alice", False)), 1)
        with self.assertRaises(ValidationError):
            h.svc.get("../../x")

    def test_cancel_and_discard(self):
        h = Harness()
        session = h.inspect(LF.CISCO)
        sid = session["session_id"]
        h.svc.request_fetch("alice", False, sid, LF.CISCO_ARTICLES[:2])
        cancelled = h.svc.cancel("alice", False, sid)
        self.assertEqual(cancelled["status"], "ready")
        self.assertTrue(all(i["state"] == "listed" for i in cancelled["items"]))
        self.assertEqual(h.run(), 0)
        session = h.fetch(h.svc.get(sid), LF.CISCO_ARTICLES[:1])
        self.assertTrue(h.store.query(C.LANTERN, {"doc_type": "stage"}))
        h.svc.discard("alice", False, sid)
        with self.assertRaises(NotFoundError):
            h.svc.get(sid)
        self.assertEqual(h.store.query(C.LANTERN, {"doc_type": "stage"}), [])

    def test_cancel_while_running_and_discard_mid_run(self):
        h = Harness()
        session = h.inspect(LF.CISCO)
        sid = session["session_id"]
        h.svc.request_fetch("alice", False, sid, LF.CISCO_ARTICLES)
        queued = h.svc.next_queued()
        doc = h.store.get(C.LANTERN, queued["_key"])
        doc["cancel_requested"] = True
        h.store.upsert(C.LANTERN, doc)
        h.svc.process(queued, h.factory(h.svc))
        after = h.svc.get(sid)
        self.assertEqual(after["status"], "ready")
        self.assertEqual(sum(1 for i in after["items"] if i["state"] == "fetched"), 0)

        h.svc.request_fetch("alice", False, sid, LF.CISCO_ARTICLES)
        queued = h.svc.next_queued()
        h.store.delete(C.LANTERN, queued["_key"])
        self.assertEqual(h.svc.process(queued, h.factory(h.svc))["status"], "discarded")

    def test_time_budget_requeues(self):
        h = Harness(settings=LanternSettings(worker_time_budget_seconds=10))
        session = h.inspect(LF.CISCO)
        h.svc.request_fetch("alice", False, session["session_id"], LF.CISCO_ARTICLES)
        ticks = iter([0, 1, 100] + [200] * 50)
        result = h.svc.process(h.svc.next_queued(), h.factory(h.svc), monotonic=lambda: next(ticks))
        self.assertEqual(result["status"], "queued")
        h.run()
        self.assertEqual(h.svc.get(session["session_id"])["status"], "ready")

    def test_cleanup_and_recovery(self):
        h = Harness()
        session = h.inspect(LF.ARTICLE)
        h.clock.now += 25 * 3600
        self.assertEqual(h.svc.cleanup_expired(), 1)
        self.assertEqual(h.store.query(C.LANTERN, {"doc_type": "stage"}), [])
        with self.assertRaises(NotFoundError):
            h.svc.get(session["session_id"])

        stuck = h.svc.create("alice", LF.CISCO)
        doc = h.store.get(C.LANTERN, stuck["_key"])
        doc.update({"status": "running", "updated_at": "2000-01-01T00:00:00Z"})
        h.store.upsert(C.LANTERN, doc)
        self.assertEqual(h.svc.recover_interrupted(60), 1)
        self.assertEqual(h.svc.get(stuck["session_id"])["status"], "queued")

    def test_worker_run_once(self):
        store = InMemoryStore()
        site = LF.standard_site()
        worker = LanternWorker(store, AppConfig({}), lambda: None, LF.session_fetcher(site))
        self.assertEqual(worker.run_once()["action"], "idle")
        worker.service.create("alice", LF.ARTICLE)
        self.assertEqual(worker.run_once()["action"], "ran")
        self.assertEqual(worker.service.list_sessions("alice", False)[0]["status"], "ready")
        follower = LanternWorker(store, AppConfig({}), lambda: False, LF.session_fetcher(site))
        self.assertEqual(follower.run_once()["action"], "skipped")

    def test_worker_honours_config(self):
        worker = LanternWorker(InMemoryStore(), AppConfig({"provider:lantern": {
            "max_articles_per_fetch": "3", "min_request_interval_seconds": "1", "remote_fetch_enabled": "0"}}),
            lambda: None)
        settings = worker.service.settings
        self.assertEqual(settings.max_articles_per_fetch, 3)
        self.assertEqual(settings.fetch.min_interval, 5, "the interval cannot go below Lantern's crawl delay")
        self.assertFalse(settings.remote_fetch_enabled)


class LanternApiTest(unittest.TestCase):
    def setUp(self):
        self.store = InMemoryStore()

    def ctx(self, caps, user="alice"):
        return make_ctx(self.store, caps, user=user)

    def test_routes_require_content_capability(self):
        viewer = self.ctx([])
        for method, path, body in (("GET", "lantern", b""), ("POST", "lantern/inspect", {"url": LF.CISCO}),
                                   ("POST", "lantern/import", {"id": "x", "items": [], "confirm": True}),
                                   ("GET", "lantern/session", b""), ("POST", "lantern/discard", {"id": "x"})):
            self.assertEqual(call(viewer, method, path, body=body)[0], 403, path)
        self.assertEqual(self.store.query(C.LANTERN, {}), [])

    def test_inspect_validates_and_queues(self):
        manager = self.ctx([CAP_MANAGE_CONTENT])
        status, body = call(manager, "POST", "lantern/inspect", body={"url": "https://evil.example/"})
        self.assertEqual(status, 400)
        self.assertEqual(body["error"]["code"], "invalid_lantern_url")
        status, body = call(manager, "POST", "lantern/inspect", body={"url": LF.CISCO})
        self.assertEqual(status, 202)
        sid = body["session"]["session_id"]
        self.assertEqual(body["session"]["status"], "queued")
        status, body = call(manager, "GET", "lantern")
        self.assertEqual((status, body["sessions"][0]["session_id"]), (200, sid))
        self.assertEqual(body["settings"]["host"], "lantern.splunk.com")
        status, _ = call(self.ctx([CAP_MANAGE_CONTENT], user="bob"), "GET", "lantern/session", {"id": sid})
        self.assertEqual(status, 403)
        status, _ = call(self.ctx([CAP_ADMIN, CAP_MANAGE_CONTENT], user="root"), "GET", "lantern/session",
                         {"id": sid})
        self.assertEqual(status, 200)

    def test_full_flow_through_api(self):
        manager = self.ctx([CAP_MANAGE_CONTENT])
        sid = call(manager, "POST", "lantern/inspect", body={"url": LF.ARTICLE})[1]["session"]["session_id"]
        h = Harness(store=self.store)
        h.run()
        status, body = call(manager, "GET", "lantern/staged", {"id": sid, "url": LF.ARTICLE})
        self.assertEqual(status, 200)
        self.assertEqual(body["usecase"]["content_id"], ARTICLE_CID)
        status, body = call(manager, "POST", "lantern/import", body={"id": sid, "items": [{"url": LF.ARTICLE}]})
        self.assertEqual(status, 400, "confirm is required")
        status, body = call(manager, "POST", "lantern/import",
                            body={"id": sid, "items": [{"url": LF.ARTICLE}], "confirm": True})
        self.assertEqual((status, body["result"]["counts"]["imported"]), (200, 1))
        status, body = call(manager, "GET", "catalog", {"provider": "lantern"})
        self.assertEqual((status, body["total"]), (200, 1))
        status, body = call(self.ctx([]), "GET", "usecase", {"id": ARTICLE_CID})
        self.assertEqual(status, 200)
        self.assertEqual(call(manager, "GET", "catalog", {"provider": "other"})[0], 400)
        self.assertEqual(call(manager, "POST", "lantern/discard", body={"id": sid})[0], 200)

    def test_bundle_import_cannot_inject_lantern_content(self):
        from splunk_ucm.content.registry import bundle_provider
        with self.assertRaises(Exception):
            bundle_provider({"provider": "lantern", "categories": [], "records": []})


if __name__ == "__main__":
    unittest.main()
