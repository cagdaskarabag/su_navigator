"""Every KV collection has its own access stanza, and the restricted ones are reached only with the system token (0.12.2)."""

import os
import re
import unittest

import helpers  # noqa: F401  (sets sys.path)
from splunk_ucm.api.app import CAP_RUN_DISCOVERY, Context
from splunk_ucm.config import AppConfig
from splunk_ucm.errors import PermissionDenied
from splunk_ucm.storage import collections as C
from splunk_ucm.storage.kvstore import InMemoryStore
from unit.test_api_worker import NoSplunkd, call

RESTRICTED = (C.FIELD_PROFILE, C.EVENT_CHECK, C.EXTERNAL_MATCHES, C.ASSESSMENTS, C.POAM, C.SNAPSHOTS)


def read(*parts):
    with open(os.path.join(helpers.ROOT, "sunavigator", *parts), encoding="utf-8") as handle:
        return handle.read()


def access(collection):
    block = re.search(r"^\[collections/%s\]\naccess = read : \[ ([^\]]*) \], write : \[ ([^\]]*) \]" % collection,
                      read("metadata", "default.meta"), re.MULTILINE)
    if not block:
        return None
    return ([r.strip() for r in block.group(1).split(",")], [w.strip() for w in block.group(2).split(",")])


class StanzaTest(unittest.TestCase):
    def test_every_collection_has_a_stanza(self):
        declared = re.findall(r"^\[([^\]]+)\]", read("default", "collections.conf"), re.MULTILINE)
        self.assertGreaterEqual(len(declared), 20)
        missing = [c for c in declared if access(c) is None]
        self.assertEqual(missing, [], "add [collections/<name>] to metadata/default.meta; the default grants read to everyone")

    def test_restricted_collections_are_not_world_readable(self):
        for name in RESTRICTED:
            readers, writers = access(name)
            self.assertNotIn("*", readers, name)
            self.assertEqual(writers, ["admin", "sc_admin"], name)
            self.assertIn("ucm_admin", readers, name)
        for name in (C.ASSESSMENTS, C.POAM, C.SNAPSHOTS):
            self.assertIn("ucm_compliance_assessor", access(name)[0], name)


class NoDirectReadStore(InMemoryStore):
    """The caller's own KV view: refuses the restricted collections, as default.meta does for an analyst."""

    def _check(self, collection):
        if collection in RESTRICTED:
            raise PermissionDenied("403 reading %s with the user session" % collection)

    def query(self, collection, *a, **kw):
        self._check(collection)
        return super().query(collection, *a, **kw)

    def get(self, collection, key):
        self._check(collection)
        return super().get(collection, key)

    def count(self, collection, *a, **kw):
        self._check(collection)
        return super().count(collection, *a, **kw)

    def upsert(self, collection, doc):
        self._check(collection)
        return super().upsert(collection, doc)

    def batch_save(self, collection, docs):
        self._check(collection)
        return super().batch_save(collection, docs)


class ExternalMatchesUseSystemStoreTest(unittest.TestCase):
    def setUp(self):
        backend = InMemoryStore()
        self.ctx = Context(NoSplunkd(), None, "alice", store=NoDirectReadStore(), audit_store=backend,
                           config=AppConfig({}), record_store=backend)
        self.ctx._caps = [CAP_RUN_DISCOVERY]

    def test_list_and_decide_do_not_touch_the_users_view(self):
        status, body = call(self.ctx, "GET", "external")
        self.assertEqual(status, 200, body)
        status, body = call(self.ctx, "POST", "external", body={"id": "xm_" + "0" * 40, "decision": "accept"})
        self.assertNotEqual(status, 403, body)
        self.assertNotIn("reading uc_external_matches", str(body))


if __name__ == "__main__":
    unittest.main()
