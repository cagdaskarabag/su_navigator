import unittest

import helpers  # noqa: F401

from splunk_ucm.audit import AuditService, row_hash
from splunk_ucm.storage import collections as C
from splunk_ucm.storage.kvstore import InMemoryStore


def filled(n=5):
    store = InMemoryStore()
    audit = AuditService(store)
    for i in range(n):
        audit.record("alice", "deployment.draft", "deployment", "uc-%d" % i, details={"revision": i, "score": 100.0})
    return store, audit


def rows(store):
    return sorted(store.query(C.AUDIT, None), key=lambda r: (r["time"], r["_key"]))


class ChainTest(unittest.TestCase):
    def test_every_row_names_the_one_before_it(self):
        store, audit = filled()
        listed = rows(store)
        self.assertEqual(listed[0]["prev_hash"], "")
        for before, after in zip(listed, listed[1:]):
            self.assertEqual(after["prev_hash"], before["hash"])
        self.assertTrue(all(row_hash(r) == r["hash"] for r in listed))

    def test_an_intact_chain_verifies_and_reports_the_head(self):
        store, audit = filled()
        result = audit.verify_chain()
        self.assertTrue(result["ok"], result)
        self.assertEqual((result["rows"], result["chained"], result["legacy"], result["branches"]), (5, 5, 0, 0))
        self.assertEqual(result["head"], rows(store)[-1]["hash"])

    def test_verification_reads_the_collection_in_pages(self):
        import splunk_ucm.audit as module
        store, audit = filled(12)
        sizes = []
        original = store.query

        def spy(collection, query=None, sort=(), skip=0, limit=0, fields=None):
            sizes.append(limit)
            return original(collection, query, sort=sort, skip=skip, limit=limit, fields=fields)

        store.query = spy
        old = module.PAGE
        module.PAGE = 5
        try:
            result = audit.verify_chain()
        finally:
            module.PAGE = old
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["chained"], 12)
        self.assertTrue(all(s <= 5 for s in sizes) and len(sizes) == 3, sizes)

    def test_an_edited_row_is_found(self):
        store, audit = filled()
        victim = rows(store)[2]
        victim["actor"] = "mallory"
        store.upsert(C.AUDIT, victim)
        result = audit.verify_chain()
        self.assertFalse(result["ok"])
        self.assertEqual([m["key"] for m in result["modified"]], [victim["_key"]])

    def test_a_deleted_middle_row_is_found_as_a_missing_predecessor(self):
        store, audit = filled()
        victim = rows(store)[2]
        store.delete(C.AUDIT, victim["_key"])
        result = audit.verify_chain()
        self.assertFalse(result["ok"])
        self.assertEqual(result["missing_count"], 1)
        self.assertEqual(result["modified_count"], 0)

    def test_retention_may_remove_the_oldest_rows(self):
        store, audit = filled()
        for victim in rows(store)[:2]:
            store.delete(C.AUDIT, victim["_key"])
        result = audit.verify_chain()
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["chained"], 3)

    def test_rows_from_before_the_chain_are_counted_not_failed(self):
        store = InMemoryStore()
        store.upsert(C.AUDIT, {"_key": "old1", "time": 1.0, "time_iso": "x", "actor": "a", "action": "x",
                               "object_type": "o", "object_id": "1", "outcome": "success", "details": {}})
        audit = AuditService(store)
        audit.record("bob", "deployment.draft", "deployment", "uc-1")
        audit.record("bob", "deployment.draft", "deployment", "uc-2")
        result = audit.verify_chain()
        self.assertTrue(result["ok"], result)
        self.assertEqual((result["legacy"], result["chained"]), (1, 2))

    def test_concurrent_writers_make_branches_which_are_not_failures(self):
        store, audit = filled(3)
        head = rows(store)[-1]
        twin = {"_key": "zz", "time": head["time"] + 0.5, "time_iso": "t", "actor": "b", "action": "deployment.draft",
                "object_type": "deployment", "object_id": "x", "outcome": "success", "details": {},
                "prev_hash": rows(store)[-2]["hash"]}
        twin["hash"] = row_hash(twin)
        store.upsert(C.AUDIT, twin)
        result = audit.verify_chain()
        self.assertTrue(result["ok"], result)
        self.assertEqual(result["branches"], 1)

    def test_a_restarted_chain_is_reported(self):
        store, audit = filled(3)
        extra = {"_key": "zz", "time": rows(store)[-1]["time"] + 1, "time_iso": "t", "actor": "b", "action": "a",
                 "object_type": "o", "object_id": "x", "outcome": "success", "details": {}, "prev_hash": ""}
        extra["hash"] = row_hash(extra)
        store.upsert(C.AUDIT, extra)
        result = audit.verify_chain()
        self.assertFalse(result["ok"])
        self.assertEqual(result["restart_count"], 1)

    def test_hash_ignores_integral_float_versus_int(self):
        a = {"_key": "k", "time": 1.5, "details": {"n": 100.0, "l": [1.0, 2.5]}}
        b = {"_key": "k", "time": 1.5, "details": {"n": 100, "l": [1, 2.5]}}
        self.assertEqual(row_hash(a), row_hash(b))

    def test_a_failing_head_read_starts_nothing_and_never_blocks_the_write(self):
        store, audit = filled(1)
        original = store.query

        def broken(collection, *args, **kw):
            if kw.get("limit") == 1:
                raise RuntimeError("kv down")
            return original(collection, *args, **kw)
        store.query = broken
        audit.record("alice", "deployment.draft", "deployment", "uc-9")
        store.query = original
        self.assertEqual(len(rows(store)), 2)
        self.assertEqual(rows(store)[-1]["prev_hash"], "")


if __name__ == "__main__":
    unittest.main()
