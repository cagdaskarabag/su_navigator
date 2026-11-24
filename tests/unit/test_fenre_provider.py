import unittest

import helpers
from splunk_ucm.content.fenre.provider import FenreConfig, FenreJsonProvider, parse_allowed_refs
from splunk_ucm.errors import IntegrityError, NotFoundError, ProviderError, RateLimitedError, ValidationError


class FenreProviderTest(unittest.TestCase):
    def setUp(self):
        self.gh = helpers.FakeGitHub()
        self.provider = helpers.fenre_provider(self.gh)

    def test_manifest_from_upstream_layout(self):
        m = self.provider.get_manifest()
        self.assertEqual(m.provider_version, "8.28.0")
        self.assertEqual(m.schema_version, "1.11.0")
        self.assertEqual(m.source_ref, self.gh.commit)
        self.assertEqual([c.category_id for c in m.categories], ["1", "5", "7", "8", "9", "10", "13", "14", "18"])
        cat9 = m.category("9")
        self.assertEqual(cat9.name, "Identity & Access Management")
        self.assertEqual(cat9.path, "content/cat-09-identity-access-management")
        self.assertEqual(m.warnings, [])

    def test_list_and_fetch_verify_blob_sha(self):
        m = self.provider.get_manifest()
        listings = self.provider.list_records(m, m.category("9"))
        self.assertEqual(sorted(l.record_id for l in listings), ["9.1.1", "9.1.2"])
        rec = self.provider.fetch_record(m, m.category("9"), listings[0])
        self.assertEqual(rec.raw["id"], rec.record_id)
        self.assertIn("/%s/" % m.source_ref, rec.source_url)

    def test_tampered_blob_rejected(self):
        m = self.provider.get_manifest()
        listing = self.provider.list_records(m, m.category("9"))[0]
        self.gh.tampered[listing.path] = b'{"id": "9.1.1", "title": "tampered", "spl": "| delete"}'
        with self.assertRaises(IntegrityError):
            self.provider.fetch_record(m, m.category("9"), listing)

    def test_raw_downloads_are_pinned_to_commit(self):
        m = self.provider.get_manifest()
        self.provider.get_use_case(m, "10.4.24")
        raw_urls = [u for u in self.gh.requests if u.startswith(helpers.RAW)]
        self.assertTrue(raw_urls)
        self.assertTrue(all("/%s/" % m.source_ref in u for u in raw_urls))

    def test_truncated_tree_rejected(self):
        self.gh.truncate_trees = True
        with self.assertRaises(ProviderError):
            self.provider.get_manifest()

    def test_missing_schema_falls_back_with_warning(self):
        self.gh.delete("schemas/uc.schema.json")
        m = self.provider.get_manifest()
        self.assertEqual(m.schema_version, "1.11.0")
        self.assertTrue(any("bundled schema" in w for w in m.warnings))

    def test_bad_version_flagged(self):
        self.gh.put("VERSION", b"<script>")
        m = self.provider.get_manifest()
        self.assertEqual(m.provider_version, "unknown")
        self.assertTrue(m.warnings)

    def test_unknown_record(self):
        m = self.provider.get_manifest()
        with self.assertRaises(NotFoundError):
            self.provider.get_use_case(m, "9.9.9")

    def test_config_validation(self):
        for kw in ({"ref": "main;rm"}, {"ref": "../x"}, {"owner": "a/b"}, {"content_root": "/etc"},
                   {"schema_path": "../../x"}, {"fetch_concurrency": 0}):
            with self.assertRaises(ProviderError, msg=kw):
                FenreJsonProvider(FenreConfig(**kw), fetcher=self.gh)

    def test_token_sent_only_to_api(self):
        captured = []

        class Spy(helpers.FakeGitHub):
            def get(self, url, headers=None, max_bytes=None):
                captured.append((url, dict(headers or {})))
                return super().get(url, headers, max_bytes)

        gh = Spy()
        provider = helpers.fenre_provider(gh, token="ghp_example")
        m = provider.get_manifest()
        provider.get_use_case(m, "9.1.1")
        for url, headers in captured:
            if url.startswith(helpers.RAW):
                self.assertNotIn("Authorization", headers)
            else:
                self.assertEqual(headers.get("Authorization"), "Bearer ghp_example")


class RefPolicyTest(unittest.TestCase):
    def setUp(self):
        self.gh = helpers.FakeGitHub()

    def fetched_content(self):
        return [u for u in self.gh.requests if "/compare/" not in u]

    def test_names_outside_allowed_refs_are_rejected_without_network(self):
        for ref in ("dev", "v1.0", "feature/main"):
            with self.assertRaises(ValidationError):
                helpers.fenre_provider(self.gh, ref=ref).get_manifest()
        self.assertEqual(self.gh.requests, [])
        provider = helpers.fenre_provider(self.gh, ref="release/2.0", allowed_refs=("main", "release/*"))
        self.assertEqual(provider.get_manifest().requested_ref, "release/2.0")

    def test_pinned_commit_on_an_allowed_branch_is_accepted(self):
        current = self.gh.commit
        m = helpers.fenre_provider(self.gh, ref=current).get_manifest()
        self.assertEqual(m.source_ref, current)
        self.assertIn("/compare/main...%s" % current, self.gh.requests[0])
        self.gh.put("content/NEW.txt", b"x")
        self.assertNotEqual(self.gh.commit, current)
        self.assertEqual(helpers.fenre_provider(self.gh, ref=current).verify_ref(), "main")

    def test_unreachable_commit_is_rejected_before_any_fetch(self):
        stray = "ab" * 20
        self.gh.diverged.add("cd" * 20)
        for sha in (stray, "cd" * 20):
            self.gh.requests.clear()
            with self.assertRaises(ValidationError) as ctx:
                helpers.fenre_provider(self.gh, ref=sha).get_manifest()
            self.assertEqual(ctx.exception.message, "commit is not reachable from an allowed ref")
            self.assertEqual(self.fetched_content(), [])

    def test_wildcards_cannot_vouch_for_a_commit(self):
        with self.assertRaises(ValidationError):
            helpers.fenre_provider(self.gh, ref=self.gh.commit, allowed_refs=("release/*",)).get_manifest()
        self.assertEqual(self.gh.requests, [])

    def test_rate_limit_is_not_reported_as_unreachable(self):
        gh = self.gh

        class Limited:
            def get(self, url, headers=None, max_bytes=None):
                if "/compare/" in url:
                    raise RateLimitedError("rate limited")
                return gh.get(url, headers, max_bytes)
        provider = FenreJsonProvider(FenreConfig(ref=gh.commit), fetcher=Limited())
        with self.assertRaises(RateLimitedError):
            provider.get_manifest()

    def test_allowed_refs_parsing_and_validation(self):
        self.assertEqual(parse_allowed_refs(" main, v* ,", "stable"), ("main", "v*", "stable"))
        self.assertEqual(parse_allowed_refs("", "main"), ("main",))
        self.assertEqual(parse_allowed_refs("main", "ab" * 20), ("main",))
        for bad in ("main;x", "a..b", "x y"):
            with self.assertRaises(ProviderError):
                FenreJsonProvider(FenreConfig(allowed_refs=(bad,)), fetcher=self.gh)


if __name__ == "__main__":
    unittest.main()
