"""Splunk Lantern page classification, collection parsing, article extraction and normalization."""

import json
import unittest

import helpers  # noqa: F401
import lantern_fakes as LF
from splunk_ucm.content.lantern import parser as P
from splunk_ucm.content.lantern.html import parse_html
from splunk_ucm.content.lantern.normalizer import NORMALIZER_VERSION, lantern_validation_policy
from splunk_ucm.content.lantern.sessions import preview_usecase
from splunk_ucm.content.registry import normalizer_for
from splunk_ucm.content.validation import RecordValidator
from splunk_ucm.storage.repositories import encode_raw

NOW = "2026-11-20T10:00:00Z"


def parsed(name, url):
    return P.parse(LF.fixture(name), url)


def article(name="article_full.html", url=LF.ARTICLE):
    page, kind = parsed(name, url)
    assert kind.kind == P.KIND_ARTICLE, kind
    return P.extract_article(page, NOW)


class ClassificationTest(unittest.TestCase):
    def test_page_kinds(self):
        cases = [("collection_cisco.html", LF.CISCO, P.KIND_COLLECTION, "guide"),
                 ("collection_security.html", LF.SECURITY, P.KIND_COLLECTION, "category"),
                 ("collection_guide.html", LF.GUIDE, P.KIND_COLLECTION, "guide"),
                 ("article_full.html", LF.ARTICLE, P.KIND_ARTICLE, "topic"),
                 ("article_minimal.html", LF.MINIMAL, P.KIND_ARTICLE, "topic"),
                 ("home.html", LF.BASE_URL + "/", P.KIND_UNSUPPORTED, "home")]
        for name, url, kind, page_type in cases:
            page, result = parsed(name, url)
            self.assertEqual((result.kind, page.meta.page_type), (kind, page_type), name)
        self.assertIn("home page", parsed("home.html", LF.BASE_URL + "/")[1].reason)

    def test_unknown_template_uses_structure(self):
        page, result = parsed("unknown_template.html", LF.BASE_URL + "/Observability_Use_Cases/A")
        self.assertEqual(result.kind, P.KIND_COLLECTION)
        self.assertIn("structural_fallback", result.signals)
        self.assertTrue(page.content_fallback)
        bare, result = P.parse("<html><body><h1>Hello</h1><p>Short.</p></body></html>", LF.CISCO)
        self.assertEqual(result.kind, P.KIND_UNSUPPORTED)
        self.assertIn("not recognised", result.reason)
        _page, result = P.parse("", LF.CISCO)
        self.assertEqual(result.kind, P.KIND_UNSUPPORTED)

    def test_metadata(self):
        page, _ = parsed("article_full.html", LF.ARTICLE)
        meta = page.meta
        self.assertEqual(meta.title, "Investigating phishing attacks")
        self.assertEqual(meta.canonical_url, LF.ARTICLE)
        self.assertEqual([c["title"] for c in meta.breadcrumbs],
                         ["Security Use Cases", "Accelerate Threat Investigation"])
        self.assertEqual(meta.modified, "2026-03-02T08:30:00Z")
        self.assertEqual(meta.published, "2025-01-10T10:00:00Z")
        self.assertEqual(meta.classifications["Technical Add-On"], ["Google Workspace Add-on"])
        self.assertEqual(meta.authors, "Test Author, Second Author")
        self.assertEqual(meta.tags, ["Enterprise Security", "Email"])


class HtmlTest(unittest.TestCase):
    def test_drops_active_content_and_survives_self_closing(self):
        root = parse_html("<div><svg/><script>bad()</script><p>kept</p><iframe src=x></iframe><style>x</style>"
                          "<p>also kept</p></div>")
        self.assertEqual(root.text(), "kept also kept")
        self.assertIsNone(root.find(lambda n: n.tag in ("script", "svg", "iframe", "style")))

    def test_block_text_is_separated(self):
        self.assertEqual(parse_html("<ul><li>one</li><li>two</li></ul>").text(), "one two")
        self.assertEqual(parse_html("<p>a<b>b</b>c</p>").text(), "abc")

    def test_depth_and_size_are_bounded(self):
        root = parse_html("<div>" * 5000 + "deep" + "</div>" * 5000)
        self.assertIn("deep", root.text())
        root = parse_html("<p>x</p>" * 200000)
        self.assertLess(len(root.find_all(lambda n: n.tag == "p")), 200000)


class CollectionTest(unittest.TestCase):
    def collection(self, name, url):
        page, result = parsed(name, url)
        self.assertEqual(result.kind, P.KIND_COLLECTION)
        return P.parse_collection(page)

    def test_cisco_style_guide(self):
        result = self.collection("collection_cisco.html", LF.CISCO)
        urls = [i["url"] for i in result.items]
        self.assertEqual(len(urls), len(set(urls)), "links are deduplicated")
        self.assertEqual(result.title, "Splunk and Cisco Use Cases")
        self.assertEqual([c["name"] for c in result.categories],
                         ["Correlate network domains", "Security, identity, and compliance",
                          "Data onboarding and platform operations"])
        self.assertEqual(result.categories[2]["subcategories"], ["Edge processing"])
        switch = next(i for i in result.items if i["url"] == LF.CISCO_ARTICLES[0])
        self.assertEqual(switch["category"], "Correlate network domains")
        self.assertEqual(switch["also_in"], [{"category": "Security, identity, and compliance", "subcategory": ""}])
        self.assertIn(LF.BASE_URL + "/Observability_Use_Cases/Troubleshoot/Assuring_enterprise_WAN_services", urls)
        self.assertIn(LF.BASE_URL + "/Sharing_information_in_a_global_operation", urls, "relative link resolved")
        self.assertIn(LF.CISCO_ARTICLES[2], urls, "?title= link canonicalized")
        self.assertIn(LF.BASE_URL + "/Platform_Data_Management/Unlock_Insights/Monitoring_Cisco_network_devices_"
                                    "using_gRPC", urls, "http link upgraded")
        joined = " ".join(urls)
        for absent in ("evil", "cisco.com", ".pdf", "@go", "Inline_only_article", "Data_Sources", "Survey",
                       "Threat_Investigation", "javascript"):
            self.assertNotIn(absent, joined)
        self.assertNotIn(LF.CISCO, urls)
        for reason in ("duplicate", "external", "navigation", "inline_link", "self_link", "anchor",
                       "unsupported_page", "unsupported_scheme"):
            self.assertGreaterEqual(result.skipped.get(reason, 0), 1, reason)
        self.assertEqual([i["position"] for i in result.items], list(range(len(result.items))))

    def test_featured_category_lists_sub_collections(self):
        result = self.collection("collection_security.html", LF.SECURITY)
        self.assertEqual([i["title"] for i in result.items],
                         ["Accelerate Threat Investigation", "Mitigate Threats With Security Monitoring",
                          "Simplify Compliance"])
        self.assertTrue(all(i["kind_guess"] == P.KIND_COLLECTION and i["role"] == "featured" for i in result.items))
        self.assertEqual(result.items[0]["description"], "Test summary for threat investigation.")
        self.assertEqual(result.items[1]["url"], LF.BASE_URL + "/Security_Use_Cases/Security_Monitoring")

    def test_guide_listing_with_subcategories(self):
        result = self.collection("collection_guide.html", LF.GUIDE)
        self.assertEqual(len(result.items), 3)
        self.assertEqual(result.categories[0]["name"], "Accelerate Threat Investigation")
        self.assertEqual(result.categories[0]["subcategories"], ["Enterprise Security", "SOAR"])
        phishing = result.items[0]
        self.assertEqual((phishing["subcategory"], phishing["kind_guess"]), ("Enterprise Security", P.KIND_ARTICLE))
        self.assertEqual(phishing["also_in"], [{"category": "Accelerate Threat Investigation", "subcategory": "SOAR"}])

    def test_empty_collection_and_limits(self):
        result = self.collection("collection_empty.html", LF.EMPTY)
        self.assertEqual(result.items, [])
        self.assertEqual(result.categories, [])
        page, _ = parsed("collection_cisco.html", LF.CISCO)
        limited = P.parse_collection(page, max_items=2)
        self.assertEqual(len(limited.items), 2)
        self.assertTrue(limited.truncated)


class ArticleTest(unittest.TestCase):
    def test_structure_is_preserved(self):
        raw = article()
        kinds = [b["type"] for b in raw["blocks"]]
        for kind in ("heading", "paragraph", "list", "table", "code"):
            self.assertIn(kind, kinds)
        headings = [(b["level"], b["text"]) for b in raw["blocks"] if b["type"] == "heading"]
        self.assertIn((2, "Prerequisites"), headings)
        self.assertIn((3, "Data"), headings)
        self.assertIn((4, "Search explanation"), headings)
        steps = next(b for b in raw["blocks"] if b["type"] == "list" and b.get("ordered"))
        self.assertEqual(steps["items"], ["Install the add-on.", "  - Use the search head.",
                                          "  - Restart if prompted.", "Run the searches below."])
        table = next(b for b in raw["blocks"] if b["type"] == "table")
        self.assertEqual(table["header"], ["Field", "Meaning"])
        self.assertEqual(table["rows"][0], ["sender", "Envelope sender address"])
        self.assertIn("1. Install the add-on.\n  - Use the search head.\n  - Restart if prompted.\n2. Run",
                      raw["implementation"])
        note = next(b for b in raw["blocks"] if b.get("text") == "Tip: test note inside the article.")
        self.assertTrue(note.get("note"))

    def test_spl_is_preserved_exactly_as_code(self):
        raw = article()
        self.assertEqual(len(raw["spl_blocks"]), 2)
        self.assertEqual(raw["spl_blocks"][0]["spl"],
                         'index=email sourcetype="gws:gmail" attachment=*\n| stats count BY sender, file_name\n'
                         '| where count > 5')
        self.assertTrue(raw["spl_blocks"][1]["spl"].startswith("| tstats count FROM datamodel=Endpoint.Processes"))
        self.assertIn("`drop_dm_object_name(Processes)`", raw["spl_blocks"][1]["spl"])
        self.assertEqual(raw["spl_blocks"][1]["section"],
                         "How to use Splunk software for this use case > Correlate with endpoint data")
        self.assertEqual(raw["code_block_count"], 3)
        bash = next(b for b in raw["blocks"] if b["type"] == "code" and not b["is_spl"])
        self.assertEqual((bash["language"], bash["text"]), ("bash", "sudo systemctl restart splunk"))

    def test_sections_map_to_fields(self):
        raw = article()
        self.assertTrue(raw["description"].startswith("Test introduction: analysts receive reports"))
        self.assertEqual(raw["business_value"], "Faster scoping of phishing campaigns and fewer compromised accounts.")
        self.assertEqual(raw["data_sources"], ["Email gateway logs", "Google: Workspace"])
        self.assertEqual(raw["products"], ["Enterprise Security", "Splunk Security Essentials"])
        self.assertEqual([(a["name"], a["role"]) for a in raw["addons"]],
                         [("Google Workspace Add-on", "primary"), ("Splunk Security Essentials", "recommended"),
                          ("Phishing Response App", "app")])
        self.assertEqual(raw["addons"][1]["splunkbase_id"], "3435")
        self.assertEqual(raw["related_articles"],
                         [{"title": "Implementing risk-based alerting",
                           "url": LF.GUIDE + "/Implementing_risk-based_alerting"}])
        self.assertEqual([r["url"] for r in raw["resources"]],
                         ["https://splunkbase.splunk.com/app/3435", "https://docs.splunk.com/Documentation/ES"])
        self.assertEqual(raw["dashboards"], [{"title": "Phishing overview dashboard", "url": ""}])
        self.assertEqual(raw["mitre"], ["T1566.001"])
        self.assertEqual(raw["section_path"], ["Security Use Cases", "Accelerate Threat Investigation"])
        self.assertEqual(raw["extraction"]["confidence"], "high")
        self.assertFalse(raw["extraction"]["needs_review"])

    def test_no_active_or_navigation_content(self):
        text = json.dumps(article())
        for absent in ("injected", "document.write", "Survey text", "mailto:", "Special:Tags"):
            self.assertNotIn(absent, text)

    def test_incomplete_page_is_flagged_not_invented(self):
        raw = article("article_minimal.html", LF.MINIMAL)
        self.assertEqual(raw["extraction"]["confidence"], "low")
        self.assertTrue(raw["extraction"]["needs_review"])
        self.assertTrue(any("no SPL" in w for w in raw["extraction"]["warnings"]))
        for field in ("business_value", "implementation", "modified", "authors", "article_type"):
            self.assertEqual(raw[field], "", field)
        for field in ("spl_blocks", "products", "addons", "data_sources", "dashboards", "mitre", "breadcrumbs"):
            self.assertEqual(raw[field], [], field)
        self.assertEqual(raw["section_path"], ["Observability Use Cases", "Troubleshoot"])

    def test_malformed_html_does_not_crash(self):
        page, result = parsed("malformed.html", LF.BASE_URL + "/Security_Use_Cases/Broken_page")
        self.assertEqual(result.kind, P.KIND_ARTICLE)
        raw = P.extract_article(page, NOW)
        self.assertEqual(raw["title"], "Broken page")
        self.assertTrue(raw["extraction"]["needs_review"])
        self.assertNotIn("alert(1)", json.dumps(raw))

    def test_hash_is_stable_and_ignores_retrieval_time(self):
        first = article()
        second = P.extract_article(parsed("article_full.html", LF.ARTICLE)[0], "2030-01-01T00:00:00Z")
        self.assertEqual(first["content_hash"], second["content_hash"])
        self.assertEqual(first["content_hash"], P.content_hash(first))
        changed_html = LF.fixture("article_full.html").replace("where count &gt; 5", "where count &gt; 10")
        changed = P.extract_article(P.parse(changed_html, LF.ARTICLE)[0], NOW)
        self.assertNotEqual(first["content_hash"], changed["content_hash"])
        changes = P.diff_articles(first, changed)
        self.assertTrue(changes)
        self.assertIn("spl_blocks", [c["field"] for c in changes])
        self.assertEqual(P.diff_articles(first, second), [])

    def test_raw_record_passes_lantern_validation(self):
        raw = article()
        validator = RecordValidator(lantern_validation_policy())
        self.assertTrue(validator.validate(raw, len(encode_raw(raw))).ok)
        bad = dict(raw, id="UC-1.1.1")
        self.assertFalse(validator.validate(bad, len(encode_raw(bad))).ok)


class NormalizerTest(unittest.TestCase):
    def test_canonical_use_case_from_article(self):
        uc = preview_usecase(article())
        self.assertRegex(uc["content_id"], r"^lantern:LN-[0-9a-f]{20}$")
        self.assertEqual(uc["key"], uc["content_id"].replace(":", "_"))
        self.assertEqual(uc["provenance"]["provider"], "lantern")
        self.assertEqual(uc["provenance"]["source_url"], LF.ARTICLE)
        self.assertEqual(uc["provenance"]["normalizer_version"], NORMALIZER_VERSION)
        self.assertEqual(uc["category_name"], "Splunk Lantern: Security Use Cases")
        self.assertEqual(uc["subcategory"], "Accelerate Threat Investigation")
        self.assertEqual(uc["domains"], ["security"])
        self.assertEqual(uc["spl"], "")
        self.assertEqual([v["model"] for v in uc["spl_variants"]],
                         ["Search 1: How to use Splunk software for this use case",
                          "Search 2: Correlate with endpoint data"])
        self.assertEqual(uc["references"][0]["title"], "Original article on Splunk Lantern")
        self.assertEqual(uc["framework_mappings"][0]["object_id"], "T1566.001")
        self.assertEqual(uc["visualization"], "Phishing overview dashboard")
        self.assertEqual((uc["criticality"], uc["difficulty"], uc["review_status"], uc["last_reviewed"]),
                         ("unknown", "unknown", "unknown", ""))

    def test_requirements_carry_honest_confidence(self):
        reqs = {r["req_id"]: r for r in preview_usecase(article())["requirements"]}
        self.assertEqual(reqs["sourcetype:gws:gmail"]["confidence"], "low")
        self.assertEqual(reqs["index:email"]["level"], "informational")
        self.assertEqual(reqs["cim_model:Endpoint"]["source"], "derived_spl")
        self.assertIn("macro:drop_dm_object_name(1)", reqs)
        self.assertIn("lookup:asset_lookup", reqs)
        self.assertEqual((reqs["data_source:Email gateway logs"]["source"],
                          reqs["data_source:Email gateway logs"]["confidence"]), ("derived_text", "medium"))
        self.assertEqual((reqs["addon:Google Workspace Add-on"]["level"],
                          reqs["addon:Google Workspace Add-on"]["confidence"]), ("required", "high"))
        self.assertEqual(reqs["addon:3435"]["level"], "recommended")
        self.assertEqual(reqs["product:Enterprise Security"]["source"], "provider_structured")
        self.assertFalse([r for r in reqs if r.startswith("spl_validity")])
        self.assertNotIn("product:Splunk Security Essentials", reqs)

    def test_single_search_becomes_primary_spl(self):
        uc = preview_usecase(article("article_single_spl.html", LF.SINGLE))
        self.assertEqual(uc["spl"], 'index=network sourcetype=cisco:ios "%LINK-3-UPDOWN"\n| stats count BY host')
        self.assertEqual(uc["spl_variants"], [])
        reqs = {r["req_id"]: r for r in uc["requirements"]}
        self.assertEqual(reqs["sourcetype:cisco:ios"]["confidence"], "medium")
        self.assertEqual(uc["domains"], ["network"])

    def test_article_without_spl(self):
        uc = preview_usecase(article("article_minimal.html", LF.MINIMAL))
        self.assertEqual((uc["spl"], uc["spl_variants"], uc["spl_status"]), ("", [], "none"))
        self.assertEqual(uc["requirements"], [])
        self.assertEqual(uc["domains"], ["observability"])

    def test_provenance_extras_and_determinism(self):
        raw = article()
        raw["import"] = {"imported_by": "alice", "imported_at": NOW, "found_in": [{"url": LF.GUIDE}]}
        normalizer = normalizer_for("lantern")
        from splunk_ucm.content.lantern.provider import StagedLanternProvider
        provider = StagedLanternProvider([raw], "s1")
        manifest = provider.get_manifest()
        self.assertTrue(manifest.partial)
        category = normalizer.normalize_category(manifest.categories[0], "lantern")
        record = provider.get_use_case(manifest, raw["id"])
        one = normalizer.normalize(record, category, manifest, NOW)
        two = normalizer.normalize(record, category, manifest, NOW)
        self.assertEqual(one, two)
        extras = one.provider_extras["lantern"]
        for field in ("source_url", "source_title", "source_retrieved_at", "source_content_hash",
                      "source_last_updated", "imported_by", "imported_at", "extraction_version",
                      "extraction_confidence"):
            self.assertTrue(extras[field], field)
        self.assertEqual(extras["imported_by"], "alice")
        self.assertEqual(extras["source_content_hash"], raw["content_hash"])


if __name__ == "__main__":
    unittest.main()
