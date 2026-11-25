import unittest

import helpers  # noqa: F401

from splunk_ucm.catalog.derived import compute_facets
from splunk_ucm.catalog.query import CatalogFilter, MATURITIES, build_query
from splunk_ucm.catalog.summary import DATA_MATURITY, catalog_summary, data_maturity
from splunk_ucm.errors import ValidationError
from splunk_ucm.model.canonical import Provenance, Requirement, SplVariant, UseCase


def make(*reqs, products=(), flags=(), variants=()):
    prov = Provenance("p", "1", "v", "r", "u", "path", "h", "b", "s", "t", "n")
    uc = UseCase("p:UC-1", "p_UC-1", "T", prov, products=list(products), quality_flags=list(flags))
    uc.requirements = [Requirement("r%d" % i, t, v, level) for i, (t, v, level) in enumerate(reqs)]
    uc.spl_variants = list(variants)
    return uc


def req(kind, value="x", level="required"):
    return (kind, value, level)


class MaturityTest(unittest.TestCase):
    def test_levels_are_ordered_and_documented(self):
        self.assertEqual(DATA_MATURITY, MATURITIES)
        self.assertEqual(DATA_MATURITY, ("raw", "normalized", "enriched", "correlated"))

    def test_events_only_is_raw(self):
        self.assertEqual(data_maturity(make(req("sourcetype", "a"), req("index", "i"))), "raw")

    def test_a_data_model_is_normalized(self):
        self.assertEqual(data_maturity(make(req("cim_model", "Authentication"))), "normalized")

    def test_a_lookup_is_enriched_and_beats_a_data_model(self):
        self.assertEqual(data_maturity(make(req("cim_model", "Authentication"), req("lookup", "assets"))), "enriched")

    def test_enterprise_security_or_three_sourcetypes_is_correlated(self):
        self.assertEqual(data_maturity(make(req("sourcetype", "a"), products=["Splunk Enterprise Security"])), "correlated")
        self.assertEqual(data_maturity(make(req("sourcetype", "a"), flags=["es_required"])), "correlated")
        three = make(req("sourcetype", "a"), req("sourcetype", "b"), req("sourcetype", "c"))
        self.assertEqual(data_maturity(three), "correlated")
        self.assertEqual(data_maturity(make(req("sourcetype", "a"), req("sourcetype", "b"))), "raw")

    def test_variant_sourcetypes_count(self):
        v = [SplVariant("m", "s", ["b", "c"])]
        self.assertEqual(data_maturity(make(req("sourcetype", "a"), variants=v)), "correlated")

    def test_informational_requirements_do_not_count(self):
        self.assertEqual(data_maturity(make(req("sourcetype", "a"), req("lookup", "l", "informational"))), "raw")

    def test_a_use_case_that_reads_no_data_has_no_level(self):
        self.assertEqual(data_maturity(make(req("macro", "m"), req("addon", "x"))), "")
        self.assertEqual(data_maturity(make()), "")

    def test_summary_carries_the_level(self):
        self.assertEqual(catalog_summary(make(req("cim_model", "Web")))["data_maturity"], "normalized")


class FilterAndFacetTest(unittest.TestCase):
    def test_filter_accepts_known_levels_only(self):
        self.assertEqual(build_query(CatalogFilter(provider_status="", maturities=["raw", "enriched"])),
                         {"data_maturity": {"$in": ["raw", "enriched"]}})
        with self.assertRaises(ValidationError):
            build_query(CatalogFilter(maturities=["expert"]))

    def test_facet_counts_active_rows_only(self):
        rows = [{"provider_status": "active", "data_maturity": "raw", "summary_version": 7},
                {"provider_status": "active", "data_maturity": "raw", "summary_version": 7},
                {"provider_status": "active", "data_maturity": "", "summary_version": 7},
                {"provider_status": "withdrawn", "data_maturity": "enriched", "summary_version": 7}]
        self.assertEqual(compute_facets(rows)["maturities"], {"raw": 2})

    def test_provider_info_reports_the_newest_import_per_provider(self):
        rows = [{"provider_status": "active", "provider": "escu", "provider_version": "6.10", "imported_at": "2026-11-01T00:00:00Z"},
                {"provider_status": "active", "provider": "escu", "provider_version": "6.11", "imported_at": "2026-11-20T00:00:00Z"},
                {"provider_status": "active", "provider": "fenre", "provider_version": "x", "imported_at": "2026-11-02T00:00:00Z"},
                {"provider_status": "withdrawn", "provider": "fenre", "provider_version": "y", "imported_at": "2026-12-01T00:00:00Z"}]
        info = compute_facets(rows)["provider_info"]
        self.assertEqual(info["escu"], {"count": 2, "version": "6.11", "updated": "2026-11-20T00:00:00Z"})
        self.assertEqual(info["fenre"], {"count": 1, "version": "x", "updated": "2026-11-02T00:00:00Z"})


if __name__ == "__main__":
    unittest.main()
