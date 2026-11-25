import json
import unittest

import helpers  # noqa: F401  (sets sys.path)
from splunk_ucm.audit import AuditService
from splunk_ucm.deployment.service import DeploymentService, DeploymentSettings
from splunk_ucm.errors import ConflictError, StorageError
from splunk_ucm.readiness import ENGINE_VERSION
from splunk_ucm.readiness.evaluators import (MET, NOT_APPLICABLE, NOT_MET, PARTIAL, UNVERIFIED,
                                             EvaluationSettings, evaluate)
from splunk_ucm.readiness.principal import (PRINCIPAL_NO_OWNER, PRINCIPAL_NOT_FOUND, PRINCIPAL_OK,
                                            PRINCIPAL_UNREADABLE, PrincipalAccess, SchedulerAccess,
                                            check_access, pattern_matches, read_principal, scan_spl)
from splunk_ucm.readiness.service import ReadinessService, ReadinessSettings
from splunk_ucm.readiness.snapshot import EnvironmentSnapshot
from splunk_ucm.spl.policy import expanded_pipeline
from splunk_ucm.storage import collections as C
from splunk_ucm.storage.transport import SplunkdTransport
from unit.test_deployment import FakeSavedSearches, UC
from unit.test_discovery import loaded_catalog
from unit.test_readiness import discovered_store, snap
from unit.test_selection_validation import FakeParser

KNOWN = [{"name": n, "status": "active"} for n in
         ("main", "winevents", "winsec", "_internal", "_audit", "_introspection", "unix_logs")]


def role(own=None, imported=None, **extra):
    own = own or {}
    imported = imported or {}
    content = {"srchIndexesAllowed": own.get("allowed", []), "srchIndexesDisallowed": own.get("disallowed", []),
               "srchIndexesDefault": own.get("default", []), "srchFilter": own.get("filter", ""),
               "imported_srchIndexesAllowed": imported.get("allowed", []),
               "imported_srchIndexesDisallowed": imported.get("disallowed", []),
               "imported_srchIndexesDefault": imported.get("default", []),
               "imported_srchFilter": imported.get("filter", "")}
    content.update(extra)
    return content


class FakeRoles(SplunkdTransport):
    def __init__(self, users=None, roles=None, fail=None):
        self.users = users or {}
        self.roles = roles or {}
        self.fail = fail or {}
        self.calls = []

    def request(self, method, path, query=None, json_body=None, form=None, timeout=60.0):
        self.calls.append(path)
        if path in self.fail:
            exc = self.fail[path]
            if isinstance(exc, Exception):
                raise exc
            return exc, b"{}"
        for prefix, table in (("/services/authentication/users/", self.users),
                              ("/services/authorization/roles/", self.roles)):
            if path.startswith(prefix):
                name = path[len(prefix):]
                if name in table:
                    return 200, json.dumps({"entry": [{"name": name, "content": table[name]}]}).encode()
                return 404, b"{}"
        return 404, b"{}"


def principal(**kw):
    base = dict(owner="ucm_scheduler", roles=["ucm_scheduler"], allowed=["*"], disallowed=[], default=["main"],
                filters=[])
    base.update(kw)
    return PrincipalAccess(status=PRINCIPAL_OK, **base)


def check(spl, p, expanded="", sourcetype_indexes=None):
    return check_access(p, scan_spl(spl, expanded), KNOWN, sourcetype_indexes)


class WildcardTest(unittest.TestCase):
    def test_star_matches_only_non_internal(self):
        self.assertTrue(pattern_matches("*", "main"))
        self.assertFalse(pattern_matches("*", "_internal"))
        self.assertFalse(pattern_matches("*", "_audit"))

    def test_underscore_star_matches_internal_only(self):
        self.assertTrue(pattern_matches("_*", "_internal"))
        self.assertTrue(pattern_matches("_*", "_audit"))
        self.assertFalse(pattern_matches("_*", "main"))

    def test_pattern_starting_with_star_never_reaches_internal(self):
        self.assertFalse(pattern_matches("*audit", "_audit"))
        self.assertTrue(pattern_matches("*audit", "web_audit"))

    def test_per_pattern_wildcards_and_case(self):
        self.assertTrue(pattern_matches("_int*", "_internal"))
        self.assertTrue(pattern_matches("_int*", "_introspection"))
        self.assertTrue(pattern_matches("win*", "WinEvents"))
        self.assertTrue(pattern_matches("w*s*c", "winsec"))
        self.assertFalse(pattern_matches("win*", "unix_logs"))
        self.assertFalse(pattern_matches("", "main"))
        self.assertTrue(pattern_matches("main", "main"))
        self.assertFalse(pattern_matches("mai", "main"))

    def test_dots_and_brackets_are_literal(self):
        self.assertFalse(pattern_matches("a.c", "abc"))
        self.assertFalse(pattern_matches("[a]*", "a1"))


class CoverageRulesTest(unittest.TestCase):
    def test_default_user_role_cannot_see_internal(self):
        out = check("index=_internal sourcetype=scheduler | stats count", principal())
        self.assertEqual(out["status"], NOT_MET)
        self.assertEqual(out["code"], "index_not_accessible")
        self.assertIn("ucm_scheduler cannot search _internal", out["detail"])
        self.assertIn("'*' does not include internal indexes", out["detail"])
        self.assertIn("still report success", out["detail"])

    def test_granting_internal_makes_it_met(self):
        out = check("index=_internal | stats count", principal(allowed=["*", "_*"]))
        self.assertEqual(out["status"], MET)
        self.assertEqual(out["code"], "index_accessible")

    def test_named_internal_index_is_enough(self):
        self.assertEqual(check("index=_internal", principal(allowed=["_internal"]))["status"], MET)
        self.assertEqual(check("index=_audit", principal(allowed=["_internal"]))["status"], NOT_MET)

    def test_non_internal_covered_by_star(self):
        self.assertEqual(check("index=winevents EventCode=4625", principal())["status"], MET)

    def test_disallowed_wins_over_allowed(self):
        out = check("index=winsec", principal(allowed=["*"], disallowed=["win*"]))
        self.assertEqual(out["status"], NOT_MET)
        self.assertIn("disallowed by 'win*'", out["detail"])
        self.assertEqual(check("index=_audit", principal(allowed=["_*"], disallowed=["_audit"]))["status"], NOT_MET)

    def test_disallowed_star_does_not_touch_internal(self):
        p = principal(allowed=["*", "_*"], disallowed=["*"])
        self.assertEqual(check("index=main", p)["status"], NOT_MET)
        self.assertEqual(check("index=_internal", p)["status"], MET)

    def test_partial_when_one_index_is_missing(self):
        out = check("(index=main OR index=_internal) | stats count", principal())
        self.assertEqual(out["status"], PARTIAL)
        self.assertIn("not _internal", out["detail"])

    def test_wildcard_in_spl_expands_over_known_indexes(self):
        self.assertEqual(check("index=win*", principal(allowed=["winsec"]))["status"], MET)
        self.assertEqual(check("index=win*", principal(allowed=["unix_logs"]))["status"], NOT_MET)
        self.assertEqual(check("index=unknown*", principal())["code"], "index_pattern_unresolved")

    def test_spl_index_star_is_unverified_never_met(self):
        out = check("index=* error | stats count", principal(allowed=["*"]))
        self.assertEqual(out["status"], UNVERIFIED)
        self.assertEqual(out["code"], "index_star")

    def test_internal_wildcard_in_spl(self):
        self.assertEqual(check("index=_* | head 1", principal(allowed=["_*"]))["status"], MET)
        self.assertEqual(check("index=_* | head 1", principal())["status"], NOT_MET)

    def test_negated_index_is_ignored(self):
        self.assertEqual(check("index=main NOT index=_internal", principal())["status"], MET)

    def test_tstats_where_index(self):
        self.assertEqual(check("| tstats count where index=_internal by host", principal())["status"], NOT_MET)
        self.assertEqual(check("| tstats count where index=main by host", principal())["status"], MET)

    def test_default_indexes_when_no_index_in_spl(self):
        p = principal(allowed=["*"], default=["main"])
        out = check("sourcetype=syslog | stats count", p)
        self.assertEqual(out["status"], UNVERIFIED)
        self.assertEqual(out["code"], "default_index_data_unknown")
        met = check("sourcetype=syslog | stats count", p, sourcetype_indexes={"syslog": ["main"]})
        self.assertEqual(met["status"], MET)
        away = check("sourcetype=syslog | stats count", p, sourcetype_indexes={"syslog": ["unix_logs"]})
        self.assertEqual(away["status"], NOT_MET)
        self.assertIn("not a default index", away["detail"])

    def test_no_default_index_means_nothing_is_searched(self):
        out = check("sourcetype=syslog", principal(default=[]))
        self.assertEqual(out["status"], NOT_MET)
        self.assertIn("no default index", out["detail"])

    def test_default_must_also_be_allowed(self):
        out = check("sourcetype=syslog", principal(allowed=["winevents"], default=["main"]))
        self.assertEqual(out["status"], NOT_MET)

    def test_wildcard_default_expands_and_internal_default_works(self):
        p = principal(allowed=["_*"], default=["_internal"])
        self.assertEqual(check("sourcetype=splunkd", p, sourcetype_indexes={"splunkd": ["_internal"]})["status"], MET)
        p = principal(allowed=["*"], default=["win*"])
        self.assertEqual(p.default_indexes(["winevents", "winsec", "main"]), ["winevents", "winsec"])

    def test_srchfilter_adds_a_warning_but_keeps_the_verdict(self):
        out = check("index=main", principal(filters=["host=web*"]))
        self.assertEqual(out["status"], MET)
        self.assertIn("search filter", out["detail"])
        self.assertIn("host=web*", out["detail"])
        out = check("index=_internal", principal(filters=["host=web*"]))
        self.assertEqual(out["status"], NOT_MET)
        self.assertIn("search filter", out["detail"])

    def test_not_applicable_when_search_reads_no_index(self):
        out = check("| inputlookup assets.csv | stats count", principal())
        self.assertEqual(out["status"], NOT_APPLICABLE)
        self.assertEqual(check("| makeresults | eval x=1", principal())["status"], NOT_APPLICABLE)

    def test_inputlookup_with_a_macro_is_not_declared_not_applicable(self):
        out = check("| inputlookup assets.csv | `enrich`", principal())
        self.assertEqual(out["status"], UNVERIFIED)


class UnverifiedClassesTest(unittest.TestCase):
    def codes(self, spl, expanded=""):
        return scan_spl(spl, expanded)["unverified"]

    def test_datamodel_searches(self):
        for spl in ("| tstats count from datamodel=Authentication where Authentication.action=failure",
                    "| tstats summariesonly=t count from datamodel=Network_Traffic.All_Traffic",
                    "| datamodel Authentication Authentication search | stats count"):
            out = check(spl, principal())
            self.assertEqual(out["status"], UNVERIFIED, spl)
            self.assertEqual(out["code"], "datamodel", spl)

    def test_tags_and_eventtypes(self):
        self.assertEqual(check("tag=authentication action=failure", principal())["code"], "tags")
        self.assertEqual(check("eventtype=failed_login", principal())["code"], "eventtypes")

    def test_unexpanded_macro_is_unverified(self):
        out = check("`windows_index` EventCode=4625", principal())
        self.assertEqual(out["status"], UNVERIFIED)
        self.assertEqual(out["code"], "macro_not_expanded")

    def test_macro_with_a_literal_uncovered_index_is_still_not_met(self):
        out = check("index=_internal `extra_filter`", principal())
        self.assertEqual(out["status"], NOT_MET)

    def test_expanded_pipeline_resolves_macros(self):
        class Parsed:
            raw = {"commands": [{"command": "search", "args": "index=winsec EventCode=4625"},
                                {"command": "stats", "args": "count by host"}]}
        expanded = expanded_pipeline(Parsed())
        out = check("`windows_index` EventCode=4625", principal(), expanded)
        self.assertEqual(out["status"], MET)
        self.assertIn("winsec", out["detail"])
        self.assertTrue(scan_spl("`windows_index` x", expanded)["expanded"])

    def test_expanded_pipeline_with_internal_index_is_not_met(self):
        class Parsed:
            raw = {"commands": [{"command": "search", "args": "index=_audit action=*"}]}
        out = check("`audit_events`", principal(), expanded_pipeline(Parsed()))
        self.assertEqual(out["status"], NOT_MET)

    def test_hidden_searches_are_unverified(self):
        out = check('index=main | map search="search index=other $host$"', principal())
        self.assertEqual(out["status"], UNVERIFIED)
        self.assertEqual(out["code"], "hidden_search")

    def test_unverified_never_becomes_met_by_any_combination(self):
        for spl in ("index=* | stats count", "tag=web", "eventtype=x", "`m`", "index=main tag=web",
                    "| tstats count from datamodel=Web"):
            self.assertNotEqual(check(spl, principal(allowed=["*", "_*"]))["status"], MET, spl)


class RoleReadingTest(unittest.TestCase):
    def transport(self, **kw):
        users = {"ucm_scheduler": {"roles": ["ucm_scheduler", "extra"]}}
        roles = {
            "ucm_scheduler": role(imported={"allowed": ["*"], "default": ["main"]}),
            "extra": role(own={"allowed": ["_audit", "winevents"], "disallowed": ["secret*"],
                               "filter": "host=a"}, imported={"allowed": ["_internal"], "default": ["winevents"]}),
        }
        return FakeRoles(users, roles, **kw)

    def test_own_and_imported_values_are_combined_across_roles(self):
        p = read_principal(self.transport(), "ucm_scheduler")
        self.assertEqual(p.status, PRINCIPAL_OK)
        self.assertEqual(p.roles, ["ucm_scheduler", "extra"])
        self.assertEqual(sorted(p.allowed), ["*", "_audit", "_internal", "winevents"])
        self.assertEqual(p.disallowed, ["secret*"])
        self.assertEqual(sorted(p.default), ["main", "winevents"])
        self.assertEqual(p.filters, ["host=a"])
        self.assertTrue(p.internal_access)

    def test_disallowed_in_one_role_applies_to_the_allowed_of_another(self):
        t = FakeRoles({"u": {"roles": ["a", "b"]}},
                      {"a": role(own={"allowed": ["*", "_*"]}), "b": role(own={"disallowed": ["_internal"]})})
        p = read_principal(t, "u")
        self.assertFalse(p.internal_access)
        self.assertTrue(p.covers("_audit")[0])
        self.assertTrue(p.covers("main")[0])

    def test_string_values_are_split(self):
        t = FakeRoles({"u": {"roles": "a"}}, {"a": role(own={"allowed": "main;_audit"})})
        self.assertEqual(read_principal(t, "u").allowed, ["main", "_audit"])

    def test_user_without_roles_sees_nothing(self):
        p = read_principal(FakeRoles({"u": {"roles": []}}), "u")
        self.assertEqual(p.status, PRINCIPAL_OK)
        self.assertEqual(check_access(p, scan_spl("index=main"), KNOWN)["status"], NOT_MET)

    def test_no_owner(self):
        p = read_principal(self.transport(), "")
        self.assertEqual(p.status, PRINCIPAL_NO_OWNER)
        out = check_access(p, scan_spl("index=main"), KNOWN)
        self.assertEqual((out["status"], out["code"]), (UNVERIFIED, "no_scheduled_owner"))

    def test_unknown_user(self):
        p = read_principal(self.transport(), "nobody_here")
        self.assertEqual(p.status, PRINCIPAL_NOT_FOUND)
        self.assertEqual(check_access(p, scan_spl("index=main"), KNOWN)["code"], "owner_not_found")

    def test_forbidden_user_read_is_unverified(self):
        t = self.transport(fail={"/services/authentication/users/ucm_scheduler": 403})
        p = read_principal(t, "ucm_scheduler")
        self.assertEqual(p.status, PRINCIPAL_UNREADABLE)
        out = check_access(p, scan_spl("index=_internal"), KNOWN)
        self.assertEqual((out["status"], out["code"]), (UNVERIFIED, "roles_unreadable"))
        self.assertIn("does not block deployment", out["detail"])

    def test_forbidden_role_read_is_unverified_even_if_other_roles_are_readable(self):
        t = self.transport(fail={"/services/authorization/roles/extra": 403})
        p = read_principal(t, "ucm_scheduler")
        self.assertEqual(p.status, PRINCIPAL_UNREADABLE)
        self.assertEqual(p.unreadable_roles, ["extra"])
        self.assertEqual(check_access(p, scan_spl("index=_internal"), KNOWN)["status"], UNVERIFIED)

    def test_transport_exception_is_a_status_not_an_error(self):
        t = self.transport(fail={"/services/authentication/users/ucm_scheduler": StorageError("down")})
        self.assertEqual(read_principal(t, "ucm_scheduler").status, PRINCIPAL_UNREADABLE)
        self.assertEqual(read_principal(None, "ucm_scheduler").status, PRINCIPAL_UNREADABLE)

    def test_summary_has_no_index_lists(self):
        summary = read_principal(self.transport(), "ucm_scheduler").summary()
        self.assertTrue(summary["internal_access"])
        self.assertTrue(summary["has_filter"])
        self.assertTrue(summary["all_indexes_access"])
        self.assertNotIn("allowed", summary)
        self.assertNotIn("disallowed", summary)
        self.assertEqual(summary["roles"], ["ucm_scheduler", "extra"])

    def test_no_principal_is_unverified(self):
        self.assertEqual(check_access(None, scan_spl("index=main"), KNOWN)["code"], "principal_not_read")

    def test_roundtrip(self):
        p = read_principal(self.transport(), "ucm_scheduler")
        self.assertEqual(PrincipalAccess.from_dict(p.to_dict()).fingerprint(), p.fingerprint())


class ReadinessIntegrationTest(unittest.TestCase):
    INTERNAL_INDEX_SOURCES = [{"kind": "index", "name": "_internal", "status": "active", "is_internal": True,
                               "window_count": 0},
                              {"kind": "index", "name": "main", "status": "active", "window_count": 5}]

    def test_engine_version_was_bumped(self):
        self.assertEqual(ENGINE_VERSION, "ucm.readiness/5")

    def test_permission_evaluator_uses_snapshot_principal(self):
        s = snap(self.INTERNAL_INDEX_SOURCES)
        s.principal = principal()
        req = {"req_id": "p", "type": "permission", "value": "x", "level": "required",
               "attributes": {"scan": scan_spl("index=_internal | stats count")}}
        out = evaluate(req, s, EvaluationSettings())
        self.assertEqual((out["status"], out["code"]), (NOT_MET, "index_not_accessible"))
        s.principal = principal(allowed=["*", "_*"])
        self.assertEqual(evaluate(req, s, EvaluationSettings())["status"], MET)
        s.principal = None
        self.assertEqual(evaluate(req, s, EvaluationSettings())["status"], UNVERIFIED)

    def assess(self, p, spl="index=_internal sourcetype=scheduler | stats count"):
        from splunk_ucm.readiness.service import assess_use_case
        store = discovered_store()
        s = EnvironmentSnapshot.load(store)
        s.principal = p
        uc = _use_case(spl)
        return assess_use_case(uc, s, ReadinessSettings(scheduled_owner="ucm_scheduler"))

    def test_assessment_adds_a_permission_requirement_that_gaps_the_score(self):
        doc = self.assess(principal())
        row = [r for r in doc["results"] if r["type"] == "permission"][0]
        self.assertEqual(row["status"], NOT_MET)
        self.assertEqual(row["value"], "runs as ucm_scheduler: index access")
        self.assertEqual(row["level"], "required")
        self.assertIn("permission", [g["type"] for g in doc["gaps"]])
        self.assertEqual(doc["engine_version"], ENGINE_VERSION)

    def test_assessment_met_after_grant_and_unverified_without_owner(self):
        doc = self.assess(principal(allowed=["*", "_*"]))
        self.assertEqual([r["status"] for r in doc["results"] if r["type"] == "permission"], [MET])
        doc = self.assess(PrincipalAccess("", PRINCIPAL_NO_OWNER, "x"))
        row = [r for r in doc["results"] if r["type"] == "permission"][0]
        self.assertEqual(row["status"], UNVERIFIED)
        self.assertNotIn("permission", [g["type"] for g in doc["gaps"]])

    def test_use_case_without_spl_has_no_permission_requirement(self):
        doc = self.assess(principal(), spl="")
        self.assertEqual([r for r in doc["results"] if r["type"] == "permission"], [])

    def test_service_reads_the_principal_once_per_job(self):
        store = discovered_store()
        calls = []

        def reader(owner):
            calls.append(owner)
            return principal(allowed=["*", "_*"])
        svc = ReadinessService(store, AuditService(store), ReadinessSettings(scheduled_owner="ucm_scheduler"),
                               principal_reader=reader)
        from splunk_ucm.readiness.service import new_job
        job = svc.enqueue(new_job("alice"))
        svc.run(job)
        self.assertEqual(calls, ["ucm_scheduler"])
        saved = store.get(C.SYNC_STATE, "rjob::" + job["job_id"])
        self.assertEqual(saved["principal"]["status"], PRINCIPAL_OK)
        permission = [r for d in store.query(C.READINESS, None) for r in d["results"] if r["type"] == "permission"]
        self.assertTrue(permission)
        self.assertTrue(all(r["status"] in (MET, NOT_APPLICABLE, UNVERIFIED) for r in permission))

    def test_reader_failure_is_unverified_not_a_failed_job(self):
        store = discovered_store()

        def reader(owner):
            raise RuntimeError("boom")
        svc = ReadinessService(store, AuditService(store), ReadinessSettings(scheduled_owner="u"),
                               principal_reader=reader)
        from splunk_ucm.readiness.service import new_job
        job = svc.run(svc.enqueue(new_job("alice")))
        self.assertEqual(job["status"], "succeeded")
        statuses = {r["status"] for d in store.query(C.READINESS, None) for r in d["results"]
                    if r["type"] == "permission"}
        self.assertEqual(statuses - {NOT_APPLICABLE}, {UNVERIFIED})

    def test_validation_scan_with_expanded_macros_is_preferred(self):
        stored = {"_key": "fenre_UC-X", "content_id": "fenre:UC-X", "source_hash": "h1", "parse_ok": True,
                  "access_scan": scan_spl("`m`", "| search index=_audit x")}
        s = EnvironmentSnapshot([], [], {"last_completed_at": "t"}, [stored])
        s.principal = principal()
        uc = _use_case("`m` x", content_id="fenre:UC-X", key="fenre_UC-X", source_hash="h1")
        from splunk_ucm.readiness.service import _requirements
        scan = [r for r in _requirements(uc, s) if r.type == "permission"][0].attributes["scan"]
        self.assertEqual(scan["indexes"], ["_audit"])
        uc = _use_case("`m` x", content_id="fenre:UC-X", key="fenre_UC-X", source_hash="changed")
        scan = [r for r in _requirements(uc, s) if r.type == "permission"][0].attributes["scan"]
        self.assertEqual(scan["unverified"], ["macro_not_expanded"])


def _use_case(spl, content_id="fenre:UC-T", key="fenre_UC-T", source_hash="x"):
    from splunk_ucm.model.canonical import Provenance, UseCase
    prov = Provenance("fenre", "UC-T", "1", "main", "", "", source_hash, "", "", "", "t")
    return UseCase(content_id, key, "t", prov, domains=["security"], category_key="c", category_name="C",
                   criticality="high", spl=spl)


class IncludeInternalTest(unittest.TestCase):
    def index_req(self, name):
        return {"req_id": "i", "type": "index", "value": name, "level": "required"}

    def test_internal_index_is_unverified_when_discovery_skipped_internal(self):
        s = snap([{"kind": "index", "name": "_internal", "status": "active", "is_internal": True,
                   "window_count": 0}], state={"last_completed_at": "t", "include_internal": False})
        out = evaluate(self.index_req("_internal"), s, EvaluationSettings())
        self.assertEqual((out["status"], out["code"]), (UNVERIFIED, "internal_not_scanned"))
        self.assertIn("include_internal = false", out["detail"])

    def test_missing_internal_name_is_also_unverified_not_undefined(self):
        s = snap([], state={"last_completed_at": "t", "include_internal": False})
        out = evaluate(self.index_req("_audit"), s, EvaluationSettings())
        self.assertEqual(out["code"], "internal_not_scanned")
        self.assertEqual(evaluate(self.index_req("nope"), s, EvaluationSettings())["code"], "not_found")

    def test_internal_index_is_evaluated_normally_when_scanned(self):
        s = snap([{"kind": "index", "name": "_internal", "status": "active", "is_internal": True,
                   "window_count": 10}], state={"last_completed_at": "t", "include_internal": True})
        self.assertEqual(evaluate(self.index_req("_internal"), s, EvaluationSettings())["status"], MET)

    def test_sourcetype_not_found_mentions_unscanned_internal_indexes(self):
        s = snap([], state={"last_completed_at": "t", "include_internal": False})
        out = evaluate({"req_id": "s", "type": "sourcetype", "value": "scheduler", "level": "required"},
                       s, EvaluationSettings())
        self.assertIn("Internal indexes were not scanned", out["detail"])
        s = snap([], state={"last_completed_at": "t", "include_internal": True})
        out = evaluate({"req_id": "s", "type": "sourcetype", "value": "scheduler", "level": "required"},
                       s, EvaluationSettings())
        self.assertNotIn("Internal indexes", out["detail"])


class DeploymentGateTest(unittest.TestCase):
    CUSTOM = {"spl_source": "custom", "custom_spl": "index=_internal sourcetype=scheduler | stats count by status",
              "cron": "*/5 * * * *"}

    def build(self, p_roles, fail=None):
        store = loaded_catalog()
        store.upsert(C.ENVIRONMENT_SOURCES, {"_key": "idx1", "kind": "index", "name": "_internal",
                                              "status": "active"})
        transport = FakeRoles({"ucm_scheduler": {"roles": ["r"]}}, {"r": p_roles}, fail=fail)
        access = SchedulerAccess(store, transport, "ucm_scheduler")
        svc = DeploymentService(store, AuditService(store), FakeParser(), FakeSavedSearches(),
                                DeploymentSettings(), access=access)
        return svc, store

    def deployed(self, svc, spec=None):
        svc.save_draft("alice", UC, dict(spec or self.CUSTOM))
        svc.submit("alice", UC)
        svc.approve("bob", UC)
        svc.deploy("bob", UC)

    def test_submit_warns_but_does_not_block(self):
        svc, store = self.build(role(imported={"allowed": ["*"]}))
        svc.save_draft("alice", UC, dict(self.CUSTOM))
        doc = svc.submit("alice", UC)
        rev = doc["revisions"][-1]
        self.assertEqual(doc["state"], "pending_approval")
        self.assertEqual(rev["scheduler_access"]["status"], NOT_MET)
        self.assertIn("ucm_scheduler cannot search _internal", rev["scheduler_access"]["detail"])
        event = AuditService(store).recent(5, "deployment.submit")[0]
        self.assertEqual(event["details"]["scheduler_access"], NOT_MET)

    def test_enable_is_gated_and_the_existing_override_is_audited(self):
        svc, store = self.build(role(imported={"allowed": ["*"]}))
        self.deployed(svc)
        with self.assertRaises(ConflictError) as ctx:
            svc.enable("bob", UC)
        self.assertEqual(ctx.exception.details["code"], "scheduler_access_gate")
        self.assertIn("ucm_scheduler cannot search _internal", ctx.exception.message)
        with self.assertRaises(ConflictError):
            svc.enable("bob", UC, "short")
        doc = svc.enable("bob", UC, "Accepted: the role is being changed this week")
        self.assertEqual(doc["live"]["status"], "enabled")
        event = AuditService(store).recent(5, "deployment.enable")[0]
        self.assertEqual(event["details"]["override_reason"], "Accepted: the role is being changed this week")
        self.assertEqual(event["details"]["scheduler_access"], NOT_MET)
        self.assertEqual(doc["history"][-1]["note"], "Accepted: the role is being changed this week")

    def test_enable_passes_without_override_when_the_role_covers_the_index(self):
        svc, store = self.build(role(imported={"allowed": ["*", "_*"]}))
        self.deployed(svc)
        self.assertEqual(svc.enable("bob", UC)["live"]["status"], "enabled")
        self.assertEqual(AuditService(store).recent(5, "deployment.enable")[0]["details"]["override_reason"], "")

    def test_role_read_failure_does_not_block(self):
        svc, _ = self.build(role(), fail={"/services/authorization/roles/r": 403})
        self.deployed(svc)
        self.assertEqual(svc.scheduler_access_for(svc.get(UC))["status"], UNVERIFIED)
        self.assertEqual(svc.enable("bob", UC)["live"]["status"], "enabled")

    def test_no_access_checker_does_not_block(self):
        store = loaded_catalog()
        svc = DeploymentService(store, AuditService(store), FakeParser(), FakeSavedSearches(), DeploymentSettings())
        self.deployed(svc)
        self.assertEqual(svc.enable("bob", UC)["live"]["status"], "enabled")

    def test_readiness_and_access_gates_share_one_override_reason(self):
        svc, store = self.build(role(imported={"allowed": ["*"]}))
        self.deployed(svc)
        store.upsert(C.READINESS, {"_key": "fenre_UC-9.1.1", "content_id": UC, "state": "blocked"})
        with self.assertRaises(ConflictError) as ctx:
            svc.enable("bob", UC)
        self.assertEqual(ctx.exception.details["code"], "readiness_gate")
        self.assertIn("readiness is blocked", ctx.exception.message)
        self.assertIn("cannot search _internal", ctx.exception.message)
        self.assertEqual(svc.enable("bob", UC, "Accepted: both reviewed")["live"]["status"], "enabled")

    def test_view_helper_uses_deployed_revision_and_live_roles(self):
        svc, _ = self.build(role(imported={"allowed": ["*"]}))
        self.assertIsNone(svc.scheduler_access_for(None))
        self.deployed(svc)
        out = svc.scheduler_access_for(svc.get(UC))
        self.assertEqual((out["status"], out["revision"]), (NOT_MET, 1))

    def test_revision_without_stored_scan_is_scanned_on_the_fly(self):
        svc, _ = self.build(role(imported={"allowed": ["*"]}))
        self.deployed(svc)
        doc = svc.store.get(C.DEPLOYMENTS, svc.get(UC)["_key"])
        doc["revisions"][-1].pop("access_scan")
        svc.store.upsert(C.DEPLOYMENTS, doc)
        self.assertEqual(svc.scheduler_access_for(svc.get(UC))["status"], NOT_MET)


class ApiTest(unittest.TestCase):
    def ctx(self, roles, fail=None, owner="ucm_scheduler"):
        from splunk_ucm.api.app import Context
        from splunk_ucm.config import AppConfig
        from unit.test_api_worker import NoSplunkd
        store = discovered_store()
        transport = FakeRoles({"ucm_scheduler": {"roles": ["r"]}}, {"r": roles}, fail=fail)
        ctx = Context(NoSplunkd(), transport, "alice", store=store, audit_store=store, record_store=store,
                      config=AppConfig({"deployment": {"scheduled_owner": owner}} if owner else {}))
        ctx._caps = ["ucm_deploy", "ucm_run_discovery"]
        return ctx, store

    def test_readiness_summary_carries_the_scheduler_card(self):
        from unit.test_api_worker import call
        ctx, _ = self.ctx(role(imported={"allowed": ["*"], "default": ["main"]}, own={"filter": "host=a"}))
        status, body = call(ctx, "GET", "readiness/summary")
        self.assertEqual(status, 200)
        card = body["scheduler"]
        self.assertEqual((card["owner"], card["status"], card["roles"]), ("ucm_scheduler", "ok", ["r"]))
        self.assertIs(card["internal_access"], False)
        self.assertTrue(card["has_filter"])
        self.assertIn("discovery_include_internal", card)
        self.assertNotIn("allowed", card)

    def test_summary_card_for_missing_owner_and_unreadable_roles(self):
        from unit.test_api_worker import call
        ctx, _ = self.ctx(role(), owner="")
        card = call(ctx, "GET", "readiness/summary")[1]["scheduler"]
        self.assertEqual((card["status"], card["internal_access"]), ("no_owner", None))
        ctx, _ = self.ctx(role(), fail={"/services/authentication/users/ucm_scheduler": 403})
        card = call(ctx, "GET", "readiness/summary")[1]["scheduler"]
        self.assertEqual(card["status"], "unreadable")

    def test_deployment_view_reports_scheduler_access(self):
        from unit.test_api_worker import call
        ctx, store = self.ctx(role(imported={"allowed": ["*"]}))
        svc = ctx.deployment_service()
        svc.search = FakeParser()
        svc.save_draft("alice", UC, dict(DeploymentGateTest.CUSTOM))
        body = call(ctx, "GET", "deployment", {"id": UC})[1]
        self.assertEqual(body["scheduler_access"]["status"], NOT_MET)
        self.assertEqual(call(ctx, "GET", "usecase", {"id": UC})[1]["deployment"]["scheduler_access"]["status"],
                         NOT_MET)

    def test_deployment_view_without_deployment_has_no_access_block(self):
        from unit.test_api_worker import call
        ctx, _ = self.ctx(role())
        self.assertIsNone(call(ctx, "GET", "deployment", {"id": UC})[1]["scheduler_access"])

    def test_validation_stores_the_scan_and_readiness_prefers_it(self):
        from splunk_ucm.validation.service import ValidationService
        store = discovered_store()
        parser = FakeParser()
        doc = ValidationService(store, AuditService(store), parser).parse_only(UC, "alice")
        self.assertIn("access_scan", doc)
        self.assertIsInstance(doc["access_scan"]["indexes"], list)
        self.assertIn("access_scan", store.get(C.VALIDATION, "fenre_UC-9.1.1"))


if __name__ == "__main__":
    unittest.main()
