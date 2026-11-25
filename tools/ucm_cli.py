#!/usr/bin/env python3
"""Operator CLI for SUNavigator content tasks performed outside Splunk.

  build-bundle  Build an offline content bundle from a local Fenre-layout checkout.
  build-escu-bundle  Build an offline bundle from an ESCU package (directory or .tar.gz).
  build-control-fixtures  Build the control-test fixture bundle from a Fenre samples/ tree (D-054).
  validate      Validate every record of a local checkout without importing it.
  manifest      Resolve the remote provider manifest (network; no Splunk needed).

A GitHub token, when needed, is read from the UCM_GITHUB_TOKEN environment
variable and is never accepted on the command line.
"""

import argparse
import json
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "..",
                                "sunavigator", "lib"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from splunk_ucm.config import DEFAULTS  # noqa: E402
from splunk_ucm.content.escu.package import build_bundle as build_escu_bundle  # noqa: E402
from splunk_ucm.deployment.controltest import build_fixture_bundle  # noqa: E402
from splunk_ucm.content.registry import bundle_provider, remote_provider  # noqa: E402
from splunk_ucm.errors import UcmError  # noqa: E402
from ucm_bundle_builder import build_bundle_from_directory  # noqa: E402


def _csv(value):
    return [v.strip() for v in value.split(",") if v.strip()] if value else None


def cmd_build_bundle(args) -> int:
    bundle = build_bundle_from_directory(args.repo, _csv(args.categories), record_ids=_csv(args.records))
    data = json.dumps(bundle, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    with open(args.output, "wb") as handle:
        handle.write(data)
    print(json.dumps({"output": args.output, "bytes": len(data), "categories": len(bundle["categories"]),
                      "records": len(bundle["records"]), "provider_version": bundle["provider_version"],
                      "source_ref": bundle["source_ref"]}, indent=2))
    return 0


def cmd_build_escu_bundle(args) -> int:
    enricher, extra, extra_report = None, "", None
    if args.security_content:
        import security_content
        enricher, extra_report = security_content.load(args.security_content)
        extra = "security_content:" + (extra_report["commit"] or "unpinned")
    bundle, report = build_escu_bundle(args.package, enricher, extra)
    if extra_report is not None:
        report["security_content"] = extra_report
    data = json.dumps(bundle, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    with open(args.output, "wb") as handle:
        handle.write(data)
    print(json.dumps(dict(report, output=args.output, bytes=len(data)), indent=2))
    return 0


def cmd_build_control_fixtures(args) -> int:
    bundle, report = build_fixture_bundle(args.samples, args.provider)
    data = json.dumps(bundle, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
    with open(args.output, "wb") as handle:
        handle.write(data)
    print(json.dumps(dict(report, output=args.output, bytes=len(data)), indent=2))
    return 0


def cmd_validate(args) -> int:
    bundle = build_bundle_from_directory(args.repo, _csv(args.categories))
    provider = bundle_provider(bundle)
    manifest = provider.get_manifest()
    validator = provider.validator(manifest)
    invalid, warnings, total = [], 0, 0
    for pcat in manifest.categories:
        for listing in provider.list_records(manifest, pcat):
            record = provider.fetch_record(manifest, pcat, listing)
            result = validator.validate(record.raw, record.raw_size or None)
            total += 1
            warnings += len(result.warnings)
            if not result.ok:
                invalid.append({"record_id": record.record_id,
                                "errors": [f.message for f in result.errors[:3]]})
    print(json.dumps({"records": total, "invalid": len(invalid), "warnings": warnings,
                      "invalid_records": invalid[:50]}, indent=2))
    return 1 if invalid else 0


def cmd_manifest(args) -> int:
    settings = dict(DEFAULTS.get("provider:fenre", {}))
    provider = remote_provider("fenre", settings, os.environ.get("UCM_GITHUB_TOKEN", ""), args.ref or "")
    manifest = provider.get_manifest()
    summary = manifest.summary()
    if not args.full:
        summary["categories"] = [{"category_id": c["category_id"], "name": c["name"],
                                  "upstream_count": c["upstream_count"]} for c in summary["categories"]]
    print(json.dumps(summary, indent=2))
    return 0


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(prog="ucm_cli")
    sub = parser.add_subparsers(dest="command", required=True)
    p = sub.add_parser("build-bundle", help="build an offline content bundle")
    p.add_argument("--repo", required=True, help="path to a local Fenre-layout checkout")
    p.add_argument("--categories", help="comma-separated category ids (default: all)")
    p.add_argument("--records", help="comma-separated record ids, e.g. 10.1.1,10.1.2")
    p.add_argument("--output", required=True)
    p.set_defaults(func=cmd_build_bundle)
    p = sub.add_parser("build-escu-bundle", help="build an offline bundle from an ESCU package")
    p.add_argument("--package", required=True, help="extracted DA-ESS-ContentUpdate directory or .tar.gz")
    p.add_argument("--security-content", help="pinned checkout of github.com/splunk/security_content; adds data "
                   "sources, supported add-ons, drilldowns, risk entities, test references, macro definitions and status")
    p.add_argument("--output", required=True)
    p.set_defaults(func=cmd_build_escu_bundle)
    p = sub.add_parser("build-control-fixtures", help="build control-test fixtures from a Fenre samples/ tree")
    p.add_argument("--samples", required=True, help="path to the samples/ directory")
    p.add_argument("--provider", default="fenre", help="provider id the fixtures belong to (default fenre)")
    p.add_argument("--output", required=True)
    p.set_defaults(func=cmd_build_control_fixtures)
    p = sub.add_parser("validate", help="validate a local checkout")
    p.add_argument("--repo", required=True)
    p.add_argument("--categories")
    p.set_defaults(func=cmd_validate)
    p = sub.add_parser("manifest", help="resolve the remote manifest")
    p.add_argument("--ref", help="branch, tag or commit (default: configured ref)")
    p.add_argument("--full", action="store_true")
    p.set_defaults(func=cmd_manifest)
    args = parser.parse_args(argv)
    try:
        return args.func(args)
    except UcmError as exc:
        print(json.dumps({"error": exc.to_dict()}, indent=2), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
