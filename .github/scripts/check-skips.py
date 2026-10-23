#!/usr/bin/env python3
"""Fail a CI job when tests were skipped for any reason other than an explicitly allowed one.

A skipped test is not a passed test. On Linux the only legitimate skips are the Windows-only
tests, which carry a fixed reason string; anything else (or any skip at all on Windows) fails.
"""
import argparse
import re
import sys
import xml.etree.ElementTree as ET

NS = {"t": "http://microsoft.com/schemas/VisualStudio/TeamTest/2010"}


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("trx")
    ap.add_argument("--allow", action="append", default=[],
                    help="substring that a skip reason may contain (repeatable)")
    ap.add_argument("--max-skipped", type=int, default=None,
                    help="fail if more than this many tests were skipped")
    args = ap.parse_args()

    root = ET.parse(args.trx).getroot()
    outcomes = {"Passed": 0, "Failed": 0, "NotExecuted": 0, "Other": 0}
    unexplained = []
    skipped = []

    for r in root.iterfind(".//t:UnitTestResult", NS):
        outcome = r.get("outcome", "Other")
        outcomes[outcome if outcome in outcomes else "Other"] += 1
        if outcome == "NotExecuted":
            msg = r.findtext(".//t:ErrorInfo/t:Message", default="", namespaces=NS).strip()
            skipped.append((r.get("testName"), msg))
            if not any(a in msg for a in args.allow):
                unexplained.append((r.get("testName"), msg or "<no reason recorded>"))

    total = sum(outcomes.values())
    print(f"{total} tests: {outcomes['Passed']} passed, {outcomes['Failed']} failed, "
          f"{outcomes['NotExecuted']} skipped, {outcomes['Other']} other")
    for name, msg in skipped:
        print(f"  skipped: {name}\n           {msg}")

    problems = []
    if total == 0:
        problems.append("no test results found")
    if outcomes["Failed"] or outcomes["Other"]:
        problems.append("there are failed or inconclusive tests")
    if unexplained:
        problems.append(f"{len(unexplained)} test(s) skipped for a reason that is not allowed")
    if args.max_skipped is not None and outcomes["NotExecuted"] > args.max_skipped:
        problems.append(f"{outcomes['NotExecuted']} skipped, at most {args.max_skipped} allowed")

    for p in problems:
        print(f"FAIL: {p}", file=sys.stderr)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
