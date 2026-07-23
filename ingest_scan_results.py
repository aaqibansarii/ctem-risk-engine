"""
CLI utility for loading raw scan results from a JSON file, extracting CVE
findings, scoring them, and storing them in Supabase.

Usage:
    python ingest_scan_results.py --input sample_data/sample_raw_findings.json
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path

from app.risk_engine import score_finding
from app.risk_store import save_risk_score
from app.scan_ingestion import score_requests_from_scan_payload


def main() -> None:
    parser = argparse.ArgumentParser(description="Extract and score raw scan results into Supabase.")
    parser.add_argument("--input", required=True, help="Path to the raw JSON scan results file.")
    parser.add_argument("--default-tool", default=None, help="Default scanner/tool name if the payload omits it.")
    parser.add_argument("--output", default=None, help="Optional path to write the scored JSON results.")
    args = parser.parse_args()

    input_path = Path(args.input)
    payload = json.loads(input_path.read_text())
    batch = score_requests_from_scan_payload(payload, default_tool=args.default_tool)

    results = []
    for item in batch.items:
        result = score_finding(asset=item.asset, cve=item.cve, tool=item.tool)
        save_risk_score(result)
        results.append(result.model_dump(mode="json"))

    if args.output:
        Path(args.output).write_text(json.dumps(results, indent=2))
    else:
        print(json.dumps(results, indent=2))


if __name__ == "__main__":
    main()
