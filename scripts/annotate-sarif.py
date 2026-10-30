"""Write each result of a SARIF report as a GitHub Actions annotation.

The semgrep job uploads its SARIF to the repository's Security tab and fails on
any WARNING or ERROR result, but neither the job log nor the Security tab is
readable without signing in. Annotations show on the run's summary page for
anyone. Run after the scan step failed; prints one `::error` line per result
and exits 0, since the scan step has already failed the job.

    python3 scripts/annotate-sarif.py semgrep.sarif
"""
import json
import sys


def escape_data(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def escape_property(text: str) -> str:
    return escape_data(text).replace(":", "%3A").replace(",", "%2C")


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <report.sarif>", file=sys.stderr)
        return 2
    try:
        with open(sys.argv[1], encoding="utf-8") as f:
            sarif = json.load(f)
    except (OSError, ValueError) as e:
        print(f"::error title=No SARIF report::{escape_data(f'{sys.argv[1]}: {e}')}")
        return 0
    count = 0
    for run in sarif.get("runs", []):
        for result in run.get("results", []):
            rule = result.get("ruleId", "?")
            message = (result.get("message", {}).get("text") or "").strip().splitlines()
            props = [f"title={escape_property(rule)}"]
            locations = result.get("locations") or []
            if locations:
                physical = locations[0].get("physicalLocation", {})
                uri = physical.get("artifactLocation", {}).get("uri")
                line = physical.get("region", {}).get("startLine")
                if uri:
                    props.insert(0, f"file={escape_property(uri)}")
                    if line:
                        props.insert(1, f"line={line}")
            first = message[0][:400] if message else "(no message)"
            print(f"::error {','.join(props)}::{escape_data(first)}")
            count += 1
    print(f"{count} result(s) named")
    return 0


if __name__ == "__main__":
    sys.exit(main())
