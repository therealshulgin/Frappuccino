"""Write each failing test of a JUnit XML report as a GitHub Actions annotation.

A job's log is readable only by a signed-in viewer, while annotations show on
the run's summary page for anyone. Run after a test step that failed, with the
directory that holds the XML reports; it prints one `::error` line per failing
or erroring test case and exits 0, since the test step has already failed the
job.

    python3 scripts/annotate-test-failures.py mobile/build/outputs/androidTest-results/connected
"""
import pathlib
import sys
import xml.etree.ElementTree as ET


def escape_data(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def escape_property(text: str) -> str:
    return escape_data(text).replace(":", "%3A").replace(",", "%2C")


def failures(root: pathlib.Path):
    for report in sorted(root.rglob("*.xml")):
        try:
            tree = ET.parse(report)
        except ET.ParseError:
            yield (str(report), "the report is not valid XML")
            continue
        for case in tree.getroot().iter("testcase"):
            for problem in list(case.findall("failure")) + list(case.findall("error")):
                detail = (problem.get("message") or problem.text or "").strip()
                first = detail.splitlines()[0] if detail else "(no message)"
                yield (f"{case.get('classname')}.{case.get('name')}", first[:400])


def main() -> int:
    if len(sys.argv) != 2:
        print(f"usage: {sys.argv[0]} <reports directory>", file=sys.stderr)
        return 2
    root = pathlib.Path(sys.argv[1])
    if not root.is_dir():
        print(f"::error title=No test reports::{escape_data(str(root))} does not exist: the tests did not run")
        return 0
    count = 0
    for title, message in failures(root):
        print(f"::error title={escape_property(title)}::{escape_data(message)}")
        count += 1
    print(f"{count} failing test(s) named")
    return 0


if __name__ == "__main__":
    sys.exit(main())
