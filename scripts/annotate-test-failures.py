"""Write each failing test of a JUnit XML report as a GitHub Actions annotation.

A job's log is readable only by a signed-in viewer, while annotations show on
the run's summary page for anyone. Run after a test step that failed, with the
directory that holds the XML reports; it prints one `::error` line per failing
or erroring test case and exits 0, since the test step has already failed the
job.

    python3 scripts/annotate-test-failures.py mobile/build/outputs/androidTest-results/connected

The reports are read with html.parser rather than an XML library: it resolves
no external entity and expands no entity definition, so it needs no defused
parser, and the reports are flat enough for it (testcase elements, each with
its failure or error children and their message attribute).
"""
import pathlib
import sys
from html.parser import HTMLParser


def escape_data(text: str) -> str:
    return text.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def escape_property(text: str) -> str:
    return escape_data(text).replace(":", "%3A").replace(",", "%2C")


class _Report(HTMLParser):
    """Collects (test, first line of the message) for each failure or error."""

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.case = None
        self.problem = None  # [test, text] while inside a failure or error
        self.found = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "testcase":
            self.case = f"{a.get('classname')}.{a.get('name')}"
        elif tag in ("failure", "error") and self.case is not None:
            self.problem = [self.case, a.get("message") or ""]

    def handle_startendtag(self, tag, attrs):
        self.handle_starttag(tag, attrs)
        if tag in ("failure", "error"):
            self.handle_endtag(tag)

    def handle_data(self, data):
        if self.problem is not None and not self.problem[1].strip():
            self.problem[1] += data

    def handle_endtag(self, tag):
        if tag in ("failure", "error") and self.problem is not None:
            test, text = self.problem
            lines = text.strip().splitlines()
            self.found.append((test, lines[0][:400] if lines else "(no message)"))
            self.problem = None
        elif tag == "testcase":
            self.case = None


def failures(root: pathlib.Path):
    for report in sorted(root.rglob("*.xml")):
        parser = _Report()
        try:
            parser.feed(report.read_text(encoding="utf-8", errors="replace"))
            parser.close()
        except Exception as e:  # a report this script cannot read is itself worth naming
            yield (str(report), f"the report could not be read: {type(e).__name__}")
            continue
        yield from parser.found


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
