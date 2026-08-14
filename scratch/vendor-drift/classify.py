#    Copyright Frank V. Castellucci
#    SPDX-License-Identifier: Apache-2.0

# -*- coding: utf-8 -*-

"""Classify upstream walrus-core items against the pysui-fastcrypto port manifest.

Companion to ``rust_ranges.py``. That script extracts every item and its line
range from the upstream sources; this one decides, for each extracted item,
whether the port manifest accounts for it.

Three classes of finding are reported:

``UNCLASSIFIED``
    The item exists upstream but appears in neither a port table nor an
    exclusion list. Newly added upstream items land here by definition, which
    is what makes the completeness step of ``/vendor-drift-check`` useful.

``PHANTOM``
    A line range cited by the manifest that begins at no upstream item. Almost
    always a stale number left behind when upstream shifted.

``SWALLOWED``
    A ported item whose exact span lies inside an exclusion range, so the
    manifest both claims and disclaims the same code.

Run with no arguments from ``scratch/vendor-drift/``. Exit status is 1 when
anything needs triage, 0 when the manifest fully accounts for upstream.

``--emit-exclusions FILE`` prints a ready-to-paste manifest exclusion bullet
for one file, built from that file's unclassified items. Generating the text
mechanically avoids the transcription errors that hand-written line citations
accumulate.
"""

import argparse
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

HERE = Path(__file__).resolve().parent
DEFAULT_MANIFEST = HERE / "walrus-port-manifest.md"
DEFAULT_GROUND_TRUTH = HERE / "ground_truth-14641cc0.txt"

SRC_MARKER = "walrus-core/src/"

#: Manifest heading name -> ground-truth relative path. The upstream crate root
#: was vendored as ``core.rs`` rather than ``lib.rs``.
ALIASES = {"core.rs": "lib.rs"}

CONTAINER_KINDS = frozenset({"impl", "trait", "mod"})
TEST_MOD_NAMES = frozenset({"tests", "test"})
WHOLE_FILE_KEY = "whole files"
WHOLE_FILE_END = 10**9

TABLE_ROW_RE = re.compile(r"^\|\s*(.+?)\s*\|\s*(\d[0-9\-]*)\s*\|")
BULLET_RE = re.compile(r"^-\s+\*\*(.+?):\*\*\s*(.*)$")
NOT_NEEDED_RE = re.compile(r"^\s*(?:-\s*)?NOT needed:\s*(.*)$", re.IGNORECASE)
BACKTICK_RE = re.compile(r"`[^`]*`")
SPAN_RE = re.compile(r"(\d+)\s*-\s*(\d+)")
NUM_RE = re.compile(r"\d+")
GT_SPAN_RE = re.compile(r"(\d+)(?:-(\d+))?$")


@dataclass(frozen=True)
class Item:
    """A single upstream item extracted by ``rust_ranges.py``."""

    kind: str
    name: str
    start: int
    end: int

    def inside(self, *, start: int, end: int) -> bool:
        """Return True when this item lies wholly within the given span."""
        return start <= self.start and self.end <= end

    def label(self) -> str:
        """Return a human-readable ``name (start-end)`` label."""
        return f"{self.name} ({self.start}-{self.end})"


@dataclass
class Coverage:
    """Manifest-declared spans for one source file."""

    ported: list = field(default_factory=list)
    excluded: list = field(default_factory=list)

    def all_spans(self) -> list:
        """Return every span the manifest cites for this file."""
        return self.ported + self.excluded


def parse_ground_truth(*, path: Path) -> dict:
    """Parse the pinned ground-truth listing into ``relpath -> [Item]``."""
    files: dict = {}
    current: list | None = None
    for raw in path.read_text(encoding="utf-8").splitlines():
        if raw.startswith("==="):
            full = raw[3:].strip()
            marker = full.find(SRC_MARKER)
            rel = full[marker + len(SRC_MARKER):] if marker >= 0 else full
            current = []
            files[rel] = current
            continue
        if current is None or not raw.strip():
            continue
        parts = raw.split()
        if len(parts) < 3:
            continue
        span = GT_SPAN_RE.fullmatch(parts[-1])
        if span is None:
            continue
        start = int(span.group(1))
        end = int(span.group(2)) if span.group(2) else start
        current.append(
            Item(kind=parts[0], name=" ".join(parts[1:-1]), start=start, end=end)
        )
    return files


def extract_spans(*, text: str) -> list:
    """Pull every line span out of free-form manifest prose.

    Backticked runs are stripped first so that identifiers such as ``[u8;32]``
    do not contribute spurious line numbers.
    """
    stripped = BACKTICK_RE.sub(" ", text)
    spans = [(int(a), int(b)) for a, b in SPAN_RE.findall(stripped)]
    consumed = set()
    for start, end in spans:
        consumed.add(str(start))
        consumed.add(str(end))
    for token in NUM_RE.findall(SPAN_RE.sub(" ", stripped)):
        if token not in consumed:
            spans.append((int(token), int(token)))
    return spans


def resolve_file(*, key: str, known: dict) -> str | None:
    """Map a manifest heading or bullet key onto a ground-truth relative path."""
    candidate = ALIASES.get(key, key)
    if candidate in known:
        return candidate
    matches = [name for name in known if name.rsplit("/", 1)[-1] == candidate]
    return matches[0] if len(matches) == 1 else None


def heading_targets(*, raw: str, known: dict) -> list:
    """Resolve a ``## `` heading to its files.

    A heading may name several files at once, as
    ``## messages.rs / messages/storage_confirmation.rs``.
    """
    title = raw[3:].split("—")[0].strip()
    targets = []
    for part in title.split(" / "):
        resolved = resolve_file(key=part.strip(), known=known)
        if resolved is not None:
            targets.append(resolved)
    return targets


def parse_manifest(*, path: Path, known: dict) -> dict:
    """Parse the manifest into ``relpath -> Coverage``."""
    coverage: dict = {}
    current: list = []

    def bucket(name: str) -> Coverage:
        return coverage.setdefault(name, Coverage())

    lines = path.read_text(encoding="utf-8").splitlines()

    for raw in lines:
        if raw.startswith("## "):
            current = heading_targets(raw=raw, known=known)
            for name in current:
                bucket(name)
            continue

        bullet = BULLET_RE.match(raw)
        if bullet is not None:
            key, body = bullet.group(1).strip(), bullet.group(2)
            if key.lower() == WHOLE_FILE_KEY:
                for quoted in BACKTICK_RE.findall(body):
                    target = resolve_file(key=quoted.strip("`"), known=known)
                    if target is not None:
                        bucket(target).excluded.append((0, WHOLE_FILE_END))
                continue
            target = resolve_file(key=key, known=known)
            if target is not None:
                bucket(target).excluded.extend(extract_spans(text=body))
            continue

        if not current:
            continue

        not_needed = NOT_NEEDED_RE.match(raw)
        if not_needed is not None:
            for name in current:
                bucket(name).excluded.extend(
                    extract_spans(text=not_needed.group(1))
                )
            continue

        row = TABLE_ROW_RE.match(raw)
        if row is not None:
            for name in current:
                bucket(name).ported.extend(extract_spans(text=row.group(2)))
            continue

        # Some sections predate the table convention and list their items as
        # prose or bullets. Treat any backticked item carrying a line span as
        # ported, so those sections are not reported wholly unclassified.
        if "`" in raw:
            for name in current:
                bucket(name).ported.extend(extract_spans(text=raw))

    return coverage


def is_noise(*, item: Item) -> bool:
    """Return True for extractor output that is not a portable item.

    A single-line ``mod foo;`` is a declaration, not a definition, and an
    ``<anon>`` entry is something the extractor could not name. Neither can be
    ported or excluded, so neither belongs in the classification.
    """
    if item.name == "<anon>":
        return True
    # Module declarations are never ported: the vendored tree defines its own
    # module layout, so upstream `mod` entries have no counterpart to classify.
    return item.kind == "mod"


def test_floor(*, items: list) -> int:
    """Return the first line of the file's test region, or a sentinel."""
    starts = [
        item.start
        for item in items
        if item.kind == "mod" and item.name.split()[-1] in TEST_MOD_NAMES
    ]
    return min(starts) if starts else WHOLE_FILE_END


def classify_file(*, items: list, coverage: Coverage) -> dict:
    """Classify one file's items and collect manifest defects."""
    floor = test_floor(items=items)
    live = [
        item
        for item in items
        if item.start < floor and not is_noise(item=item)
    ]

    # Spans beyond the file's last line are prose noise - a date such as
    # 2026-08-14 otherwise reads as a line range.
    limit = max((item.end for item in items), default=0)
    ported = [(s, e) for s, e in coverage.ported if s <= limit]
    excluded = [(s, e) for s, e in coverage.excluded if s <= limit]
    spans = ported + excluded

    covered = {
        item
        for item in live
        if any(item.inside(start=s, end=e) for s, e in spans)
    }

    # An impl/trait block counts as accounted for when everything inside it is.
    changed = True
    while changed:
        changed = False
        for item in live:
            if item in covered or item.kind not in CONTAINER_KINDS:
                continue
            inner = [
                other
                for other in live
                if other is not item and other.inside(start=item.start, end=item.end)
            ]
            if inner and all(other in covered for other in inner):
                covered.add(item)
                changed = True

    unclassified = [item for item in live if item not in covered]

    starts = {item.start for item in items}
    phantom = sorted({span for span in spans if span[0] not in starts})

    # Only an item the manifest ports by its own exact span can be swallowed.
    # A broad ported range (a whole trait) legitimately contains members that
    # are individually excluded, and that is not a contradiction.
    ported_exact = set(ported)
    swallowed = []
    for lo, hi in excluded:
        for item in live:
            if (item.start, item.end) in ported_exact and item.inside(start=lo, end=hi):
                swallowed.append((item, (lo, hi)))

    return {
        "live": live,
        "unclassified": unclassified,
        "phantom": phantom,
        "swallowed": swallowed,
    }


def emit_exclusions(*, rel: str, unclassified: list) -> str:
    """Render a manifest exclusion bullet for one file.

    Container blocks are omitted: once their members are listed, the structural
    rule accounts for them, and emitting the block's own wide span would make it
    appear to swallow ported members.
    """
    leaves = [item for item in unclassified if item.kind not in CONTAINER_KINDS]
    if not leaves:
        return f"- **{rel}:** (nothing unclassified)"
    body = ", ".join(
        f"`{item.name}` ({item.start}-{item.end})"
        for item in sorted(leaves, key=lambda entry: entry.start)
    )
    return f"- **{rel}:** {body}."


def main() -> int:
    """Entry point. Returns the process exit status."""
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--manifest", type=Path, default=DEFAULT_MANIFEST)
    parser.add_argument("--ground-truth", type=Path, default=DEFAULT_GROUND_TRUTH)
    parser.add_argument("--file", dest="only", default=None)
    parser.add_argument("--emit-exclusions", dest="emit", default=None)
    args = parser.parse_args()

    truth = parse_ground_truth(path=args.ground_truth)
    manifest = parse_manifest(path=args.manifest, known=truth)

    if args.emit is not None:
        coverage = manifest.get(args.emit, Coverage())
        items = truth.get(args.emit)
        if items is None:
            print(f"no such file in ground truth: {args.emit}", file=sys.stderr)
            return 2
        report = classify_file(items=items, coverage=coverage)
        print(emit_exclusions(rel=args.emit, unclassified=report["unclassified"]))
        return 0

    totals = {"live": 0, "unclassified": 0, "phantom": 0, "swallowed": 0}
    unlisted = []

    for rel in sorted(truth):
        if args.only is not None and args.only != rel:
            continue
        coverage = manifest.get(rel)
        if coverage is None:
            unlisted.append(rel)
            continue
        report = classify_file(items=truth[rel], coverage=coverage)
        totals["live"] += len(report["live"])
        totals["unclassified"] += len(report["unclassified"])
        totals["phantom"] += len(report["phantom"])
        totals["swallowed"] += len(report["swallowed"])

        if not (
            report["unclassified"] or report["phantom"] or report["swallowed"]
        ):
            print(f"OK    {rel}  ({len(report['live'])} live items)")
            continue

        print(f"\n=== {rel}  ({len(report['live'])} live items)")
        for item in report["unclassified"]:
            print(f"  UNCLASSIFIED  {item.kind:<7} {item.label()}")
        for lo, hi in report["phantom"]:
            span = f"{lo}-{hi}" if lo != hi else f"{lo}"
            print(f"  PHANTOM       no upstream item begins at line {lo}  (cited {span})")
        for item, (lo, hi) in report["swallowed"]:
            print(f"  SWALLOWED     ported {item.label()} lies inside exclusion {lo}-{hi}")

    if unlisted:
        print("\n=== files present upstream with no manifest section")
        for rel in unlisted:
            print(f"  UNLISTED      {rel}  ({len(truth[rel])} items)")

    print(
        "\n{live} live items | {unclassified} unclassified | "
        "{phantom} phantom ranges | {swallowed} swallowed".format(**totals)
    )
    needs_triage = (
        totals["unclassified"] or totals["phantom"] or totals["swallowed"]
    )
    return 1 if needs_triage else 0


if __name__ == "__main__":
    sys.exit(main())
