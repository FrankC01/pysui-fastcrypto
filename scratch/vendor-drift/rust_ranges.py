#!/usr/bin/env python3
"""Extract doc-comment-anchored line ranges for Rust items in vendored walrus sources.

Convention: an item's range starts at the first line of its leading doc-comment
(/// or //!) or attribute (#[...]) block, and ends at the line holding its
closing brace or terminating semicolon.
"""
import re
import sys

DOC_RE = re.compile(r'^\s*(///|//!)')
ATTR_RE = re.compile(r'^\s*#\[')
DECL_RE = re.compile(
    r'^(?P<indent>[ \t]*)'
    r'(?:pub(?:\([^)]*\))?[ \t]+)?'
    r'(?:default[ \t]+)?(?:const[ \t]+)?(?:async[ \t]+)?(?:unsafe[ \t]+)?(?:extern[ \t]+"[^"]*"[ \t]+)?'
    r'(?P<kind>macro_rules!|fn|struct|enum|trait|impl|type|const|static|union|mod)'
    r'(?:[ \t]+(?P<name>[A-Za-z_][A-Za-z0-9_]*))?'
)


def strip_code(line):
    """Remove line comments and string/char literals so brace counting is safe."""
    out = []
    i = 0
    n = len(line)
    while i < n:
        c = line[i]
        if c == '/' and i + 1 < n and line[i + 1] == '/':
            break
        if c == '"':
            i += 1
            while i < n:
                if line[i] == '\\':
                    i += 2
                    continue
                if line[i] == '"':
                    i += 1
                    break
                i += 1
            out.append('""')
            continue
        if c == "'":
            # could be a lifetime; only treat as char literal if it closes soon
            j = i + 1
            if j < n and line[j] == '\\':
                j += 2
            else:
                j += 1
            if j < n and line[j] == "'":
                out.append("''")
                i = j + 1
                continue
        out.append(c)
        i += 1
    return ''.join(out)


def find_start(lines, i):
    """Walk backwards over contiguous doc comments and attribute lines."""
    s = i
    j = i - 1
    bracket_debt = 0
    while j >= 0:
        raw = lines[j]
        code = strip_code(raw)
        stripped = raw.strip()
        if bracket_debt > 0:
            s = j
            bracket_debt += code.count(']') - code.count('[')
            j -= 1
            continue
        if DOC_RE.match(raw):
            s = j
            j -= 1
            continue
        if ATTR_RE.match(raw):
            s = j
            j -= 1
            continue
        if stripped.endswith(']') and not stripped.startswith('#['):
            # possible tail of a multi-line attribute
            debt = code.count(']') - code.count('[')
            if debt > 0:
                s = j
                bracket_debt = debt
                j -= 1
                continue
        break
    return s


def find_end(lines, i):
    """From declaration line i, return the line index terminating the item."""
    n = len(lines)
    paren = 0
    j = i
    brace_line = None
    while j < n:
        code = strip_code(lines[j])
        for ch in code:
            if ch in '([':
                paren += 1
            elif ch in ')]':
                paren -= 1
            elif ch == ';' and paren <= 0:
                return j
            elif ch == '{' and paren <= 0:
                brace_line = j
                break
        if brace_line is not None:
            break
        j += 1
    if brace_line is None:
        return i
    depth = 0
    j = brace_line
    while j < n:
        code = strip_code(lines[j])
        for ch in code:
            if ch == '{':
                depth += 1
            elif ch == '}':
                depth -= 1
                if depth == 0:
                    return j
        j += 1
    return brace_line


def extract(path):
    with open(path, 'r', encoding='utf-8') as fh:
        lines = fh.read().split('\n')
    results = []
    # Map of line index -> enclosing impl/trait name, for qualifying methods.
    owners = []
    for idx, raw in enumerate(lines):
        m = DECL_RE.match(raw)
        if not m:
            continue
        kind = m.group('kind')
        name = m.group('name')
        indent = len(m.group('indent').expandtabs(4))
        start = find_start(lines, idx)
        end = find_end(lines, idx)
        if kind == 'impl':
            header = raw.strip().rstrip('{').strip()
            owners.append((start, end, header, indent))
            results.append((kind, header, start + 1, end + 1, indent))
            continue
        if kind == 'trait':
            owners.append((start, end, name, indent))
        qualifier = None
        for (os_, oe, oname, oind) in owners:
            if os_ <= idx <= oe and oind < indent:
                qualifier = oname
        label = name or '<anon>'
        if qualifier:
            short = qualifier
            mm = re.match(r'impl(?:<[^>]*>)?\s+(?:(?P<tr>[^ ]+)\s+for\s+)?(?P<ty>[A-Za-z_][A-Za-z0-9_]*)', qualifier)
            if mm:
                short = mm.group('ty')
            label = short + '::' + label
        results.append((kind, label, start + 1, end + 1, indent))
    return results


def main():
    for path in sys.argv[1:]:
        print('=== ' + path)
        for kind, label, start, end, indent in extract(path):
            rng = str(start) if start == end else '{}-{}'.format(start, end)
            print('  {:<12} {:<60} {}'.format(kind, label, rng))


if __name__ == '__main__':
    main()
