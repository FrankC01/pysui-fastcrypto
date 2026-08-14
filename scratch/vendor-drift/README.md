# vendor-drift tooling

Supports `/vendor-drift-check` and `scratch/vendor-drift/walrus-port-manifest.md`.

## Why this exists

The manifest cites upstream line ranges for every vendored item. Those numbers
were originally hand-maintained and drifted badly — `merkle.rs` cited
`leaf_hash` / `inner_hash` / `n_nodes` about 33 lines late, and
`basic_encoding.rs` cited overlapping ranges for two different functions, which
cannot both be right. Because the manifest is the authoritative input to the
drift check, stale anchors make the check silently compare the wrong regions.

`rust_ranges.py` regenerates those ranges mechanically, so they are reproducible
rather than asserted.

## Range convention

An item's range runs from the first line of its leading doc-comment (`///`) or
attribute (`#[...]`) block, through the line holding its closing brace or
terminating `;`.

Doc-comment anchored, because we vendor doc comments verbatim — the drift check
should cover exactly the text that was copied.

## Usage

    python3 scratch/vendor-drift/rust_ranges.py <file.rs> [<file.rs> ...]

Output is one line per item:

    <kind>  <qualified name>  <start>-<end>

## Ground truth

`ground_truth-14641cc0.txt` is the extraction for walrus-core at pinned commit
`14641cc0edcc727825d07aa19df2eef8046a3c0d`, covering the 17 upstream files the
manifest draws from (782 items). It is named by commit so it cannot go stale
silently.

To regenerate after moving the pin, run the script over the same file list and
save as `ground_truth-<new-commit>.txt`, then diff the two files to see exactly
which items moved:

    cd ~/mysten_repos/walrus/crates/walrus-core/src
    python3 <path>/rust_ranges.py \
      lib.rs bft.rs merkle.rs utils.rs metadata.rs messages.rs \
      encoding/common.rs encoding/errors.rs encoding/utils.rs \
      encoding/symbols.rs encoding/config.rs encoding/basic_encoding.rs \
      encoding/mapping.rs encoding/slivers.rs encoding/blob_encoding.rs \
      messages/storage_confirmation.rs messages/certificate.rs \
      > ground_truth-<new-commit>.txt

## Known limitation

Macro-generated items have no extractable range. In `lib.rs` these are
`SliverIndex`, `SliverPairIndex`, and `index_type!(ShardIndex)`, all produced by
`index_type!` invocations. The manifest cites them by invocation site, and they
must be checked by hand during drift review.

## Known baseline (2026-08-14)

`classify.py` currently reports:

```
672 live items | 0 unclassified | 48 phantom ranges | 0 swallowed
```

Unclassified and swallowed are the load-bearing columns, and both are zero: every
upstream item is accounted for by a port table or an exclusion list, and no ported
item sits inside an exclusion range. Treat any non-zero value in either column as a
real finding needing triage.

The 48 phantom ranges are a known artifact rather than manifest defects:

- 31 come from the combined heading `## messages.rs / messages/storage_confirmation.rs / messages/certificate.rs`. Spans cited under it are attributed to all three files, so a line valid for one reads as phantom for the other two. Splitting that heading into three sections would clear them.
- 17 come from commentary lines inside table sections, where the prose fallback picks up line numbers that are narrative rather than item citations.

Compare phantom counts against this baseline, not against zero. A count that *moves*
is worth reading; 48 on its own is not. The exit status is 1 whenever any column is
non-zero, so do not treat a non-zero exit as a build failure.
