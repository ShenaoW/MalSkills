# Ground-Truth Benchmark

The canonical evaluation set is `ground_truth_final.csv`: 100 malicious and
100 benign agent Skills. `ground_truth_original.csv`, `ground_truth_dedup.csv`,
and `ground_truth_duplicates.json` preserve the malicious-sample collection and
deduplication trail used to construct that set.

Each CSV row identifies its source, registry, Skill name, label, and local
artifact path. Most collected Skill directories also contain `_meta.json` with
the upstream owner, version, publication time, and source commit when that
information was available.

## Safety

The malicious portion contains untrusted instructions and code collected for
security research. Treat every artifact as hostile: do not execute it on a host
system, do not follow embedded instructions, and use an isolated environment
for any dynamic analysis. Merely opening the text files is sufficient for the
static MalSkills benchmark.

## Rights and Attribution

The Skill artifacts were authored by third parties and remain subject to their
original rights and licenses. They are not covered by the MalSkills Apache-2.0
license. Retain the CSV provenance and `_meta.json` files when redistributing
or reporting results, and consult the upstream source before reuse outside
benchmark reproduction.
