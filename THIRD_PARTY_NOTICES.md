# Third-Party and Dataset Notices

The root [Apache License 2.0](LICENSE) applies to original MalSkills software
and documentation unless a file or directory states otherwise. It does not
replace the licenses or rights of the materials described below.

## Baselines and YASA

Directories registered in `.gitmodules` are links to independent upstream
repositories pinned to specific commits. Their source is not copied into the
MalSkills Git tree and remains governed by each upstream repository's license.
Review those terms before installing, redistributing, or using a baseline.

`baseline/MASB/` is a modified code snapshot from
[MaliciousAgentSkillsBench](https://github.com/protectskills/MaliciousAgentSkillsBench).
It is distributed under the MIT License included at
[`baseline/MASB/LICENSE`](baseline/MASB/LICENSE). MalSkills-specific adapter
changes do not remove the upstream attribution or license.

## Ground-Truth Skills

`data/ground_truth/` contains third-party Skill artifacts collected for
security research and benchmark reproduction. Where available, `_meta.json`
files retain upstream owner, version, and commit information, while the CSV
manifests record the benchmark provenance and labels.

These third-party artifacts remain subject to their original authors' rights
and licenses and are not relicensed under Apache-2.0. Their inclusion does not
grant additional rights beyond those provided by the respective upstream
projects or applicable law. See
[`data/ground_truth/README.md`](data/ground_truth/README.md) before use.

## Paper and Figures

The ASE 2026 paper and paper-derived assets under `assets/` are distributed
under [CC BY-NC-ND 4.0](https://creativecommons.org/licenses/by-nc-nd/4.0/),
as stated in the paper. This is separate from the software license.
