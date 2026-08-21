from __future__ import annotations

import argparse
import csv
import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path


SKILL_FILE_NAMES = {
    "skill.md",
    "skills.md",
}


@dataclass(frozen=True)
class SampleRecord:
    source: str
    registry: str
    skill_name: str
    label: str
    ground_truth_path: str


@dataclass(frozen=True)
class SkillFileHash:
    relative_path: str
    sha256: str


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Build a deduplicated ground truth CSV from skill markdown hashes."
    )
    parser.add_argument(
        "--input",
        default="data/ground_truth/ground_truth_original.csv",
        help="Input CSV path.",
    )
    parser.add_argument(
        "--output",
        default="data/ground_truth/ground_truth_dedup.csv",
        help="Output deduplicated CSV path.",
    )
    parser.add_argument(
        "--duplicates-json",
        default="data/ground_truth/ground_truth_dedup_duplicates.json",
        help="Output JSON path for duplicate groups.",
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Repository root used to resolve relative ground truth paths.",
    )
    return parser.parse_args()


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def load_records(path: Path) -> list[SampleRecord]:
    with path.open(newline="", encoding="utf-8") as handle:
        reader = csv.DictReader(handle)
        return [
            SampleRecord(
                source=row["Source"],
                registry=row["Registry"],
                skill_name=row["Skill_name"],
                label=row["Label"],
                ground_truth_path=row["Ground_truth_path"],
            )
            for row in reader
        ]


def collect_skill_hashes(sample_dir: Path) -> list[SkillFileHash]:
    hashes: list[SkillFileHash] = []
    for path in sorted(sample_dir.rglob("*")):
        if not path.is_file():
            continue
        if path.name.lower() not in SKILL_FILE_NAMES:
            continue
        rel = path.relative_to(sample_dir).as_posix()
        hashes.append(SkillFileHash(relative_path=rel, sha256=sha256_bytes(path.read_bytes())))
    return hashes


def build_sample_digest(skill_hashes: list[SkillFileHash]) -> str:
    payload = json.dumps(
        [{"relative_path": item.relative_path, "sha256": item.sha256} for item in skill_hashes],
        sort_keys=True,
        ensure_ascii=True,
        separators=(",", ":"),
    ).encode("utf-8")
    return sha256_bytes(payload)


def record_sort_key(record: SampleRecord) -> tuple[str, str, str, str, str]:
    return (
        record.source,
        record.registry,
        record.skill_name,
        record.ground_truth_path,
        record.label,
    )


def main() -> None:
    args = parse_args()
    repo_root = Path(args.root).resolve()
    input_path = (repo_root / args.input).resolve()
    output_path = (repo_root / args.output).resolve()
    duplicates_json_path = (repo_root / args.duplicates_json).resolve()

    records = load_records(input_path)
    grouped: dict[str, list[dict[str, object]]] = defaultdict(list)

    for record in records:
        sample_dir = (repo_root / record.ground_truth_path).resolve()
        skill_hashes = collect_skill_hashes(sample_dir)
        sample_digest = build_sample_digest(skill_hashes)
        grouped[sample_digest].append(
            {
                "record": record,
                "skill_file_hashes": [
                    {"relative_path": item.relative_path, "sha256": item.sha256} for item in skill_hashes
                ],
            }
        )

    deduped_records: list[SampleRecord] = []
    duplicate_groups: list[dict[str, object]] = []

    for sample_digest, items in sorted(grouped.items(), key=lambda item: len(item[1]), reverse=True):
        sorted_items = sorted(items, key=lambda item: record_sort_key(item["record"]))  # type: ignore[index]
        canonical = sorted_items[0]
        deduped_records.append(canonical["record"])  # type: ignore[arg-type]
        if len(sorted_items) > 1:
            duplicate_groups.append(
                {
                    "sample_digest": sample_digest,
                    "canonical": canonical["record"].ground_truth_path,  # type: ignore[index]
                    "size": len(sorted_items),
                    "members": [
                        {
                            "source": item["record"].source,  # type: ignore[index]
                            "registry": item["record"].registry,  # type: ignore[index]
                            "skill_name": item["record"].skill_name,  # type: ignore[index]
                            "ground_truth_path": item["record"].ground_truth_path,  # type: ignore[index]
                        }
                        for item in sorted_items
                    ],
                    "skill_file_hashes": canonical["skill_file_hashes"],  # type: ignore[index]
                }
            )

    deduped_records.sort(key=record_sort_key)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["Source", "Registry", "Skill_name", "Label", "Ground_truth_path"],
        )
        writer.writeheader()
        for record in deduped_records:
            writer.writerow(
                {
                    "Source": record.source,
                    "Registry": record.registry,
                    "Skill_name": record.skill_name,
                    "Label": record.label,
                    "Ground_truth_path": record.ground_truth_path,
                }
            )

    duplicates_json_path.parent.mkdir(parents=True, exist_ok=True)
    with duplicates_json_path.open("w", encoding="utf-8") as handle:
        json.dump(
            {
                "input_count": len(records),
                "deduped_count": len(deduped_records),
                "duplicate_group_count": len(duplicate_groups),
                "duplicate_groups": duplicate_groups,
            },
            handle,
            ensure_ascii=False,
            indent=2,
        )

    print(
        json.dumps(
            {
                "input_csv": input_path.relative_to(repo_root).as_posix(),
                "output_csv": output_path.relative_to(repo_root).as_posix(),
                "duplicates_json": duplicates_json_path.relative_to(repo_root).as_posix(),
                "input_count": len(records),
                "deduped_count": len(deduped_records),
                "duplicate_group_count": len(duplicate_groups),
            },
            ensure_ascii=False,
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
