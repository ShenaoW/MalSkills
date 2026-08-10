#!/usr/bin/env bash
set -Eeuo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUTPUT_DIR=""
PAUSE_SEC="1.2"
RUN_SETUP=0
RUN_FULL=0
RUN_DOCKER_BUILD=0
RUN_DOCKER_RUN=0
RUN_DOCKER_SMOKE=0
QUIET_BUILD=1
CONCISE=0
SINGLE_DEMO=0
SKIP_SINGLE=0
SKIP_MINI_BENCHMARK=0
SAMPLE_PATH="data/ground_truth/malicious/clawhub/pepe276_publish-dist"
SINGLE_OUTPUT_NAME="single_sample_full"
DEMO_VARIANT="benchmark_full"
DOCKER_IMAGE="malskills-demo:latest"
DOCKER_RESULT="not_requested"

usage() {
  cat <<'EOF'
Usage: bash scripts/demo_reproduce.sh [options]

Recording-friendly reproduction script for MalSkills.

Options:
  --single-demo           Shortest defense demo: one malicious sample only, no benchmark run.
  --recording             Fast recording mode: no setup/build, smoke-test existing Docker image if present.
  --concise               Print only key status lines; write detailed logs to files.
  --verbose-demo          Print detailed source/config output.
  --setup                 Create .venv, install Python deps, clone/build YASA.
  --from-scratch          Alias of --setup. Use this when demonstrating deployment from zero.
  --docker-build          Build the Docker image to demonstrate containerized deployment.
  --docker-run            After --docker-build, run a container smoke demo.
  --docker-smoke          Run a container smoke demo only if the image already exists.
  --docker-image NAME     Docker image tag. Default: malskills-demo:latest
  --quiet-build           Hide long setup/docker logs and write them to command_logs/. Default.
  --verbose-build         Print full setup/docker logs to terminal.
  --output DIR            Output directory. Default: output/demo_reproduction/<timestamp>
  --pause SEC             Sleep between demo sections. Default: 1.2
  --no-pause              Disable sleeps between sections.
  --sample PATH           Single-skill demo sample.
  --skip-single           Skip single-skill full analysis.
  --skip-mini-benchmark   Skip 2-case benchmark demo.
  --full                  Also run the 200-entry benchmark_full evaluation.
  -h, --help              Show this help.

Recommended recording command:
  bash scripts/demo_reproduce.sh --single-demo

Deployment-from-scratch recording command:
  bash scripts/demo_reproduce.sh --from-scratch --docker-build --docker-run --no-pause

Full reproduction command:
  bash scripts/demo_reproduce.sh --no-pause --full
EOF
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --single-demo)
      SINGLE_DEMO=1
      PAUSE_SEC="0"
      RUN_DOCKER_SMOKE=1
      CONCISE=1
      QUIET_BUILD=1
      SKIP_MINI_BENCHMARK=1
      shift
      ;;
    --recording)
      PAUSE_SEC="0"
      RUN_DOCKER_SMOKE=1
      CONCISE=1
      QUIET_BUILD=1
      shift
      ;;
    --concise)
      CONCISE=1
      shift
      ;;
    --verbose-demo)
      CONCISE=0
      shift
      ;;
    --setup)
      RUN_SETUP=1
      shift
      ;;
    --from-scratch)
      RUN_SETUP=1
      shift
      ;;
    --docker-build)
      RUN_DOCKER_BUILD=1
      shift
      ;;
    --docker-run)
      RUN_DOCKER_BUILD=1
      RUN_DOCKER_RUN=1
      shift
      ;;
    --docker-smoke)
      RUN_DOCKER_SMOKE=1
      shift
      ;;
    --docker-image)
      DOCKER_IMAGE="${2:?missing value for --docker-image}"
      shift 2
      ;;
    --quiet-build)
      QUIET_BUILD=1
      shift
      ;;
    --verbose-build)
      QUIET_BUILD=0
      shift
      ;;
    --output)
      OUTPUT_DIR="${2:?missing value for --output}"
      shift 2
      ;;
    --pause)
      PAUSE_SEC="${2:?missing value for --pause}"
      shift 2
      ;;
    --no-pause)
      PAUSE_SEC="0"
      shift
      ;;
    --sample)
      SAMPLE_PATH="${2:?missing value for --sample}"
      shift 2
      ;;
    --skip-single)
      SKIP_SINGLE=1
      shift
      ;;
    --skip-mini-benchmark)
      SKIP_MINI_BENCHMARK=1
      shift
      ;;
    --full)
      RUN_FULL=1
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      echo "Unknown option: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

cd "$ROOT_DIR"

if [[ -z "$OUTPUT_DIR" ]]; then
  OUTPUT_DIR="output/demo_reproduction/$(date +%Y%m%d_%H%M%S)"
fi
mkdir -p "$OUTPUT_DIR"
LOG_FILE="$OUTPUT_DIR/demo.log"
COMMAND_LOG_DIR="$OUTPUT_DIR/command_logs"
mkdir -p "$COMMAND_LOG_DIR"

if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  BOLD=$'\033[1m'
  GREEN=$'\033[32m'
  YELLOW=$'\033[33m'
  BLUE=$'\033[34m'
  RESET=$'\033[0m'
else
  BOLD=""
  GREEN=""
  YELLOW=""
  BLUE=""
  RESET=""
fi

exec > >(tee -a "$LOG_FILE") 2>&1

on_error() {
  local exit_code=$?
  echo
  echo "${YELLOW}[FAILED]${RESET} line ${BASH_LINENO[0]}: ${BASH_COMMAND}"
  echo "Log: $LOG_FILE"
  exit "$exit_code"
}
trap on_error ERR

section() {
  echo
  echo "${BLUE}================================================================${RESET}"
  echo "${BOLD}$1${RESET}"
  echo "${BLUE}================================================================${RESET}"
  if [[ "$PAUSE_SEC" != "0" ]]; then
    sleep "$PAUSE_SEC"
  fi
}

run_cmd() {
  echo
  echo "${GREEN}$ $*${RESET}"
  "$@"
}

run_long_cmd() {
  local label="$1"
  shift
  local log_file="$COMMAND_LOG_DIR/${label}.log"
  echo
  echo "${GREEN}$ $*${RESET}"
  if [[ "$QUIET_BUILD" == "1" ]]; then
    echo "Long output is hidden for recording. Full log: $log_file"
    if "$@" >"$log_file" 2>&1; then
      echo "OK: $label"
    else
      echo "FAILED: $label"
      echo "Last 80 log lines:"
      tail -80 "$log_file" || true
      return 1
    fi
  else
    "$@"
  fi
}

run_yasa_tsc() {
  echo
  echo "${GREEN}$ (cd vendor/yasa && npx tsc)${RESET}"
  if [[ "$QUIET_BUILD" == "1" ]]; then
    local log_file="$COMMAND_LOG_DIR/yasa_tsc.log"
    echo "Long output is hidden for recording. Full log: $log_file"
    if (cd vendor/yasa && npx tsc) >"$log_file" 2>&1; then
      echo "OK: yasa_tsc"
    else
      echo "FAILED: yasa_tsc"
      echo "Last 80 log lines:"
      tail -80 "$log_file" || true
      return 1
    fi
  else
    (cd vendor/yasa && npx tsc)
  fi
}

need_command() {
  if ! command -v "$1" >/dev/null 2>&1; then
    echo "Missing command: $1"
    echo "Run with --setup if the missing tool is managed by this project, or install it first."
    exit 1
  fi
}

setup_environment() {
  section "0. Setup Python environment and YASA"
  need_command python3
  if [[ -x .venv/bin/python ]]; then
    echo "Reuse existing Python virtualenv: .venv"
  else
    run_long_cmd python_venv python3 -m venv .venv
  fi
  run_long_cmd pip_upgrade .venv/bin/python -m pip install --upgrade pip
  run_long_cmd pip_install_project .venv/bin/python -m pip install -e . semgrep

  need_command git
  need_command npm
  if [[ ! -f vendor/yasa/package.json ]]; then
    mkdir -p vendor
    run_cmd git clone --branch v0.3.1 --depth 1 https://github.com/antgroup/YASA-Engine.git vendor/yasa
  fi
  run_long_cmd yasa_npm_ci npm --prefix vendor/yasa ci
  run_yasa_tsc
}

print_tree_snapshot() {
  local root="$1"
  local max_depth="$2"
  local limit="${3:-30}"
  find "$root" -maxdepth "$max_depth" -type f \
    ! -path "*/__pycache__/*" \
    ! -name "*.pyc" \
    | sort \
    | sed 's#^\./##' \
    | awk -v limit="$limit" 'NR <= limit { print }'
}

PY=".venv/bin/python"
if [[ "$RUN_SETUP" == "1" ]]; then
  setup_environment
fi

section "1. Demo metadata"
echo "Project root: $ROOT_DIR"
echo "Output dir:   $OUTPUT_DIR"
echo "Log file:     $LOG_FILE"
echo "Date:         $(date '+%Y-%m-%d %H:%M:%S %Z')"
echo "Mode:         YASA + LLM full pipeline"
if [[ "$RUN_SETUP" == "1" ]]; then
  echo "Deployment:   from scratch (--setup/--from-scratch)"
else
  echo "Deployment:   reuse existing local environment"
  echo "              run with --from-scratch to demonstrate environment deployment"
fi
echo "Build logs:   $COMMAND_LOG_DIR"

section "2. Source and deployment materials"
if [[ "$CONCISE" == "1" ]]; then
  echo "Core source package: malskills/ ($(find malskills -name '*.py' -type f | wc -l | tr -d ' ') Python files)"
else
  echo "Core source package:"
  print_tree_snapshot "malskills" 2 30
  echo
fi
echo "Reproduction and deployment files:"
for file in \
  "scripts/demo_reproduce.sh" \
  "docs/DEMO_REPRODUCTION.md" \
  "Dockerfile" \
  ".dockerignore" \
  "pyproject.toml" \
  "README.md"; do
  if [[ -f "$file" ]]; then
    echo "- present: $file"
  else
    echo "- missing: $file"
  fi
done

section "3. Containerization deployment plan"
if [[ -f Dockerfile ]]; then
  echo "Dockerfile is present and defines a reproducible image with Python, Node, project dependencies, Semgrep, and YASA build."
else
  echo "Dockerfile is missing."
fi
echo
echo "Docker build command:"
echo "  docker build -t $DOCKER_IMAGE ."
echo
echo "Docker run command with OpenAI-compatible API:"
echo "  docker run --rm -e MALSKILLS_LLM_MODE=openai_api -e OPENAI_API_KEY=\"\$OPENAI_API_KEY\" -v \"\$PWD/output:/app/output\" $DOCKER_IMAGE bash scripts/demo_reproduce.sh --no-pause"
echo
if command -v docker >/dev/null 2>&1; then
  run_cmd docker --version
  if [[ "$RUN_DOCKER_BUILD" == "1" ]]; then
    run_long_cmd docker_build docker build -t "$DOCKER_IMAGE" .
    DOCKER_RESULT="build_ok"
    if [[ "$RUN_DOCKER_RUN" == "1" ]]; then
      run_cmd docker run --rm "$DOCKER_IMAGE" .venv/bin/malskills --help
      DOCKER_RESULT="build_and_run_ok"
    fi
  elif [[ "$RUN_DOCKER_SMOKE" == "1" ]]; then
    if docker image inspect "$DOCKER_IMAGE" >/dev/null 2>&1; then
      echo "Docker image already exists: $DOCKER_IMAGE"
      run_cmd docker run --rm "$DOCKER_IMAGE" .venv/bin/malskills --help
      DOCKER_RESULT="smoke_ok_reused_image"
    else
      echo "Docker image not found: $DOCKER_IMAGE"
      echo "Build it once with: bash scripts/demo_reproduce.sh --docker-build --docker-run --skip-single --skip-mini-benchmark --no-pause"
      DOCKER_RESULT="image_missing"
    fi
  else
    echo "Docker build not requested. Use --docker-build to build the image during recording."
  fi
else
  echo "Docker CLI not found on this host. The Dockerfile and run commands are still provided for deployment."
  DOCKER_RESULT="docker_cli_missing"
fi

if [[ ("$RUN_DOCKER_BUILD" == "1" || "$RUN_DOCKER_SMOKE" == "1") \
  && "$SKIP_SINGLE" == "1" \
  && "$SKIP_MINI_BENCHMARK" == "1" \
  && "$RUN_FULL" != "1" ]]; then
  section "4. Docker-only run complete"
  case "$DOCKER_RESULT" in
    build_ok|build_and_run_ok|smoke_ok_reused_image)
      echo "Docker result: $DOCKER_RESULT"
      exit 0
      ;;
    *)
      echo "Docker-only run did not complete successfully: $DOCKER_RESULT" >&2
      exit 1
      ;;
  esac
fi

section "4. Local environment checks"
if [[ ! -x "$PY" ]]; then
  echo "Python virtualenv not found: $PY"
  echo "Run: bash scripts/demo_reproduce.sh --setup"
  exit 1
fi
need_command node
need_command npm
run_cmd "$PY" --version
run_cmd node --version
run_cmd npm --version

if [[ "$CONCISE" != "1" ]]; then
  run_cmd "$PY" -m malskills.cli show-llm-config
fi
run_cmd "$PY" - <<'PY'
import json
import sys
from malskills.llm_runtime import describe_llm_runtime
from malskills.sdg.yasa import YasaAdapter

yasa = YasaAdapter()
llm = describe_llm_runtime()
payload = {
    "yasa_available": yasa.available(),
    "yasa_root": str(yasa.yasa_root),
    "llm_backend": llm["resolved_backend"],
    "llm_model": llm["model"],
}
print(json.dumps(payload, indent=2, sort_keys=True))
if not payload["yasa_available"]:
    raise SystemExit("YASA is unavailable. Build vendor/yasa first or run with --setup.")
if payload["llm_backend"] == "unavailable":
    raise SystemExit("LLM backend is unavailable. Configure Codex/Claude CLI or API credentials.")
PY

BENCHMARK_INDEX="$OUTPUT_DIR/ground_truth_benchmark.json"
DEMO_BENCHMARK="$OUTPUT_DIR/demo_benchmark_2cases.json"
if [[ "$SKIP_MINI_BENCHMARK" != "1" || "$RUN_FULL" == "1" ]]; then
  section "6. Build reproducible benchmark index"
  if [[ "$CONCISE" == "1" ]]; then
    run_long_cmd build_benchmark "$PY" -m malskills.cli build-benchmark-index --root . --output "$BENCHMARK_INDEX"
    run_cmd "$PY" - "$BENCHMARK_INDEX" <<'PY'
import json
import sys
from collections import Counter
from pathlib import Path

entries = json.loads(Path(sys.argv[1]).read_text(encoding="utf-8"))
labels = Counter(entry["label"] for entry in entries)
print("Benchmark index")
print(f"- entries: {len(entries)}")
print(f"- labels: {dict(labels)}")
PY
  else
    run_cmd "$PY" -m malskills.cli build-benchmark-index --root . --output "$BENCHMARK_INDEX"
  fi
else
  if [[ "$SINGLE_DEMO" != "1" ]]; then
    section "6. Benchmark index skipped"
    echo "Single-demo mode does not run benchmark evaluation."
  fi
fi

if [[ "$SKIP_MINI_BENCHMARK" != "1" ]]; then
  run_cmd "$PY" - "$BENCHMARK_INDEX" "$DEMO_BENCHMARK" <<'PY'
import json
import sys
from pathlib import Path

source = Path(sys.argv[1])
dest = Path(sys.argv[2])
entries = json.loads(source.read_text(encoding="utf-8"))
required = [
    "ground_truth::clawhub::steipete/github",
    "ground_truth::clawhub::pepe276/publish-dist",
]
by_id = {entry["entry_id"]: entry for entry in entries}
selected = []
missing = []
for entry_id in required:
    item = by_id.get(entry_id)
    if item is None:
        missing.append(entry_id)
    else:
        selected.append(item)
if missing:
    raise SystemExit(f"missing required demo benchmark entries: {missing}")
dest.write_text(json.dumps(selected, indent=2, sort_keys=True), encoding="utf-8")
print(f"wrote {len(selected)} demo benchmark entries to {dest}")
for item in selected:
    print(f"- {item['label']}: {item['entry_id']} -> {item['local_path']}")
PY
fi

if [[ "$SKIP_SINGLE" != "1" ]]; then
  if [[ "$SINGLE_DEMO" == "1" ]]; then
    section "6. Single malicious sample analysis: YASA + LLM"
  else
    section "7. Single skill full analysis: YASA + LLM"
  fi
  SINGLE_OUT="$OUTPUT_DIR/$SINGLE_OUTPUT_NAME"
  run_cmd "$PY" -m malskills.cli analyze-skill "$SAMPLE_PATH" --output "$SINGLE_OUT"
  run_cmd "$PY" - "$SINGLE_OUT" <<'PY'
import json
import sys
from collections import Counter
from pathlib import Path

root = Path(sys.argv[1])
verdict = json.loads((root / "verdict.json").read_text(encoding="utf-8"))
feedback = json.loads((root / "feedback_loop.json").read_text(encoding="utf-8"))
operand_resolutions = json.loads((root / "operand_resolutions.json").read_text(encoding="utf-8"))
resolution_methods = Counter(item.get("method", "unknown") for item in operand_resolutions)
llm_runtime = feedback.get("llm_feedback_runtime", {}) if isinstance(feedback.get("llm_feedback_runtime", {}), dict) else {}
llm_backend = feedback.get("backend") or llm_runtime.get("backend")
llm_model = feedback.get("model") or llm_runtime.get("model")
print("Single-skill verdict")
print(f"- label: {verdict.get('label')}")
print(f"- malicious_patterns: {verdict.get('malicious_patterns', [])}")
print("Engine participation")
print(f"- llm_backend: {llm_backend}")
print(f"- llm_model: {llm_model}")
print(f"- operand_resolution_methods: {dict(resolution_methods)}")
print(f"- output: {root}")
if llm_backend in {None, "unavailable"}:
    raise SystemExit("LLM backend was not recorded in feedback_loop.json")
if resolution_methods.get("yasa", 0) < 1:
    raise SystemExit("YASA did not produce operand resolutions for this demo sample")
PY
else
  if [[ "$SINGLE_DEMO" != "1" ]]; then
    section "7. Single skill full analysis skipped"
    echo "Skipped by --skip-single"
  fi
fi

if [[ "$SKIP_MINI_BENCHMARK" != "1" ]]; then
  section "8. Mini benchmark demo: 1 benign + 1 malicious"
  MINI_OUT="$OUTPUT_DIR/eval_mini"
  run_cmd "$PY" -m malskills.cli run-eval --benchmark "$DEMO_BENCHMARK" --output "$MINI_OUT" --variant "$DEMO_VARIANT"
  run_cmd "$PY" -m malskills.cli render-report --results "$MINI_OUT"
  run_cmd "$PY" - "$MINI_OUT" "$DEMO_VARIANT" <<'PY'
import json
import sys
from collections import Counter
from pathlib import Path

root = Path(sys.argv[1])
variant = sys.argv[2]
payload = json.loads((root / f"eval_{variant}.json").read_text(encoding="utf-8"))
metrics = payload["metrics"]
status_counts = Counter(row["status"] for row in payload["results"])
pred_counts = Counter(row["predicted"] for row in payload["results"])
label_pred = Counter((row["label"], row["predicted"]) for row in payload["results"])
risk_positive = {"malicious"}
risk_tp = sum(1 for row in payload["results"] if row["label"] == "malicious" and row["predicted"] in risk_positive)
risk_fp = sum(1 for row in payload["results"] if row["label"] != "malicious" and row["predicted"] in risk_positive)
risk_fn = sum(1 for row in payload["results"] if row["label"] == "malicious" and row["predicted"] not in risk_positive)
risk_tn = sum(1 for row in payload["results"] if row["label"] != "malicious" and row["predicted"] not in risk_positive)
risk_precision = risk_tp / (risk_tp + risk_fp) if risk_tp + risk_fp else 0.0
risk_recall = risk_tp / (risk_tp + risk_fn) if risk_tp + risk_fn else 0.0
risk_f1 = 2 * risk_precision * risk_recall / (risk_precision + risk_recall) if risk_precision + risk_recall else 0.0
case_root = root / "cases" / variant
llm_cases = 0
yasa_cases = 0
for case_dir in case_root.iterdir():
    feedback_path = case_dir / "feedback_loop.json"
    operand_resolutions_path = case_dir / "operand_resolutions.json"
    if feedback_path.exists():
        feedback = json.loads(feedback_path.read_text(encoding="utf-8"))
        llm_runtime = feedback.get("llm_feedback_runtime", {}) if isinstance(feedback.get("llm_feedback_runtime", {}), dict) else {}
        llm_backend = feedback.get("backend") or llm_runtime.get("backend")
        if llm_backend not in {None, "unavailable"}:
            llm_cases += 1
    if operand_resolutions_path.exists():
        items = json.loads(operand_resolutions_path.read_text(encoding="utf-8"))
        if any(item.get("method") == "yasa" for item in items):
            yasa_cases += 1
print("Mini benchmark summary")
print(f"- entries: {int(metrics['num_entries'])}")
print(f"- strict_precision_malicious_only: {metrics['precision']}")
print(f"- strict_recall_malicious_only: {metrics['recall']}")
print(f"- malicious_precision: {risk_precision:.4f}")
print(f"- malicious_recall: {risk_recall:.4f}")
print(f"- malicious_f1: {risk_f1:.4f}")
print(f"- risk_confusion: TP={risk_tp}, FP={risk_fp}, FN={risk_fn}, TN={risk_tn}")
print(f"- status_counts: {dict(status_counts)}")
print(f"- prediction_counts: {dict(pred_counts)}")
print(f"- label_prediction_counts: {dict(label_pred)}")
print(f"- llm_cases: {llm_cases}")
print(f"- yasa_cases: {yasa_cases}")
print(f"- report: {root / 'summary.md'}")
if status_counts.get("error", 0) or status_counts.get("timeout", 0):
    raise SystemExit("Mini benchmark has error or timeout cases")
if llm_cases != int(metrics["num_entries"]):
    raise SystemExit("Not every mini benchmark case recorded LLM feedback")
PY
else
  if [[ "$SINGLE_DEMO" != "1" ]]; then
    section "8. Mini benchmark demo skipped"
    echo "Skipped by --skip-mini-benchmark"
  fi
fi

if [[ "$RUN_FULL" == "1" ]]; then
  section "9. Full benchmark reproduction: 200 entries"
  FULL_OUT="$OUTPUT_DIR/eval_full"
  run_cmd "$PY" -m malskills.cli run-eval --benchmark "$BENCHMARK_INDEX" --output "$FULL_OUT" --variant "$DEMO_VARIANT"
  run_cmd "$PY" -m malskills.cli render-report --results "$FULL_OUT"
  run_cmd "$PY" - "$FULL_OUT" "$DEMO_VARIANT" <<'PY'
import json
import sys
from collections import Counter
from pathlib import Path

root = Path(sys.argv[1])
variant = sys.argv[2]
payload = json.loads((root / f"eval_{variant}.json").read_text(encoding="utf-8"))
metrics = payload["metrics"]
status_counts = Counter(row["status"] for row in payload["results"])
pred_counts = Counter(row["predicted"] for row in payload["results"])
print("Full benchmark summary")
print(f"- entries: {int(metrics['num_entries'])}")
print(f"- precision: {metrics['precision']}")
print(f"- recall: {metrics['recall']}")
print(f"- f1: {metrics['f1']}")
print(f"- confusion: TP={int(metrics['tp'])}, FP={int(metrics['fp'])}, FN={int(metrics['fn'])}, TN={int(metrics['tn'])}")
print(f"- avg_runtime_sec: {metrics['avg_runtime_sec']}")
print(f"- status_counts: {dict(status_counts)}")
print(f"- prediction_counts: {dict(pred_counts)}")
print(f"- report: {root / 'summary.md'}")
PY
else
  if [[ "$SINGLE_DEMO" != "1" ]]; then
    section "9. Full benchmark reproduction not requested"
    echo "Use --full to run all 200 entries. This is slow because every case invokes the LLM backend."
  fi
fi

if [[ "$SINGLE_DEMO" == "1" ]]; then
  section "7. Core detection report"
else
  section "10. Delivery report"
fi
CORE_REPORT="$OUTPUT_DIR/core_detection_report.md"
DELIVERY_REPORT="$OUTPUT_DIR/delivery_report.md"
run_cmd "$PY" - "$OUTPUT_DIR" "$DEMO_VARIANT" "$DOCKER_RESULT" "$RUN_SETUP" "$RUN_FULL" "$SINGLE_DEMO" "$SAMPLE_PATH" "$SINGLE_OUTPUT_NAME" <<'PY'
import json
import sys
from collections import Counter
from pathlib import Path

output_dir = Path(sys.argv[1])
variant = sys.argv[2]
docker_result = sys.argv[3]
setup_requested = sys.argv[4] == "1"
full_requested = sys.argv[5] == "1"
single_demo = sys.argv[6] == "1"
sample_path = sys.argv[7]
single_output_name = sys.argv[8]

def read_json(path: Path):
    if not path.exists():
        return None
    return json.loads(path.read_text(encoding="utf-8"))

def feedback_runtime(feedback):
    if not feedback:
        return {}
    runtime = feedback.get("llm_feedback_runtime", {})
    if not isinstance(runtime, dict):
        runtime = {}
    return {
        "backend": feedback.get("backend") or runtime.get("backend"),
        "model": feedback.get("model") or runtime.get("model"),
    }

def resolution_methods(path: Path):
    items = read_json(path)
    if not items:
        return {}
    return dict(Counter(item.get("method", "unknown") for item in items))

def benchmark_summary(root: Path):
    payload = read_json(root / f"eval_{variant}.json")
    if not payload:
        return None
    metrics = payload["metrics"]
    status_counts = Counter(row["status"] for row in payload["results"])
    pred_counts = Counter(row["predicted"] for row in payload["results"])
    label_pred = Counter(f"{row['label']} -> {row['predicted']}" for row in payload["results"])
    case_root = root / "cases" / variant
    llm_cases = 0
    yasa_cases = 0
    if case_root.exists():
        for case_dir in case_root.iterdir():
            runtime = feedback_runtime(read_json(case_dir / "feedback_loop.json"))
            if runtime.get("backend") not in {None, "unavailable"}:
                llm_cases += 1
            items = read_json(case_dir / "operand_resolutions.json") or []
            if any(item.get("method") == "yasa" for item in items):
                yasa_cases += 1
    return {
        "entries": int(metrics["num_entries"]),
        "precision": metrics["precision"],
        "recall": metrics["recall"],
        "f1": metrics["f1"],
        "confusion": f"TP={int(metrics['tp'])}, FP={int(metrics['fp'])}, FN={int(metrics['fn'])}, TN={int(metrics['tn'])}",
        "status_counts": dict(status_counts),
        "prediction_counts": dict(pred_counts),
        "label_prediction_counts": dict(label_pred),
        "llm_cases": llm_cases,
        "yasa_cases": yasa_cases,
        "summary_path": str(root / "summary.md"),
    }

single_root = output_dir / single_output_name
single_verdict = read_json(single_root / "verdict.json")
single_feedback = read_json(single_root / "feedback_loop.json")
single_runtime = feedback_runtime(single_feedback)
single_resolution_methods = resolution_methods(single_root / "operand_resolutions.json")
mini = benchmark_summary(output_dir / "eval_mini")
full = benchmark_summary(output_dir / "eval_full")
single_label = single_verdict.get("label") if single_verdict else None
single_risk_alert = single_label == "malicious"

lines = [
    "# MalSkills Core Detection Report",
    "",
    "## 1. Delivery Scope",
    "",
    f"- Demo mode: {'single malicious sample' if single_demo else 'benchmark demo'}",
    f"- Environment deployment from scratch: {'yes' if setup_requested else 'no, reused existing local environment'}",
    f"- Docker deployment status: {docker_result}",
    f"- Full 200-entry benchmark requested: {'yes' if full_requested else 'no'}",
    "",
    "## 2. Standardized Artifacts",
    "",
    "- Source code: `malskills/`",
    "- Reproduction script: `scripts/demo_reproduce.sh`",
    "- Deployment document: `docs/DEMO_REPRODUCTION.md`",
    "- Containerization files: `Dockerfile`, `.dockerignore`",
    "- Benchmark data: `data/ground_truth/`",
    "",
    "## 3. Malicious Sample Detection Result",
    "",
]
if single_verdict:
    lines.extend([
        f"- Sample: `{sample_path}`",
        "- Ground-truth label: `malicious`",
        f"- System decision: `{'RISK_ALERT' if single_risk_alert else 'NO_ALERT'}`",
        f"- Verdict label: `{single_verdict.get('label')}`",
        f"- Malicious patterns: `{single_verdict.get('malicious_patterns', [])}`",
        f"- LLM backend: `{single_runtime.get('backend')}`",
        f"- LLM model: `{single_runtime.get('model')}`",
        f"- Operand resolution methods: `{single_resolution_methods}`",
        "- Interpretation: `malicious` is the only positive verdict; `benign` is the negative verdict.",
    ])
else:
    lines.append("- Skipped or not generated.")
if single_demo:
    lines.extend([
        "",
        "## 4. Finding Files",
        "",
        "- Primary report for defense: `core_detection_report.md`",
        f"- Single-skill raw verdict: `{single_output_name}/verdict.json`",
        f"- LLM runtime findings: `{single_output_name}/feedback_loop.json`",
        f"- YASA operand resolutions: `{single_output_name}/operand_resolutions.json`",
        "- Full terminal log: `demo.log`",
        "",
        "## 5. Scope Note",
        "",
        "- This run intentionally demonstrates one confirmed malicious sample only.",
        "- Benchmark evaluation is optional and is not needed for the short recording demo.",
        "- Use `--full` only when reproducing all benchmark entries offline.",
    ])
else:
    lines.extend(["", "## 4. Mini Benchmark Result", ""])
    if mini:
        lines.extend([
            f"- Entries: `{mini['entries']}`",
            f"- Strict malicious precision: `{mini['precision']}`",
            f"- Strict malicious recall: `{mini['recall']}`",
            f"- Strict malicious confusion: `{mini['confusion']}`",
            f"- Status counts: `{mini['status_counts']}`",
            f"- Prediction counts: `{mini['prediction_counts']}`",
            f"- Label to prediction: `{mini['label_prediction_counts']}`",
            f"- LLM cases: `{mini['llm_cases']}/{mini['entries']}`",
            f"- YASA hit cases: `{mini['yasa_cases']}`",
            f"- Report: `{mini['summary_path']}`",
        ])
    else:
        lines.append("- Skipped or not generated.")
    lines.extend(["", "## 5. Full Benchmark Result", ""])
    if full:
        lines.extend([
            f"- Entries: `{full['entries']}`",
            f"- Strict malicious precision: `{full['precision']}`",
            f"- Strict malicious recall: `{full['recall']}`",
            f"- Strict malicious confusion: `{full['confusion']}`",
            f"- Status counts: `{full['status_counts']}`",
            f"- Prediction counts: `{full['prediction_counts']}`",
            f"- LLM cases: `{full['llm_cases']}/{full['entries']}`",
            f"- YASA hit cases: `{full['yasa_cases']}`",
            f"- Report: `{full['summary_path']}`",
        ])
    else:
        lines.append("- Not requested in this run. Use `--full` to reproduce all 200 entries.")
if single_demo:
    lines.extend([
        "",
        "## 6. Notes for Defense",
        "",
        "- The runnable prototype is demonstrated by `analyze-skill` on one confirmed malicious sample.",
        "- Container deployment is demonstrated by the Dockerfile and the recorded Docker status above.",
        "- Do not present `suspicious` as a final malicious conviction; present it as a risk alert with YASA and LLM findings.",
    ])
else:
    lines.extend([
        "",
        "## 6. Which File Should I Show?",
        "",
        "- Primary report for defense: `core_detection_report.md`",
        "- Full terminal log: `demo.log`",
        f"- Single-skill raw verdict: `{single_output_name}/verdict.json`",
        f"- LLM runtime findings: `{single_output_name}/feedback_loop.json`",
        f"- YASA operand resolutions: `{single_output_name}/operand_resolutions.json`",
        "- Mini benchmark summary: `eval_mini/summary.md`",
        "",
        "## 7. Notes for Defense",
        "",
        "- The runnable prototype is demonstrated by `analyze-skill` and `run-eval`.",
        "- Container deployment is demonstrated by the Dockerfile and optional `--docker-build` run.",
        "- Detection results are stored as JSON artifacts: `verdict.json`, `feedback_loop.json`, `operand_resolutions.json`, and `eval_*.json`.",
    ])
content = "\n".join(lines) + "\n"
(output_dir / "core_detection_report.md").write_text(content, encoding="utf-8")
(output_dir / "delivery_report.md").write_text(content, encoding="utf-8")
print(output_dir / "core_detection_report.md")
PY

if [[ "$SINGLE_DEMO" == "1" ]]; then
  section "8. Core outputs"
else
  section "11. Core outputs"
fi
echo "Primary detection report:"
echo "  $CORE_REPORT"
echo
echo "Raw findings files:"
for file in \
  "$OUTPUT_DIR/$SINGLE_OUTPUT_NAME/verdict.json" \
  "$OUTPUT_DIR/$SINGLE_OUTPUT_NAME/feedback_loop.json" \
  "$OUTPUT_DIR/$SINGLE_OUTPUT_NAME/operand_resolutions.json" \
  "$OUTPUT_DIR/eval_mini/summary.md" \
  "$OUTPUT_DIR/eval_mini/eval_${DEMO_VARIANT}.json"; do
  if [[ -f "$file" ]]; then
    echo "  $file"
  fi
done
echo
echo "Full logs:"
echo "  $LOG_FILE"
echo "  $COMMAND_LOG_DIR/"

echo
echo "${GREEN}[OK]${RESET} Reproduction demo finished."
echo "Output dir: $OUTPUT_DIR"
echo "Log file:   $LOG_FILE"
echo "Report:     $CORE_REPORT"
