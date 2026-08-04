# MalSkills Reproduction and Delivery Guide

本文档面向答辩中的“工程落地能力与标准化交付”评分项，覆盖可运行完整原型系统、容器化部署方案、可复现源码、部署文档和检测结果展示。

## 1. 答辩推荐演示顺序

建议录屏时按下面顺序展示：

1. 源码与交付物：`malskills/`、`scripts/demo_reproduce.sh`、`Dockerfile`、`docs/DEMO_REPRODUCTION.md`。
2. 环境部署：展示 `--from-scratch` 命令，必要时现场执行。
3. 容器化部署：展示 `Dockerfile` 和 `docker build` 命令，网络稳定时现场执行 `--docker-build`。
4. 检测演示：运行单个恶意样本的 YASA + LLM 完整分析。
5. 结果归档：展示 `core_detection_report.md` 和 JSON 证据文件。

## 2. 一键录屏脚本

推荐录屏命令：

```bash
bash scripts/demo_reproduce.sh --single-demo
```

该命令复用当前已部署环境，并且只对已有 Docker 镜像做 smoke run。它不会重新安装依赖，不会重新构建镜像，不跑 benchmark，只分析一个恶意样本，适合正式录屏。

正式答辩录屏建议只展示这条命令。环境部署和 Docker 构建可以在录屏前完成一次，录屏时通过脚本输出的部署状态、Docker smoke run 和核心报告证明交付链路可复现。

如果需要补充 2 样本 benchmark 演示：

```bash
bash scripts/demo_reproduce.sh --recording
```

从环境部署开始的命令：

```bash
bash scripts/demo_reproduce.sh --from-scratch --no-pause
```

该命令会创建或复用 `.venv`、安装 Python 依赖，并在 `vendor/yasa` 目录内编译 YASA，然后继续运行检测演示。安装日志默认不会刷屏，会写入输出目录的 `command_logs/`。

首次构建 Docker 镜像：

```bash
bash scripts/demo_reproduce.sh --docker-build --docker-run --skip-single --skip-mini-benchmark --no-pause
```

该命令只做容器构建与 smoke run，不跑 LLM 检测，适合在录屏前预热镜像缓存。

如果需要把“从零部署 + Docker 构建 + 检测演示”全部现场跑出来：

```bash
bash scripts/demo_reproduce.sh --from-scratch --docker-build --docker-run --no-pause
```

这条命令输出最多、耗时最长，不建议正式录屏时使用，除非必须展示完整从零部署过程。

默认输出目录：

```text
output/demo_reproduction/<timestamp>/
```

核心输出文件：

- `demo.log`：完整终端日志。
- `core_detection_report.md`：答辩时最核心的检测报告，优先展示这个文件。
- `delivery_report.md`：同 `core_detection_report.md`，保留兼容旧路径。
- `single_sample_full/verdict.json`：单样本检测结论。
- `single_sample_full/feedback_loop.json`：规则学习状态；默认关闭候选收集，只有显式传入 `--rule-store` 和 `--collect-rule-candidates` 才会调用规则规格生成器。
- `single_sample_full/analysis_metadata.json`：本次扫描加载的规则集摘要与抽取器状态。
- `single_sample_full/operand_resolutions.json`：YASA 等分析器产生的 Operand 解析与值流记录。
- `eval_mini/summary.md`：mini benchmark 汇总，仅 `--recording` 或未跳过 mini benchmark 时生成。
- `eval_mini/eval_benchmark_full.json`：mini benchmark 结构化结果，仅 `--recording` 或未跳过 mini benchmark 时生成。
- `command_logs/`：安装、Docker 构建、YASA 编译等长命令日志。

## 3. 容器化部署方案

构建镜像：

```bash
docker build -t malskills-demo:latest .
```

容器内 smoke run：

```bash
docker run --rm malskills-demo:latest .venv/bin/malskills --help
```

如果镜像已经构建过，正式录屏只需要：

```bash
bash scripts/demo_reproduce.sh --single-demo
```

使用 OpenAI-compatible API 在容器中运行完整演示：

```bash
docker run --rm \
  -e MALSKILLS_LLM_MODE=openai_api \
  -e OPENAI_API_KEY="$OPENAI_API_KEY" \
  -e OPENAI_MODEL="${OPENAI_MODEL:-gpt-5.3-codex-medium}" \
  -v "$PWD/output:/app/output" \
  malskills-demo:latest \
  bash scripts/demo_reproduce.sh --no-pause
```

说明：

- `Dockerfile` 会安装 Python、Node、项目依赖、Semgrep，并编译 YASA。
- LLM 凭据不写入镜像，通过环境变量注入。
- 如果使用本机 Codex CLI，可通过 `MALSKILLS_CODEX_CLI` 指向容器内可用的 CLI，并挂载对应认证目录。

## 4. 检测结果展示口径

答辩时优先打开：

```text
output/demo_reproduction/<timestamp>/core_detection_report.md
```

这个文件已经把工程交付、Docker 状态、单样本检测结果、mini benchmark 结果汇总在一起。
在 `--single-demo` 模式下，它只包含单样本检测结果，不包含 benchmark 指标。

单样本演示使用：

```text
data/ground_truth/malicious/clawhub/pepe276_publish-dist
```

当前工具只输出 `malicious` 和 `benign`。演示前应使用当前配置重跑样本，展示 `verdict.json` 中的二分类结果、命中 Pattern 和分析后端，不要复用旧三分类结果。

mini benchmark 使用 2 个样本：

- 良性：`ground_truth::clawhub::steipete/github`
- 恶意：`ground_truth::clawhub::pepe276/publish-dist`

已验证的典型输出：

- Entries：`2`
- Status：`ok=2`
- LLM cases：`2/2`
- YASA hit cases：`1`
- Prediction counts 只应包含 `benign` 和 `malicious`
- Precision、recall 和 F1 直接按 `malicious` 正类计算

全量 200 样本结果已经跑过，目录：

```text
output/rq1_malskills/
```

该目录中的历史结果来自旧三分类逻辑，不能代表当前二分类规则。正式报告前需要重新运行 200 样本评估；当前 precision、recall、F1 和 false-positive rate 都直接以 `malicious` 为正类计算。

## 5. 全量实验复现

重新构建 benchmark：

```bash
.venv/bin/malskills build-benchmark-index \
  --root . \
  --output output/ground_truth_final_benchmark.json
```

运行完整 200 样本评测：

```bash
.venv/bin/malskills run-eval \
  --benchmark output/ground_truth_final_benchmark.json \
  --output output/rq1_malskills \
  --variant benchmark_full
```

生成报告：

```bash
.venv/bin/malskills render-report --results output/rq1_malskills
```

一键全量复现：

```bash
bash scripts/demo_reproduce.sh --no-pause --full
```

该步骤会逐样本调用 LLM，耗时较长。答辩录屏建议展示命令和已生成报告，现场运行默认 mini benchmark 即可证明链路可运行。
