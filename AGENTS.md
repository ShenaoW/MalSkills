# 仓库指南

## 项目结构与模块组织
`PLANS.md` 是总路线图；架构、taxonomy 或 benchmark 目标变化时必须同步更新。`.ralphy/` 保存本项目的长时运行工作流：`.ralphy/config.yaml` 定义规则与命令，`.ralphy/prd/` 维护任务队列。目录组织应按**方法阶段**划分，而不是按“静态分析 / 大模型 / 形式化组件”划分：`skillguard/evidence/` 负责 evidence fact extraction，其中再细分 Semgrep 与 LLM 子模块；`skillguard/primitive/` 负责 object identity analysis 与 primitive facts compilation，其中包含 YASA 接入和对象绑定逻辑；`skillguard/reasoning/` 负责基于 Datalog 风格规则的恶意模式推理与 Souffle 导出。公共编排与数据结构保留在 `skillguard/*.py`。规则文件位于 `rules/semgrep/`、`rules/yasa/` 和 `rules/skillguard.dl`；实验放在 `experiments/`，测试放在 `tests/`。

## 构建、测试与开发命令
- `python3 -m skillguard.cli analyze-skill <path> --output <dir>`：运行完整分析流程并输出 JSON/证明产物。
- `python3 -m skillguard.cli analyze-skill <path> --output <dir> --reasoning-mode formal`：仅运行形式化推理。
- `python3 -m skillguard.cli analyze-skill <path> --output <dir> --reasoning-mode llm`：仅运行 LLM 推理。
- `python3 -m skillguard.cli run-eval --benchmark <file> --output <dir> --variant full`：执行完整 benchmark 评估。
- `python3 -m skillguard.cli run-eval --benchmark experiments/benchmark_study/malicious_200_seed1337.json --output <dir> --variant benchmark_full`：复现当前 malicious-200 召回率 gate。
- `./ralphy/ralphy.sh --codex --prd .ralphy/prd/`：推荐的长期自动执行入口。
- `python3 -m py_compile experiments/run_benchmark_study.py skillguard/*.py skillguard/evidence/*.py skillguard/primitive/*.py skillguard/reasoning/*.py tests/*.py`：快速语法检查。
- `pytest -q tests/test_yasa_object_binding.py`：YASA object-binding 最小回归测试。

## 编码风格与命名规范
所有的编程任务中的目录，文件名、变量和注释都使用英文。使用 4 空格缩进、Python 3.9+、类型标注和 dataclass 风格记录。函数/模块使用 `snake_case`，类使用 `PascalCase`。Primitive subtype、evidence subtype 和规则标识都必须与当前 taxonomy 保持一致，例如 `outbound_connection`、`private_key_or_api_key_access`、`R8_DYNAMIC_SINK`。术语上优先使用 `evidence facts`、`primitive facts` 和 `object graph`，避免把中间层重新写回成模糊的“告警”或“黑盒标签”。新增结构化检测优先落在 `rules/semgrep/` 或 `rules/yasa/`，不要重新引入手写 regex 扫描器。

## 测试规范
测试文件命名为 `test_<behavior>.py`。优先在 `tmp_path` 下使用数据集中的真实skill，并断言 evidence facts、primitive facts、verdict、Souffle facts 和 proof chain。若静态分析行为发生变化，测试必须证明结果来自 Semgrep 或 YASA；若大模型提取行为变化，测试应覆盖 evidence fact schema 和与静态层的同构输出。可选依赖使用 `pytest.mark.skipif` 保护。

## 安全与配置说明
Semgrep 与大模型共同构成 `evidence fact extraction` 阶段：二者并行分析全部 artifact，并输出同一 schema 的 evidence facts。`evidence` 输出只保留原始敏感操作命中，不在该阶段推导派生属性。YASA 不属于“快速扫描阶段”，而属于 `object identity + primitive compilation` 阶段，用于补充对象绑定、参数角色和对象同一性。当前 YASA 主输出为 `object_binding / parameter_binding`，而不是旧的 `taint_flow`。benchmark 变体中的 `benchmark_full` 现在会启用 YASA、cross-artifact resolution 与 hybrid reasoning，跑的是当前主链路。输出物中应区分 `evidence.json`、`primitive_support_evidence.json` 与 `all_evidence.json`。本仓库目前不是 Git worktree，因此 Ralphy 默认应使用顺序 PRD 模式，而不是并行 worktree/branch 模式。

## 提交与评审说明
当前目录已是 Git 仓库，建议采用“小步提交 + 基线分支 + 实验分支/worktree”的方式推进。推荐把 `main` 作为稳定基线，把单个规则、schema 或实验改动放入 feature branch。提交信息建议使用祈使式、带范围的标题，例如 `evidence: 增加 markdown 下载器规则` 或 `reasoning: 收紧 capability mismatch 推理`。评审说明应包含：修改动机、影响的模块/规则、执行过的测试命令，以及关键输出路径。
