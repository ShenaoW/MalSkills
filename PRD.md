# SkillGuard 总任务清单

本文件是供 `ralphy` / `codex` 长周期执行使用的总 PRD，聚合核心分析链路与模型评估链路。执行时建议使用：

```bash
./ralphy/ralphy.sh --codex --prd PRD.md --branch-per-task --no-browser
```

## Core Analysis

- [ ] 按阶段重构目录与模块边界：统一收敛到 `skillguard/evidence/`、`skillguard/primitive/`、`skillguard/reasoning/`、`skillguard/reporting/`，避免继续按“静态分析/大模型/形式化工具实现细节”拆目录。
- [ ] 固化 `evidence facts` 的统一 Schema：覆盖异构 artifact（代码、Markdown、manifest、config、prompt、installer snippet）的来源、定位、对象引用、参数槽位、置信度、提取器来源，并保证 Semgrep 与 LLM 输出同构。
- [ ] 扩展 Semgrep 规则体系作为一阶段主力证据提取器：覆盖文件读写、环境变量读取、网络发送、shell 执行、依赖安装、动态加载、prompt/markdown 中命令片段、权限声明与 capability mismatch 等高价值模式。
- [ ] 实现 LLM evidence extractor：对全部 artifact 并行分析，补足 Semgrep 未覆盖的语义模式，并严格输出同一套 `evidence facts` Schema，而不是直接输出风险标签。
- [ ] 建立 neuro-symbolic feedback loop：把 LLM 新发现但高价值、可复用的 finding pattern 归档为候选 Semgrep 规则/提示模板，并形成“发现-固化-复用”的闭环。
- [ ] 在二阶段实现 object identity analysis：引入 YASA 作为代码级细粒度 taint / pointer / alias 分析后端，对 Semgrep/LLM 标出的可疑代码块继续做参数指向、对象绑定、source-to-sink 关系解析。
- [ ] 为 YASA 建立项目内规则与配置体系：优先支持 Python / JavaScript / Go / Java，并明确如何处理 Markdown 中提取出的代码片段与仓库内脚本文件。
- [ ] 引入 LLM primitive-side normalizer：在 YASA 无法覆盖、代码不完整、跨 artifact 引用不透明时，辅助做对象语义归一、跨制品对象链接与 primitive 参数补全，但输出仍必须受 Schema 约束。
- [ ] 完成 `primitive facts` 编译：把一阶段 `evidence facts` 与二阶段对象绑定/污点结果编译成规范化 primitive，例如 `READ_ENV(key_class, object)`、`READ_FILE(path_class, object)`、`NETWORK_SEND(dst_class, object)`、`DYNAMIC_LOAD(src_class, object)`。
- [ ] 设计完善的 malicious capability / primitive taxonomy：确保 primitive 集合和参数维度足够 sound，可覆盖 secrets exfiltration、downloader-installer、dynamic sink injection、hidden instruction override、capability mismatch、indirect config sink 等主要恶意模式。
- [ ] 构建 Datalog / Souffle 规则引擎：对 `primitive facts` 与对象同一性关系进行组合推理，输出 malicious pattern、触发规则、对象链路与可审计 proof chain。
- [ ] 输出面向论文 artifact 的中间产物：保存 evidence JSON、primitive JSON、Souffle facts、rule trace、最终 verdict 与代表性 case study 目录，便于实验复现与论文插图。

## Model And Eval

- [ ] 建立论文评估所需 benchmark 清单与元数据：区分 confirmed malicious、mixed ecosystem、benign-only、ablation 子集，并固定随机种子、样本来源、标签准则与 artifact 完整性检查流程。
- [ ] 先在全部 1000+ 恶意样本中随机抽取 200 个恶意样本作为快速迭代集，固定种子并保存抽样清单，作为当前 recall gate。
- [ ] 以 `malicious_200` 作为 Eval-A：持续优化 Semgrep 规则、YASA 配置、LLM prompt / schema、primitive taxonomy 与 Datalog 模式，直到召回率达到并稳定超过 95%。
- [ ] 在达到 200-sample gate 后，扩展到全部已确认恶意样本作为 Eval-B，验证 full malicious recall、失败模式与长尾攻击类型覆盖情况。
- [ ] 构建 Eval-C mixed benchmark：混合恶意与良性 skill，报告 precision / recall / F1 / FPR，并对比基线（仅 Semgrep、仅 LLM、无对象绑定、无 formal reasoning）回答论文 RQ1。
- [ ] 构建 Eval-D ablation：至少覆盖 `-LLM evidence`、`-YASA object analysis`、`-feedback loop`、`-formal reasoning`、`heuristic reasoning only`，回答论文 RQ2 / RQ3。
- [ ] 单独评估 neuro-symbolic feedback 的贡献：统计 LLM 发现并成功沉淀为静态规则的 pattern 数量、后续命中次数、对 recall/throughput 的增益。
- [ ] 单独评估 object-centric primitive compilation 的贡献：对比“只看敏感操作共现”与“要求同一 object / linked object”的差异，展示误报下降和解释性提升。
- [ ] 单独评估 formal reasoning 的解释能力：输出规则触发链、对象绑定链、primitive 组合链，并整理为论文中的 case study 表格与图示。
- [ ] 系统性记录运行代价：Semgrep 时间、YASA 时间、LLM 调用次数/成本、Datalog 推理时间、单样本总时延，并分析可扩展性。
- [ ] 建立自动化评测脚本：一键运行 benchmark、导出 JSON/CSV、生成聚合表格与论文所需图表源数据。
- [ ] 固化当前阶段的回归门槛：任何后续改动都至少不能低于 `malicious_200` 上的 95% recall 目标，并保留代表性失败样例用于持续分析。

## Deliverables

- [ ] 生成可直接运行的端到端 artifact：输入 skill 目录，输出 evidence facts、primitive facts、Datalog 推理结果、proof chain 与 verdict。
- [ ] 生成可复现实验脚本与结果汇总：覆盖主实验、消融实验、case study、运行时统计。
- [ ] 生成论文写作所需素材：系统图、taxonomy 表、benchmark 统计表、主要结果表、case study 证据链展示。
- [ ] 在 `AGENTS.md`、`PLANS.md` 与 `.ralphy/` 配置中保持与本 PRD 一致，确保长期任务执行与人工开发遵循同一 methodology。
