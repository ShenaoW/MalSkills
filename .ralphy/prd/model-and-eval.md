## 模型与评测任务

### A. 模型后端接入与可复现配置
- [ ] 接通在线模型分析，并明确读取哪些环境变量；优先支持本地 `Codex CLI / Claude Code CLI`，备选为在线模型 API。
- [ ] 明确 evidence fact extraction 阶段与 primitive compilation 阶段中 LLM/CLI agent 的调用边界。
- [ ] 保持缓存可复现：同一 artifact + schema + backend 命中同一缓存文件。
- [ ] 在 README 或实验说明里写清最小配置方式、缓存位置和失败回退策略。
- [ ] 让模型输出覆盖代码、markdown、manifest、config、prompt、installer 片段等全部 artifact。

### B. Eval-A：malicious-200 开发 gate
- [ ] 固定随机种子抽取 200 个恶意样本，作为方法开发阶段的快速 gate。
- [ ] 每次 evidence fact schema、Semgrep、LLM、YASA、primitive facts 编译或 formal 规则变动后，重新跑 malicious-200 gate。
- [ ] 记录 false negative，并把 miss 映射到缺失 evidence fact、primitive fact 或 pattern。
- [ ] 在 recall 低于 95% 时，优先修覆盖，不先做 benign precision 微调。
- [ ] 保持 `>=95%` 作为开发阶段 benchmark floor。

### C. Eval-B：confirmed malicious 全量召回研究
- [ ] 在 `data/malicious_confirmed` 与其他可分析恶意数据上构建 confirmed malicious 全量评测集。
- [ ] 选取并复现 `baseline/` 中可运行的基线工具。
- [ ] 对比本方法与 baseline 在恶意 Skills 上的 `malicious recall`、`strict malicious recall`、`per-pattern coverage`。
- [ ] 输出论文 RQ1 的恶意侧结果表格，并保留原始结果 JSON。

### D. Eval-C：mixed ecosystem 误报研究
- [ ] 构建 mixed ecosystem / representative benign 样本集。
- [ ] 对比本方法与 baseline 在良性 Skills 上的 `precision`、`false positive rate`。
- [ ] 输出 false positive case list，并说明触发的 evidence fact / primitive fact / pattern。
- [ ] 将 Eval-B 与 Eval-C 合并整理为论文 RQ1：与 baseline 的总体性能对比。

### E. Eval-D：消融实验设计与执行
- [ ] 设计论文 RQ2 的消融配置，而不仅是简单关闭模块。
- [ ] 至少覆盖：`Semgrep-only`、`no-YASA`、`no-model`、`no-formal`，并按当前方法学解释每个消融对应移除了哪一阶段能力。
- [ ] 记录各消融在召回、误报、runtime、cost 上的变化。
- [ ] 输出 paper-ready 的 ablation 表格与图例说明。

### F. 运行时、成本与扩展性
- [ ] 统计不同评测配置下的 throughput。
- [ ] 统计模型调用成本与缓存命中收益。
- [ ] 记录 YASA 在大型仓库上的额外开销，并评估 selective invocation 策略。
- [ ] 形成 runtime / cost 的实验小节素材。

### G. Case Study 与解释性产物
- [ ] 固化代表性 case study 的中间产物路径。
- [ ] 为每个案例保留完整链路：`artifact -> evidence fact -> primitive fact -> rule -> pattern -> verdict`。
- [ ] 至少准备一例配置文件间接 sink 注入、一例文档/实现不一致、一例对象链外传的代表性案例。
- [ ] 生成可直接放进论文 artifact 或 appendix 的解释样例。

### H. 论文与 artifact 输出
- [ ] 让 `experiments/run_benchmark_study.py` 输出稳定目录结构。
- [ ] 生成 paper-ready 表格：RQ1 对比、RQ2 消融、runtime、cost。
- [ ] 对每个 benchmark miss 写出“暴露了什么 evidence fact / primitive fact / pattern gap”的简要记录。
- [ ] 整理实验复现实验脚本、结果目录与说明文档，满足 artifact 提交要求。
