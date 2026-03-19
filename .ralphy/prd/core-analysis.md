## 核心分析任务

### A. 按方法阶段重组目录
- [ ] 将仓库目录从按“静态分析 / 大模型 / formal”划分，改成按方法阶段划分。
- [ ] 建立 `skillguard/evidence/`，统一承载 `Semgrep + LLM` 的 evidence fact extraction。
- [ ] 建立 `skillguard/primitive/`，统一承载 `YASA + LLM` 的 object identity analysis 与 primitive facts compilation。
- [ ] 建立 `skillguard/reasoning/`，统一承载 Datalog 推理、pattern 判定与 Souffle 导出。
- [ ] 更新 pipeline、CLI、tests、实验脚本中的导入路径与模块边界。

### B. Evidence Fact Extraction 统一化
- [ ] 把当前文档、实现和测试中的术语统一为 `evidence facts` 与 `primitive facts`。
- [ ] 明确 `Semgrep` 与 `LLM` 是并行的 evidence fact producer，而不是前后补丁关系。
- [ ] 让 `Semgrep` 与 `LLM` 输出保持同一个 evidence fact schema。
- [ ] 明确 evidence fact 的必要字段：producer、artifact、span、fact type、binding、attributes、confidence、provenance。
- [ ] 让代码、markdown、prompt、manifest、config、installer 片段都能进入统一 evidence fact 提取流程。

### C. Semgrep 快速扫描扩展
- [ ] 为 markdown / prompt 中的 setup、下载器、secret 请求补充更细的 generic 规则。
- [ ] 为 config 中的 endpoint、permission、tool surface 补充更细的结构化规则。
- [ ] 为 JS / Python 中的 config reference、dynamic load、危险 sink 补充规则。
- [ ] 将新增 parsing-based 检测优先固化到 `rules/semgrep/`，避免回退到 Python 手写扫描器。
- [ ] 每新增一类规则，都补一个 `tests/test_extractors.py` 回归样例。

### D. LLM Evidence Fact 提取与反馈
- [ ] 让 LLM 对全部 artifact 并行分析，而不是只分析自然语言说明。
- [ ] 让 LLM 输出只包含结构化 evidence facts，不直接输出最终恶意结论。
- [ ] 覆盖 Semgrep 难以处理的第三方库函数、LOTL、语义伪装和文档/实现不一致场景。
- [ ] 识别模型发现但静态规则未覆盖的高价值 evidence facts。
- [ ] 为可复用模式生成新的 Semgrep 规则草案，形成 neuro-symbolic feedback。

### E. YASA 深度对象分析接入
- [ ] 明确哪些敏感 API / sink 需要 YASA 做参数与对象指向分析。
- [ ] 让 YASA 仅在 `Python / JavaScript / Go / Java` 代码对象上运行。
- [ ] 支持对 markdown / prompt 中提升出的代码片段按语言选择性调用 YASA。
- [ ] 明确 YASA 的输出如何进入 primitive compilation，而不是混入 evidence 快速扫描层。
- [ ] 为每个 YASA 规则补对应的参数解析与 flow 断言测试。

### F. Object Identity Analysis 与 Primitive Facts 编译
- [ ] 细化对象身份分析逻辑，明确何时两个操作作用于同一 logical object。
- [ ] 明确跨制品对象连接条件，如 `config_value -> config_ref -> network_send/fetch`。
- [ ] 让 `YASA + LLM` 在这一阶段共同补全敏感操作的参数对象绑定。
- [ ] 增加对 tool surface、endpoint class、secret class 的参数化映射。
- [ ] 把 primitive 表示收敛为 object-centric primitive facts。
- [ ] 保证 graph edge 能完整体现 `contains`、`supports`、`resolved_from`、`same_object` 等关系。
- [ ] 增加 graph 的可视化导出能力，例如 `.dot` 输出。

### G. 基于 Datalog 的形式化推理增强
- [ ] 收紧 `Dynamic_Sink_Injection` 推理条件，减少误报。
- [ ] 完善 `Capability_Mismatch` 的 declared vs actual capability 比较逻辑。
- [ ] 增强 `Tool_Surface_Expansion` 与 `External_Service_Bootstrap` 规则覆盖。
- [ ] 让规则显式利用同一对象或关联对象上的操作链，而不只看 primitive 共现。
- [ ] 让 pattern 解释链稳定输出 `evidence fact -> primitive fact -> rule -> pattern -> verdict`。
- [ ] 为每个新增/修改的 pattern 补一个 `tests/test_pipeline.py` 端到端样例。

### H. 回归、解释性与 artifact 输出
- [ ] 对每个新增 primitive fact family 增加 `evidence fact -> primitive fact` 断言测试。
- [ ] 对每个新增 malicious pattern 增加 `primitive fact -> pattern -> verdict` 断言测试。
- [ ] 确保输出中的 graph、facts、verdict 能直接支持论文里的解释样例。
- [ ] 固化代表性案例的中间产物路径，便于 benchmark、artifact 和论文复用。
