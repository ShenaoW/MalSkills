# AST 项目计划

## 题目
面向恶意 Agent Skill 的 Neuro-Symbolic + Formal 检测系统

## 工作原则
- 在 artifact、benchmark 脚本和实验结果达到本文件里程碑之前，不停止推进。
- 如果系统架构、primitive taxonomy、benchmark 目标或工作流发生变化，必须立刻更新 `PLANS.md`。
- 如果仓库结构、命令入口或协作方式变化，必须同步更新 `AGENTS.md` 与 `.ralphy/` 工作流说明。
- 本项目坚持 `primitive-first`：不直接把系统设计成“恶意/良性黑盒分类器”，而是先刻画 capability boundary，再做可解释推理。

## 一句话目标
构建一个以 Capability Primitive 为统一抽象的恶意 Skill 分析系统：先从异构 artifact 中提取统一 schema 的 `evidence facts`，再进行对象身份分析和 `primitive facts` 编译，最后通过 Datalog 风格规则推导恶意模式、解释链和最终 verdict。

## 系统契约
- **输入**：单个 skill 目录或 benchmark 条目
- **Evidence Facts 层**：Semgrep 与大模型并行产生的统一 schema 事实
- **Primitive Facts 层**：带对象绑定关系、参数化和 provenance 的 primitive facts
- **输出层**：二元风险标签、多标签恶意模式、触发规则、证明链、评测指标

## 当前硬目标
- **首要指标**：恶意样本召回率
- **当前 gate**：固定随机 200 个恶意样本，召回率必须 `>= 95%`
- **静态后端**：`Semgrep` 负责 parsing-based 快速扫描；`YASA` 负责 primitive compilation 阶段中的细粒度流/参数分析
- **模型后端**：优先通过本地的codex，claude code的coding agent的cli来分析，备选方案是用在线模型的chat
- **形式化后端**：Python 规则推理 + Souffle facts 导出

### 最新检查点
- `experiments/benchmark_study/malicious_200_seed1337.json`：当前固定种子恶意子集
- `experiments/benchmark_study/malicious_200_heuristic_eval.json`：当前恶意召回率门槛结果，`n=200` 时达到 `97.5%`
- 当前剩余问题主要集中在未覆盖恶意模式与超大仓库带来的超时成本，而不是 recall gate 失败

---

## 1. 问题定义

### 核心主张
Skill 安全分析的起点不应该是“它是否恶意”，而应该是“它到底能做什么”。系统围绕这一点展开：

1. 用统一的 `evidence facts` 描述代码、配置、自然语言中的安全相关直接结果；
2. 用对象身份分析把这些结果编译成 object-centric `primitive facts`；
3. 用形式化规则推导组合风险，并输出可解释结论。

### 威胁模型
默认攻击者可以控制 Skill 发布包中的任意制品。

#### 纳入分析的制品
- 自然语言说明：`SKILL.md`、`CLAUDE.md`、system prompt、setup 文档
- 代码：`js/ts`、`python`、markdown code fence 中的嵌入代码
- 配置与清单：`json`、`yaml`、`.env`、`.mcp.json`、settings
- 安装与启动链路：依赖脚本、shell 片段、引导命令

#### 纳入分析的行为
- 敏感数据外传
- 凭据窃取与 secret harvesting
- downloader-installer 与远程执行链
- 隐藏指令覆盖与 prompt subversion
- 文件系统侦察
- 外部服务引导与动态 sink 注入
- 声明能力与实际能力不一致
- 危险工具权限扩张 / MCP surface expansion

#### 暂不覆盖
- 完整语义等价分析
- 纯动态状态才能观察到的行为完整性证明
- 任意运行时环境下的完全 soundness

---

## 2. 规范化架构

### 当前目标包结构
- `skillguard/evidence/`：evidence fact extraction
  - `semgrep/`：Semgrep 快速扫描与规则适配
  - `llm/`：模型分析、缓存、schema 校验、神经符号反馈
- `skillguard/primitive/`：object identity analysis 与 primitive facts compilation
  - `yasa/`：YASA 用于指针分析，解析代码API中的具体参数值
  - `llm/`：模型分析，解析异构制品中的敏感操作的具体对象，将这些对象参数化得到schema
  - `compiler/`：对象绑定、跨制品解析、primitive facts 编译
- `skillguard/reasoning/`：形式化推理、pattern 判定、Souffle 导出
- `skillguard/*.py`：ingest、公共模型、报告、CLI、评测

### 阶段 A：Ingestion
- 规范化 skill 目录，构建稳定 artifact inventory
- 优先保留 skill-surface 制品，过滤仓库噪音
- 为 artifact 分配稳定 ID、路径和元数据

### 阶段 B：Evidence Fact Extraction
- `Semgrep` 是异构 artifact 的 parsing-based 快速扫描主力，基于已知敏感操作Specification编写的rules来进行parsing-based的扫描
- 大模型分析与 Semgrep 并行运行，也面向全部 artifact 提取事实，主要是分析Semgrep覆盖不到第三方库函数和各种LOTL等技术，补充新的rules
- 所有后端统一输出同一个 `evidence fact` schema

### 阶段 C：Object Identity Analysis + Primitive Compilation
- 对 evidence facts 做对象身份分析与语义归一化
- 把低层结果编译成参数化、对象绑定的 primitive facts
- `YASA` 在这一阶段补充对代码对象的深度参数/指针/污点分析
- 大模型/CLI AGENT用于在这一阶段来分析其他异构制品的敏感操作的具体对象
- 必须保留 `artifact -> evidence fact -> primitive fact` 的 provenance
- 跨制品解析只能依赖显式事实与对象绑定

### 阶段 D：Datalog-Based Formal Reasoning
- 从 primitive facts 及其对象关系推导恶意模式
- 形式化状态与 Python 推理结果保持一致
- 最终标签必须可解释、可审计

### 阶段 E：Reporting
- 输出机器可读 JSON
- 输出人类可读解释链：
  `artifact span -> evidence fact -> primitive fact -> triggered rule -> pattern -> verdict`

---

## 3. Evidence Fact 提取设计

### 3.0 组件协同原则
当前分析链必须严格分层：

1. `skillguard/ingest.py`：发现并筛选 skill 相关 artifact
2. `skillguard/evidence/`：并行调度 Semgrep 与大模型 producer，统一提取 evidence facts
3. `skillguard/primitive/`：结合 YASA 深度分析做对象身份分析、跨制品链接与 primitive facts 编译
4. `skillguard/reasoning/`：只消费 primitive facts + object relation graph，不直接消费源码文本

这条边界必须保持稳定：
- Semgrep 与 LLM 共同负责 evidence fact extraction
- YASA 与 LLM 共同负责 primitive compilation 阶段所需的敏感操作的参数化对象分析
- LLM 同时承担语义补全、同构事实提取与规则发现
- 神经符号反馈负责把高价值模型发现沉淀为静态规则
- 组合与推理属于 primitive/formal 层

### 3.1 静态分析契约

#### Semgrep：异构 artifact 的快速 parsing-based 扫描
- 覆盖代码、配置、shell、markdown、prompt 等制品
- 语言侧优先使用 `python`、`javascript/typescript`、`json`、`yaml`
- markdown / prompt / shell block 使用 `generic` 模式
- 任何新增 parsing-based 检测，都必须沉淀为 Semgrep 规则，而不是 Python 手写扫描器

### 3.2 大模型并行提取与神经符号反馈
- 大模型分析与静态分析并行运行，而不是作为后处理补丁
- 大模型输入覆盖全部 artifact：代码、markdown、manifest、config、prompt、installer 片段
- 大模型输出必须与静态层共用同一 evidence fact schema
- 大模型不能直接输出最终恶意结论，只能输出结构化的evidence facts
- 模型发现但静态规则未覆盖的高价值模式，应尽可能固化成新的 Semgrep / YASA 规则或模板，形成 feedback loop

### 3.3 Semgrep 规则家族

#### 代码规则
- env 访问
- 文件读取 / 目录枚举
- 网络发送 / 获取
- shell 执行
- 动态加载 / import
- config reference accessor

#### 文本 / generic 规则
- 隐藏 setup 指令
- downloader-installer 片段
- markdown 中的 shell pipeline
- secret request
- 外部 MCP endpoint
- permission expansion 声明
- capability declaration 与 action description

#### 配置规则
- 外部 URL 字面量
- secret-bearing key
- 权限列表
- 工具 surface 声明
- 后续可解析为 sink 的 endpoint key/value

### 3.4 evidence fact schema 要求
分析器直接输出的是 `evidence facts`，而不是最终 primitive。每条事实至少需要：

- producer（semgrep / yasa / llm）
- artifact id / path
- span
- fact type
- object 或 parameter binding
- attributes
- confidence
- provenance

## 4. Object Identity Analysis 与 Primitive Facts 编译

### 4.1 YASA 的角色
`YASA` 不属于 evidence fact extraction 的快速扫描层，而属于 primitive compilation 阶段的深度分析组件：

- 只在代码或从 markdown / prompt 提升出来的代码块上运行
- 必须通过 `rules/yasa/` 中的项目本地规则配置驱动
- 仅适用于 `Python / JavaScript / Go / Java`
- 用于当某个敏感 API / sink 需要详细分析参数对象指向时补充深度事实
- 重点覆盖的 flow family：
  - `env/file/config -> network`
  - `env/user input -> exec`
  - `dynamic parameter -> sensitive sink`

### 4.2 模型提取约束
模型不能直接输出最终安全结论，只能输出结构化事实。

#### 执行策略
- 若本地 API / `.env` 已配置，优先使用在线模型并缓存结果
- schema 版本必须固定，所有 records 必须校验后才能进入下游
- 模型输出与静态输出必须在 primitive compilation 阶段统一融合

### 4.3 Primitive Fact 基本要求
每个 primitive fact 必须包含：
- primitive type
- parameter tuple
- operation object / object identity
- confidence
- provenance evidence IDs
- artifact paths

### 4.4 当前核心 primitive fact 家族
- `READ_FILE(path_class, sensitivity_class, source)`
- `LIST_DIR(path_class, source)`
- `READ_ENV(key_class, sensitivity_class, source)`
- `READ_CONFIG(key, value_class, source)`
- `NETWORK_SEND(dst_class, protocol, source)`
- `NETWORK_FETCH(dst_class, protocol, source)`
- `SHELL_EXEC(command_class, source)`
- `DYNAMIC_LOAD(module_source, source)`
- `REQUEST_SECRET(secret_class, source)`
- `SETUP_INSTRUCTION(intent_class, source)`
- `EMBED_HIDDEN_INSTRUCTION(intent_class, source)`
- `DECLARED_CAPABILITY(scope, implied_capabilities, source)`
- `TAINT_FLOW(flow_kind, sink_rule, source)`
- `TOOL_SURFACE_EXPOSURE(tool_class, destination_class, source)`
- `CONFIG_ENDPOINT(endpoint_class, source)`

### 4.5 恶意模式 taxonomy
- `Sensitive_Exfiltration`
- `Credential_Theft`
- `Secret_Request`
- `Remote_Code_Execution`
- `Downloader_Installer`
- `Filesystem_Recon`
- `Prompt_Instruction_Override`
- `Hidden_Setup_Trap`
- `Dynamic_Sink_Injection`
- `Capability_Mismatch`
- `Obfuscated_Execution`
- `Tool_Surface_Expansion`
- `External_Service_Bootstrap`

### 4.6 覆盖哲学
不存在一个有限 taxonomy 能对未来所有恶意行为都保持完全 sound。当前项目的实际目标是：

1. 让 primitive fact 空间显式化；
2. 将 benchmark 中出现的恶意模式投影到该空间中；
3. 对每一个新的 false negative，用规则或 taxonomy 扩展进行吸收，而不是堆叠一次性 heuristic。

---

## 5. 基于 Datalog 的形式化推理设计

### 规则族
- 跨制品 endpoint 解析
- 污点与敏感性传播
- secret request / secret exposure 推理
- capability mismatch 推理
- tool-surface expansion 推理
- downloader / bootstrap chain 推理
- 基于同一对象或关联对象的操作链推理
- 基于 pattern severity 的最终二元策略

### 二元标签策略
- `malicious`：任意高危 pattern 触发
- `suspicious`：仅中危 pattern 触发
- `benign`：否则

---

## 6. Benchmark 与实验设计

### 数据集
- `data/clawsec_malskills`
- `data/malicious_confirmed`
- `data/MaliciousAgentSkillsBench`

仅元数据条目不计入 artifact-level 指标。

### 评测切分
- **Eval-A**：随机恶意子集（`n=200`），用于 recall tuning（仅作为工具开发阶段的测试）
- **Eval-B**：confirmed malicious 全量 recall study（与Baseline工具对比恶意skills上的召回）
- **Eval-C**：mixed ecosystem false-positive study（与Baseline工具对比良性Skills上的误报，Eval-B和Eval-C共同构成论文的RQ1，即与Baseline工具的性能对比）
- **Eval-D**：消融实验：Semgrep-only / no-YASA / no-model / no-formal 等配置，具体的消融方法需要具体设计（消融实验作为论文的RQ2）

### 指标
#### 主要指标
- malicious recall
- strict malicious recall

#### 次要指标
- precision
- false positive rate
- per-pattern coverage
- throughput
- model cost

---

## 7. 执行路线图

### 阶段 1：按方法阶段重组目录
- [ ] 将现有 `skillguard/static/`、`skillguard/intent/`、`skillguard/primitives/`、`skillguard/formal/` 重构为按阶段组织的 `skillguard/evidence/`、`skillguard/primitive/`、`skillguard/reasoning/`
- [ ] 把 Semgrep 与 LLM 放入 `evidence/` 阶段目录
- [ ] 把 YASA 与对象身份分析逻辑放入 `primitive/` 阶段目录
- [ ] 清理旧的按引擎划分残留入口与导入路径

### 阶段 2：并行 evidence fact 提取升级
- [ ] 接通在线模型提取与本地 API 配置
- [ ] 统一静态层与模型层的 evidence fact schema
- [ ] 建立模型发现 -> 规则沉淀的神经符号反馈流程
- [ ] 刷新缓存 schema、测试和实验说明

### 阶段 3：primitive fact compilation 扩展
- [ ] 用 YASA 深度分析补全敏感 API 参数对象绑定
- [ ] 补充LLM/AGENT CLI来分析敏感操作的参数对象绑定
- [ ] 完善 secret requests、tool surfaces、external bootstrap、endpoint class 等 primitive fact
- [ ] 完善 pattern taxonomy 与规则覆盖

### 阶段 4：召回率调优循环
- [ ] 固定随机种子抽取 200 个恶意样本
- [ ] 跑评估
- [ ] 检查每个 false negative
- [ ] 扩展规则 / taxonomy 覆盖
- [ ] 重复直到 recall `>= 95%`

### 阶段 5：论文 / Artifact 输出
- [ ] 生成 benchmark 表格
- [ ] 生成 case study
- [ ] 生成 ablation
- [ ] 生成可解释样例输出

---

## 8. 风险与假设

### 风险
- Semgrep generic 规则如果不控制 artifact 类型和上下文，容易过匹配
- YASA 在大型仓库上可能成本高，需要 artifact 级筛选
- recall-oriented 覆盖增强可能阶段性拉高 ecosystem false positive

### 假设
- 当前优化顺序是先 recall，后 precision
- 在线模型 API 可以通过本地 `.env` 或环境变量提供
- 每个新的恶意 benchmark miss 都应该转化为 taxonomy 或规则更新，而不是一次性补丁
