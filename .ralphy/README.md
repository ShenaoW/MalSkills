# SkillGuard 的 Ralphy 工作流

本目录把本地 `ralphy/` 项目适配到了 SkillGuard。执行时以 `.ralphy/config.yaml` 为规则源，以 `.ralphy/prd/` 为长期任务队列。

## 推荐模式

当前仓库不是顶层 Git worktree，因此默认使用**顺序 PRD 模式**，不要优先开启 `--parallel` 或 `--branch-per-task`。

```bash
./ralphy/ralphy.sh --codex --prd .ralphy/prd/
```

## 推荐任务粒度

- 单个 evidence fact producer 的局部增强
- 单个 primitive fact 编译逻辑的局部增强
- 单个 pattern / rule 的局部增强
- 单个评测脚本或单组 benchmark 输出改进
- 单个文档同步任务（如更新 `PLANS.md` / `AGENTS.md`）

不推荐把“重构整个系统”作为一个任务直接交给 Ralphy，而是拆成多个 micro-task。

## 常用运行方式

- 执行 backlog：`./ralphy/ralphy.sh --codex --prd .ralphy/prd/`
- 执行单一任务：`./ralphy/ralphy.sh --codex "收紧 Dynamic_Sink_Injection 推理规则"`
- 禁用浏览器：`./ralphy/ralphy.sh --codex --prd .ralphy/prd/ --no-browser`

如需向底层引擎追加参数，使用 `--`：

```bash
./ralphy/ralphy.sh --codex --prd .ralphy/prd/ --no-browser -- --full-auto
```

## 期望执行流程

1. 从 `.ralphy/prd/` 里挑选下一个未完成任务
2. 尽量用最小改动完成当前 micro-task
3. 运行配置中的语法检查 / 测试命令
4. 若架构、工作流或 benchmark 目标变化，更新 `PLANS.md`、`AGENTS.md`
5. 不手工编辑 `.ralphy/progress.txt`，该文件由 Ralphy 维护

## 适合本项目的执行策略

- 先把目录和模块收敛为按阶段组织，而不是按引擎组织
- 再做 evidence facts 提取层和规则层的低耦合改动
- 然后做对象身份分析与 primitive facts 编译
- 再做 Datalog 推理与 benchmark gate
- 最后整理论文产物与案例输出
