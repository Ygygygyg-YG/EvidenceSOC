# Task13 人工复核实现与验证

实现位置：`evals/review.py`，共享引用遍历位于 `evals/metrics/evidence.py`。固定 `Random(42)`，在 AIT、DEDALE 各抽取两个攻击案例和两个正常案例；八个底层案例均保留八组，共 64 个预注册槽位。另用固定种子 42 对全部槽位生成 `presentation_order`，在报告产生前随计划封存。复核者固定为 `user`，时间窗口为上海时间 `19:00–00:00`。

复核对象是完整、封存的报告。`_report` 支持评分行中的 `diagnosis`（裸 Diagnosis 或图快照）和运行器的 `result.diagnostic_snapshot`；同时存在时，以实际封存快照为准。`report_sha256` 对完整对象计算，包含原始 `origin`、`classification`、`attack_steps`、原生 `claims`、证据、知识及封存信息。改变原始步骤的描述或发生时间、溯源、分类或原生主张后，旧复核不能再次导入。

`report_claims` 保留规范化诊断的原生主张与类型化结论，并逐项列出原始快照溯源、分类和攻击步骤中的非空字段。步骤描述、发生时间、技术编号等均进入人工判断集合。外层原生主张使用 `snapshot:` 前缀，类型化事实使用 `typed:snapshot.` 路径，避免与规范化诊断中的同名主张混淆。列举过程仅使用结构化字段，不调用模型、不生成判断。

`report_citations` 和证据指标共用 `ordered_citations`：先按既有规范顺序遍历规范化诊断，再遍历原快照的顶层引用、溯源、分类、攻击步骤及原生主张；去重后前五条必须逐条提供人工相关性判断。证据有效率按全部实际引用计数，P@5 沿同一顺序使用人工判断，UCR 只统计导入的人工主张判断；没有人工复核时语义结果仍为空。内外两层显式证据摘要都必须与可信注册表相符，跨案例证据不算有效。导入还要求全部实际主张恰好判断一次、每条主张有状态与来源依据、时区明确的复核时间，以及一致的计划哈希、槽位和案例绑定。无报告或无事实时保留客观原因，不计为完成语义复核。

盲包不包含行、组或模型字段，按预注册置换呈现，避免按案例和固定组次序展示；保留本案例证据注册表、原始事实文本及引用。`reviewed_at`、`relevance` 和人工判断均为空。组织者保管控制侧映射。导出和导入均校验呈现顺序完整覆盖 64 个槽位，不允许缺失、重复或新增槽位。

本次修改复核、完整报告证据引用遍历及对应回归测试；诊断分类和攻击链仍使用规范化诊断。未调用模型、提交代码或运行真实数据。实际人工复核仍由用户完成。

2026-10-19 红绿验证：完整报告复核先得到 `9 failed, 7 passed`；完整报告证据指标先得到 `5 failed, 19 passed`；呈现顺序先得到 `6 failed, 16 passed`。分别覆盖原始报告哈希与事实遗漏、原始引用计数/P@5/摘要约束、预注册置换缺失和篡改。最终执行：

```powershell
& 'D:\传智杯\services\backend\.venv\Scripts\python.exe' '.tmp\pytest_inherited.py' 'evals\tests\test_metrics.py' 'evals\tests\test_review.py' -q -p no:cacheprovider --basetemp 'D:\传智杯\.tmp\task13-review-order-green1'
# 46 passed in 0.69s

& 'D:\传智杯\services\backend\.venv\Scripts\ruff.exe' check evals/review.py evals/tests/test_review.py evals/metrics/evidence.py evals/tests/test_metrics.py
# All checks passed!
```
