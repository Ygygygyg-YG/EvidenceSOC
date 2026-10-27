# Task13 补充整改：空计划处理与验证（2026-10-27）

本次对应补充整改任务 E，执行用户“先完善后验证再进入真实计时”的选择。对象仍为新176行 B2/B3 补充回归的准备工作；没有恢复旧704行实验，没有重跑原36个分析槽。原冻结4953、旧登记、实际失败和模型费用保持原字节。真实完整六分支计时仍为 **0/3**。

## 已确认的原始事实

10月26日第一次实际规划收到 HTTP200、有效结构和正常结束标识，模型原文为 `{"response_plan":null}`。原产品正常进入 manual_review；旧 E worker 因缺少实际待审批计划而失败。模型没有给出理由，因此不能将原因认定为目标不存在、证据不足、额度、超时或时钟错误。该次物理请求0.013663元；最新旧结果审计记录的开发合计为0.34352132元。

历史事实及边界保存于 `data/task13/supplements/task13-repair-202610-v2/development/e2-candidate-20261026-6b2d8520/activation/evening-plan1-failure-audit-20261026.json`。原槽不得重放；旧4953替补提案未授权，不覆盖当前源码、schema或提示词。

## 修补后的行为

1. `ResponseOutput` 增加可选 `no_plan_reason`。非空原因原样保存为未经验证的模型陈述；缺省、空串或空白记录为缺失。旧合法 null 仍只算一次 valid，不因缺理由重试或调用 fallback。产品检查点及 AgentRun 审计保存原因与缺失标识；有计划及提前退出时清除遗留值。
2. 新 shared verifier 重新核对原分析、七个封印字段、实际 started claim 的 provenance、最后 valid 响应与唯一物理账本、原始 null 内容和理由、完整请求/HTTP body。worker 另查真实 checkpoint 已终止、Incident 为 manual_review、实际计划表零行。全部保存、关闭与清理成功后才能报告 no_plan；不保留资源，不创建 case-resource。
3. host 独立核验原 stdout、模型身份和工件后保存 blocked。重开同槽返回原终态，后续槽不写 start/claim、不发请求；read/decision/trial 不创建批准或计时活动。无候选不增加三次计时完成数。
4. 原业务错误先保存，检查点关闭、服务关闭、环境清理错误分别追加。四个双故障负例先失败后通过；输出只含阶段、类型和类别，失败不会升级为 no_plan 成功。
5. 来源兼容仅消去本次确切可选说明字段及限定位置语句，其余整模块 AST、引用、目标和固定 scope 校验保留。原 Python 仅解析不执行。新的来源包另行导出，原114个非manifest文件逐字节相同，旧 manifest 不覆盖。

这些修补提高可解释性和终态可靠性，不保证模型以后一定给出计划或原因，也不证明 unknown 率下降。

## 验证证据

所有路径均位于主工作区 `D:/传智杯`，不是旧冻结目录中的修改。

- 产品相关七组175项通过；实际录制 null 离线回放通过，保留原工件，无新增发送。回执：`data/task13/supplements/task13-repair-202610-v2/audit/no-plan-product-recorded-replay-20261026.json`。
- worker、host 与 shared verifier 三组139项通过；格式化后四项双故障再次通过。报告：`.tmp/task13-null-preserve-errors-report-20261027.md`。
- 严格 AST 兼容19项通过，两个独立发现的位置约束缺口关闭。最终来源包：`audit/analysis-portable-slot9-no-plan-20261027-0677b8a8`；manifest SHA256 `cdb3d98bc1a9be90dedba6a24b6ab68beb0561097286947cf4fa451a1ca197cc`。刷新回执：`audit/no-plan-analysis-package-refresh-final-20261027.json`，以上 audit 路径以本活动根目录为前缀。
- 免费真实 PostgreSQL/OpenSearch/MCP/graph 验收三种原因情况，3通过、关键跳过0。实际 checkpoint、Incident、Respond AgentRun、零计划与零批准均核对，三组临时库和索引由生产路径自动清理；全部339份 Python 源码前后哈希一致。回执：`audit/no-plan-live-final-20261027-5493b6f0/summary.json`。模型、PID、源导出和预算预检使用明确的合成注入；本项不替代实际容器预检、真实模型发送或用户批准。
- 独立源码审查 closed，待处理 Critical/Important 为0，精确18份文件摘要及证据 pin：`.tmp/task13-null-final-review-20261027.json`。该结论只表示源码问题关闭，不替代其他验收。
- 最终19组联合回归636通过、0失败、0错误，耗时325.70秒；339份Python源码前后哈希一致。回执：`audit/no-plan-joint-20261027T011138Z-ae5631b1/receipt.json`。Windows缺少原生符号链接权限导致1项跳过，该项目在后续Linux验收补验。前一轮 `no-plan-joint-20261026T163936Z-9248963c` 被中断，没有完成回执，不能作为通过证据。
- 新源码的 committed Linux 最小导出导入及新候选确认单尚待联合验证后完成。19份本次 Python 文件 Ruff check、format check 与 git diff --check 通过。

## 下一阶段与授权

当前阶段新增付费请求、真实批准和计时信用均为0。最终源码验证后才准备全新的具体发送确认单；其数据范围仍为原第9槽单一 AIT 案例，原分析、证据与知识不改写。新批次需要新的具体确认、epoch2和三个新槽，旧批次两个未用槽不追加执行；发送确认也不批准任何具体处置计划。

随后在已约定北京时间19:00–00:00、用户实际可参与时逐份生成、展示、批准并完成三次六分支计时。保留1800秒TTL，用真实最大完整耗时 M 验证 `remaining > 1.5*M+300`。完成后才固定补充正式回归版本与证据，并办理176行的独立具体出站确认。F8与16个人工复核槽属于后续补充工作，不由本次工程修补追认完成。
