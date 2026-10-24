# Task13 评估入口

Task13 的协议、控制器、隔离 worker、独立评分、人审导入和图表生成已实现。本次工程验证没有运行正式的 **704 行**实验，没有正式模型分数，也没有完成 G6/G7。配置种子保持未冻结；单元测试、fixture、工作树 Linux 导入或合成服务验证均不能代替真实模型 worker 的 G4 验收。

总模型预算为 CNY100，开发子预算不超过 CNY15，共用一个持久化 campaign account。失败、重试、独立验证和授权重跑均计费。人工复核者为 `user`，上海时间 `19:00–00:00`；时间窗口本身不表示审批。

## 资料与实现

| 内容 | 入口 |
|---|---|
| 预注册矩阵、指标、预算和 G1–G7 | [protocol.md](../docs/evaluations/protocol.md) |
| 真实输入配置、生成冻结草案、完整开发命令 | [configs/README.md](configs/README.md) |
| worker 隔离、不可变尝试、重跑与运行证据 | [运行器说明](../docs/evaluations/task13-runner-implementation.md) |
| 图、诊断和能力边界 | [后端说明](../docs/evaluations/task13-backend-implementation.md) |
| 人工抽样、盲包、64 个复核槽位与导入约束 | [人工复核说明](../docs/evaluations/task13-human-review.md)、[review.py](review.py) |
| F8 审批、过期计划续期、独立成对实验 | [verification.py](verification.py)、[verification_worker.py](adapters/verification_worker.py) |
| 指标分母、缺失值与图表解释 | [指标与图表说明](../docs/evaluations/task13-metrics-implementation.md)、[plots/generate.py](plots/generate.py) |

AIT 使用已接受的 `.backups/task12-readiness/data/ait/cases/test` 中 22 个中性案例；DEDALE 使用 `data/dedale/priority-cases-v4/test` 中 66 个案例。两者各跑八组，分别报告，不合并成一个总分。原 Task12 数据和验收记录保持不变。

## 最少工作流程

在仓库根目录使用后端 Python 环境。检查和生成计划不会调用模型：

```powershell
$task13Python = 'services/backend/.venv/Scripts/python.exe'
& $task13Python -m evals.runners.cli --help
& $task13Python -m scripts.task13_worker_runtime --help
& $task13Python -m pytest evals/tests -q --basetemp data/task13/pytest-check-new
```

受管 Windows 沙箱若不能读取 pytest 的 `0700` 临时目录，可使用本工作区已有的 `.tmp/pytest_inherited.py` 启动器，并将 `--basetemp` 放在工作区 `.tmp` 下；这个本地辅助文件不导出给 worker。

先完成并提交已测试实现，再从完整提交导出最小 worker 源码。为每次生成使用新目录：

```powershell
$testedCommit = git rev-parse HEAD
& $task13Python -m scripts.task13_worker_runtime export-source --commit $testedCommit --destination "data/task13/runtime/source-$testedCommit"
& $task13Python -m evals.freeze --source-commit $testedCommit --run-id task13-campaign --output "data/task13/control/formal-$testedCommit"
```

冻结生成器只产生 `prepared_not_frozen` 草案，不会接受 G1–G5。源代码、测试、配置种子、协议和依赖文件必须完整绑定；生成的控制文件位于 `data/task13/control`，避免提交哈希或冻结哈希自引用。仓库内 `configs/ait.json`、`configs/dedale.json` 记录的是实施前基线提交，且没有冻结哈希，不能直接执行正式实验。

按 [配置说明](configs/README.md) 从已接受的六个 AIT development 案例生成独立的开发选择和控制器。准备显式 `development.json` runtime，绑定同一提交、导出源码、Linux 锁依赖、镜像摘要、知识快照和共享预算账户，再以 `--row-limit 1` 测量第一批。`phase` 必须为 `development`。不要将正式 test 案例改名为开发集，也不要用 fixture 证明模型效果。

只有 G1–G5 和真实模型隔离证据被接受后，才给生成的控制器绑定最终 freeze 文件及其 SHA256，然后运行：

```powershell
./evals/run_formal.ps1 -Dataset ait -Config "data/task13/control/formal-$testedCommit/ait.json" -RuntimeConfig data/task13/runtime/formal.json -AllowFinalTest
./evals/run_formal.ps1 -Dataset dedale -Config "data/task13/control/formal-$testedCommit/dedale.json" -RuntimeConfig data/task13/runtime/formal.json -AllowFinalTest
```

默认输出为 `data/task13/runs/<dataset>/<run-id>`。每行的输入、结果、尝试和命令收据独立留存；恢复执行只调度尚未开始的行。只有明确记录的基础设施/传输失败可经命名授权创建第二次尝试。schema、拒答、unknown、低分和混合非传输失败均不能触发重跑。

## 人审、F8 与最终图表

人工复核在控制侧使用 `build_review_plan` 预注册抽样、`blinded_bundle` 导出盲包，再通过 `validated_reviews` 导入实际判断。人审对象是完整封存报告；缺失判断保持空值，不能用自动引用有效率代替语义支持判断。

F8 使用 `build_verification_plan` / `run_verification_plan`，保留全部 264 对实验槽位及其未适用、未审批或失败状态。已封存 B3 源状态、有效且实际持久化的用户审批，以及独立 database/index/checkpoint/trace 是前提。`run_source_review_container` 的 `read_packet`、`decision` 不接收模型 key；只有在受检 worker 中运行的 `renew_plan` 可以使用共享账户的 verification 预算。不得自动批准计划或用合成审批记录证明真实人工授权。

在新的评分输出中导入复核/F8 结果，再从冻结分数绘图；评分与绘图均不调用模型。将下列占位路径换为实际不可变产物：

```powershell
& $task13Python -m evals.runners.cli score --plan <plan.json> --output-root <attempts> --reviews <human-review.json> --verification <f8-results.json> --output <new-scores.json>
& $task13Python -m evals.plots.generate --scores <ait-scores.json> --scores <dedale-scores.json> --output-root data/task13/figures --font-path <CJK-font-file>
```

图表输出为 15 张 PNG/SVG，附 CSV、说明和哈希 manifest。缺失/N/A 不填零；空图不能完成实验交付。G6 仍需完整真实终态、必要人审和最低 F8 覆盖，G7 仍需核对数据并逐图检查。

## Task13 v2 整改补充

补充活动为 `task13-repair-202610-v2`，见 [补充协议](../docs/evaluations/task13-remediation-protocol.md) 和 [进展报告](../docs/evaluations/task13-remediation-report.md)。原活动、原 704 行及审批终态保持原位；以上 v1 正式运行命令不用于派发 v2。

`evals.remediation.prepare_bundle` 将独立登记投影成36项开发分析或176行B2/B3配对请求；`execute_bundle` 要求逐次验证实际出站确认、冻结源码/配置、R1/R2及预算的可信 admission verifier。登记或 `executable=false` 字段均不构成授权。派发标记先持久化，状态未知不自动重放，已完成槽不择优重跑。注入的离线 worker 只生成 `offline_contract_test` 范围结果。

模型 worker 使用 `RemediationRequest` 和 `run_remediation_container`，保持原 Docker 只读挂载、PID/nonce 与服务探针。原 SQLite 的3350条历史前缀必须匹配，控制侧配置还绑定原 active 路径，防止误用空库或副本。开发6元、回归16元、F8/续期6元均同时受原总额100元与累计开发15元限制；2元机动额度保持占用，不自动转移。

R1/R2 可用 `python -m evals.rag_gates --project-root <主项目根>` 在真实本地隔离服务上执行，最终模型 HTTP 由强制录制 transport 拦截，付费调用为0。每次写新 attempt，历史失败与早期 canonical 回执保留；当前有效索引由进展报告指向。

F8 v2 使用 `VerificationCampaign` 维护264对/528分支完整状态，并要求实际产品审批验证及至少三次开发六分支耗时证据。新续期入口为 `RemediationReviewRequest` / `run_remediation_review_container`：读取与决定不创建模型，合法续期使用稳定调用标识及补充预算。开发续期的实际模型计费阶段为development，F8为verification；它们都保留真实逐计划审批、封存诊断与30分钟TTL约束。合成审批和回放结果不计入正式覆盖。
