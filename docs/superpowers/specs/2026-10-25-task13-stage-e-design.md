# Task13 阶段 E 最小实施设计与验收清单

> 供实施者逐项执行；实施时使用 subagent-driven-development 或 executing-plans。本文是免费工程设计，不是新增出站同意、源 epoch 注册回执、计划批准、计时回执或真实产品状态。2026-10-25 编写。

**目标：** 在保留全部旧记录与预算的前提下，将按固定顺序取得的合格分析导入新真实产品流程，经真实计划批准完成至少三次六分支计时，为新冻结、176 行回归、F8 和新人工复核提供合法入口。

**架构：** 只增加同账本 source epochs、分析导入入口和 E 计时控制器。复用现有产品校验/封存、PostgreSQL checkpointer、respond、持久化批准、隔离 worker 和受控观察；不建立 provider gateway 或新服务。

**技术：** Python、Pydantic、SQLite 原子账本、现有 LangGraph/PostgreSQL/OpenSearch/MCP、现有 Docker runtime。

## 1. 事实、范围与不可变边界

- 本设计的源码依据为 `D:\传智杯\.backups\task13-remediation` 的冻结 commit `b1666d38d5fc0467102166beafe229d87f826539`。该树只读；后续实现位于额外隔离树 `D:\传智杯\.backups\task13-stage-e`，分支 `codex/task13-stage-e`。下文 `NEW` 专指后一个绝对路径。
- 前置文件为同 audit 目录的 `analysis36-next-stage-e-preparation-20261024.md` 与 `.json`。其“停在第五槽”是编写该报告时的状态；36 分析现已获续跑安排，本文不将旧状态当当前进度，不修改、不重放该运行器。
- 已知前四槽原回复因 `10.*` 与 `source_scope=external` 的事实不符被拒，第五槽调模前失败。这些行和费用永久保留。不能修字段、换 repeat、重跑、借其他案例或用提示变更追认成功。
- 原 development 路径只保存分析结果，不建立可保留的真实审批 checkpoint。意外残存的库/索引也不等于合法 retained source。旧 manual_review、旧 AIT 原计划、旧审批、旧 F8 缺口均不作导入来源。
- 预算唯一真实路径仍为 `D:\传智杯\data\task13\budget\campaign.sqlite`；原身份为 audit 的 `original-budget-identity.json` 中非空 3350 行前缀及其摘要。不在派发时重算身份，不创建另一份真实账本。
- 上限保持：总额 100 元、原 development 15 元、整改合计 30 元；整改 development/regression/f8 子额分别为 6/16/6 元，held contingency 为 2 元且没有派发 purpose。6 元包含本次已发生的 36 分析费用、失败、unknown、在途以及后续开发响应/续期，不是另加 6 元。
- 本次只写本文件及新隔离树的设计副本；不注册真实 epoch，不修改真实 DB、控制登记、确认文件、原冻结代码、36 runner 或真实产物，不发模型、不创建产品状态、不取得计划批准。
- 免费实现及合成测试可以继续；实际付费范围、具体出站内容和每一份真实产品计划批准以后分别办理。本文件不生成任何用户批准记录。

## 2. 源码落点与最小改动

下表路径均相对于 `NEW=D:\传智杯\.backups\task13-stage-e`；旧树同名文件只作阅读参考。

| 单元 | 新增/修改文件 | 具体责任与旧边界 |
| --- | --- | --- |
| source epoch 读取 | 新增 `evals/adapters/source_epochs.py` | 严格 manifest 类型、只读 epoch 查验、旧 campaign/caps/预算身份核对；worker 不注册 |
| 可信 host 注册 | 新增 `scripts/task13_register_source_epoch.py` | 唯一显式注册命令；同一 DB 追加记录；拒绝 worker 环境 |
| 预算接入 | 修改 `evals/adapters/budget_v2.py` | `epoch_id=None` 保留旧 constructor/binding/key；epoch 路径只接受已登记版本，跨 epoch 合并旧费用 |
| 请求/runtime 接入 | 修改 `evals/adapters/remediation_contracts.py`、`remediation_review.py`、`remediation_worker.py`、`scripts/task13_worker_runtime.py` | 新字段与新 schema 分支；旧 analysis 请求不改；保持真实 Git archive/挂载/镜像/依赖/知识/身份校验 |
| 控制侧来源审查和 worker | 新增 `evals/adapters/analysis_import.py` | 来源机械扫描、严格 provenance 导入请求、固定 respond 调用与资源 retain |
| 产品导入类型 | 新增 `services/backend/src/evidencesoc/agents/analysis_import.py` | 产品可接受的可信输入与 provenance；不依赖 eval 真值/条件 |
| 产品 graph 入口 | 修改 `services/backend/src/evidencesoc/agents/graph.py`、`state.py` | 专用 `analysis_import` 节点和方法；复用原 respond 包装、save_result、approval interrupt，不伪造 analyze/reconstruct |
| 严格 TTL | 修改 `services/backend/src/evidencesoc/agents/nodes/__init__.py` 或 graph respond 输出校验 | 仅导入入口要求计划恰 1800 秒；不放松全产品原引用/目标/审批规则 |
| E 控制器 | 新增 `evals/e_timing.py` | 独立 bootstrap、三次真实六枝、append-only 事件、真实计时导出；不调用正式 `run_case` 反造其前置回执 |
| 既有验证接口 | 复用 `evals/adapters/verification_worker.py`、`retained_workflow.py`、`evals/verification_v2.py` | 保留原持久化批准读取、克隆、观察、校验和正式 timing gate；只做必须的 epoch metadata 兼容 |
| 独立检索测时 | 新增 `scripts/task13_measure_retrieval_startup.py`；必要时为 `rag/embeddings.py`、`rag/retriever.py` 增加被动测时钩子 | 不改变查询、缓存/超时/检索通道；工程结果不进入36和正式指标 |

不为实现本设计重构评分器、六类 F1、旧 verification v1、原人工复核或现有模型 provider。

## 3. 同账本追加 source epochs

### 3.1 manifest 与可信注册

提供以下稳定接口；参数都需严格验证，禁止从 worker 自声明推导授权。

```python
register_source_epoch(db_path, manifest, *, trusted_host_authority) -> dict
require_registered_epoch(db_path, epoch_id, *, binding, budget_identity) -> dict
```

`register_source_epoch` 仅由 host 显式命令执行。`trusted_host_authority` 从后续具体阶段同意包及其真实决定记录独立读取并核对哈希，不接受把 manifest 的 `authority` 本身当授权；命令有 `TASK13_WORKER_NONCE` 或运行于 worker PID1 时拒绝。本次没有该新真实批准包，故没有可运行的真实注册命令；合成测试必须标明 synthetic。

manifest 精确包含以下语义字段，canonical JSON 计算摘要：

```text
schema_version = task13-supplement-source-epoch-v1
campaign_id = task13-repair-202610-v2
epoch_id, epoch_number, predecessor_epoch_id
source_commit, source_sha256, config_sha256
entrypoints: {repo_relative_path: file_sha256}, entrypoints_sha256
runtime_binding: {image_id, dependencies_lock_sha256,
                  dependencies_tree_sha256, knowledge_sha256,
                  controller_manifest_sha256}
budget_identity: 原固定 original-budget-identity-v1 对象
budget_limits: {total:100, development:15, supplement:30,
                purposes:{development:6, regression:16, f8:6}, held:2}
authority: {kind, packet_sha256, decision_record_sha256}
```

`source_sha256` 沿旧预算请求的语义，为 `canonical_hash(source_receipt.json)`。`entrypoints` 至少覆盖真实 controller、runtime、adapter 入口及其实际被执行的控制侧文件；不可把新 audit 脚本执行伪称 b166 代码。manifest 不能包含密钥、header 或条件真值。

epoch 0 是可信 host 对已存在 campaign 首版 source/config 的显式历史承认：必须与旧 `supplement_campaigns.frozen_config` 原值一致，authority.kind 为 `legacy_source_attestation`，引用已有合法原授权，不制造新批准。epoch 1 及以后引用前一 epoch，登记新的真实阶段范围；注册 source epoch 仍不替代模型出站范围检查及 per-plan approval。

### 3.2 最小数据结构与迁移

只在同 DB 中追加两张表，不改列、不重写旧行：

```text
supplement_source_epochs(
  epoch_id PRIMARY KEY, campaign_id, epoch_number,
  predecessor_epoch_id, source_commit, source_sha256, config_sha256,
  entrypoints_sha256, manifest_json, manifest_sha256, registered_at,
  UNIQUE(campaign_id, epoch_number), UNIQUE(predecessor_epoch_id)
)
supplement_request_epochs(
  reservation_id PRIMARY KEY REFERENCES supplement_requests(reservation_id),
  epoch_id REFERENCES supplement_source_epochs(epoch_id)
)
```

epoch 表的 UPDATE/DELETE 用 SQLite trigger 拒绝；reservation→epoch 映射只 INSERT，一经写入不得重指。manifest 生成/列摘要/前驱与编号匹配验证必须在注册事务内完成。epoch 0 前驱为空，后续注册在 `BEGIN IMMEDIATE` 中检查当下唯一 head，拒绝分叉、跳号、重复 ID 或同 ID 内容变化。重复相同显式注册可以返回原 immutable receipt，不追加第二条。

迁移与注册为不同操作：可以在临时 fixture DB 验证 schema；真实 DB 的 schema/epoch 注册留到 host 获得具体新阶段包后执行。旧 `supplement_campaigns.frozen_config`、`supplement_requests` 与全部 reservations 字节值不变；不给历史请求倒填 epoch。旧版本没有的 epoch 关联只能明确保持 legacy/unmapped。

### 3.3 构造、预占、结算与旧调用幂等

- `SupplementBudgetAccount(..., epoch_id=None)` 的旧构造、request_binding 与 physical_request_key 保持原语义，原测试继续通过。
- 非空 epoch 路径先要求真实既有 campaign 和表已存在，调用 `require_existing_budget` 与只读 `require_registered_epoch`。禁止自动创建 campaign、epoch、预算 DB 或注册缺失项；source/config/manifest/baseline/caps 不符立即拒绝。
- 新 path 的 `request_binding` 追加 epoch_id，物理 request key 可区分实际执行版本；同一事务写 reservation、supplement_request、reservation→epoch。预占时仅当前最新已登记 epoch 能发起新物理调用；已预占旧 epoch 仍可按原绑定结算，不改旧请求源码归属。
- 保留现有物理 request_id UNIQUE；新 epoch 预占额外跨全部旧请求检查 `(campaign_id, logical_call_id, physical_attempt)`，拒绝把原稳定调用换 epoch/source/config 后重放。`StableCallModel` 的 logical ID 已含 slot/role/first-seen ordinal，不能在崩溃重启时换 UUID。旧 legacy→legacy 行为兼容；只要新/既有一侧是 epoch 请求，就启用该跨版本去重。若需要新的合法操作，必须事先新登记业务 slot，而不是仅改 epoch。
- 原子预算仍由 `BudgetAccount` 和现有 campaign/purpose SUM 覆盖全部历史及新 epoch：已知实际费用加 unknown/inflight 的保守 upper。所有总额/原开发/整改/子额检查在同一 `BEGIN IMMEDIATE` 中，不加 epoch WHERE 过滤，也不把 held2 作为 purpose。
- settlement 必须核对原 reservation 的 source/config/epoch 与请求，不得由新 epoch account 结算旧 epoch 的行；summary 汇总仍跨全部 epoch。
- host 切换前同时持有全部现有 controller writer locks，停止旧阶段新派发并验证旧 worker 不会再启动新调用。在锁持有及注册事务中要求原 reservations 没有 unsettled/inflight；settled 但 usage未知的行继续按upper计入，不取消、不填0。host 从独立可信文件核对manifest与controller roots，后续roots为前版superset。旧 b166 程序不理解新表，因此禁止旧派发依赖可信 host admission；不能声称新增表能约束仍在运行的未修改旧程序。
- host options 只能挂载 `original-budget-identity.json` 指定的原绝对 DB，继续核验 3350 行前缀、campaign 与现有追加记录。相同 schema 的空 DB、另一目录副本、重新生成 baseline 或换 campaign 都拒绝。恢复是对同一账本的显式核对，不能挑更旧副本规避已发生费用。

## 4. 来源机械选择与新真实产品 checkpoint

### 4.1 机械规则先登记，再读取结果

候选扫描仅使用原 36 行顺序，扫描上限 36，选取“首三个同时满足全部资格的成功行”。先固定该规则与摘要，待这些原行均有可审计终态后再形成选择回执；扫描记录包含每行的成功、失败、unknown、benign、无目标、缺少 provenance 等原因。不得查标签/预期分类、挑 confidence、挑 RAG 成绩或用其他 repeat 替换失败。

资格依次为：实际保存的成功 result；原 schema 完整；原物理回复/输出与成功的那次 model attempt 一致；以实际入模型 evidence/knowledge 重新通过原 `AnalysisOutput`、`validate_output_citations` 及 registry 的 `validate_diagnosis`；原后审无失败；verdict=attack；原引用支持可规范化、现有模拟动作可验证的 source IP 或 host。只支持账号而无可验证过滤路径时拒绝，不借不相关 host 查询。

结果不足三行时终态为 `insufficient_qualified_sources`，保留短缺和全部失败；不自动购买分析、换案例、重跑或扩展扫描。首三行可能同案例，必须披露相关重复，不称三个独立案例。候选三行固定后，响应为空/拒绝/过期/失败也不补选第四行。

每个来源证据清单至少固定原 bundle row/request/run、原 result/stdout、原各次回复及成功 attempt、HTTP body、returned knowledge、development-condition、agent events/seed/registry、校验源码与源 epoch 摘要。清单包含路径、字节数、sha256；worker 只读挂载所需 answer-free 子集，不挂载标签或条件真值。

### 4.2 两层输入接口

eval 层定义严格 `AnalysisImportRequest`，使用独立 schema `task13-analysis-import-worker-v1`，不可复用 development analysis 的默认路由：

```text
campaign_id, epoch_id, epoch_manifest_sha256
slot_id, run_id, request_id, namespace, attempt=1, purpose=development
case_id, dataset, group=B3, agent_sha256
source_commit, source_sha256, config_sha256, budget_identity
source_selection_receipt_sha256, source_row_id
analysis_artifact_manifest, analysis_artifact_manifest_sha256
model, response_call_limit={logical:1, physical:3}
```

slot/request/incident/resource 的 ID 均先登记且稳定；同一 import slot 已 started/unknown 时禁止自动重放。调用前 host 和 worker 各自核验 source export、已登记 epoch、实际字节、预算与来源资格。

产品层定义 `ImportedAnalysis`：`AnalysisOutput` 原有效值、原 trusted seed evidence/alerts、实际入上下文且可在原返回记录验证的 knowledge、只含来源引用/摘要的 provenance；不带 gold、conditions、approvals、response_plan、state overrides 或原 run 的完成事件。现有 `InvestigationWorkflow.initial_state` 限制保留，不扩展为任意注入 state。

### 4.3 产品 graph 导入方法

```python
await workflow.import_analysis(incident_id, imported_analysis) -> dict
```

方法要求由 inspected import worker 提供经过验证的数据，且新 incident 已由 `case_environment` 在新库/索引创建、该 incident 尚无 checkpoint；在现有 `_exclusive` 锁内执行。产品再做自身 schema/引用/实际 evidence integrity 校验；eval 的 registry 校验不替代产品检查。

在固定 graph 添加 `analysis_import` 节点，受限入口仅从该方法进入，普通 `run_investigation` 仍从 triage 开始。节点实际执行 `start_run(..., analysis_import)`、导入校验、`_validate_output`、`_seal_diagnosis(state, 'analysis_import')`、`finish_run` 和 `save_result`；输出真实 import 事件，随后直接进入原 respond 包装和原 approval 节点。

封存字段沿现产品的 diagnosis/origin/classification/attack_steps/claims/evidence/knowledge。源 `AnalysisOutput` 没有 reconstruct：`attack_steps=[]`，`claims` 只可取原诊断已给出的 claims，不创造步骤或补齐事实；新增 provenance 字段记录 `analysis_import`、原 row/hash、校验版本、`reconstruct_executed=false`。不复制源文件的旧 seal 当产品 seal，不把 analyze/reconstruct 标为在新 incident 执行完成。新 seal 是本次实际产品封存时间与 `_plan_hash`，原分析时间另存 provenance。

respond 必须真实走现有 `NodeHandlers.respond` 与模型/规则校验；model/正常 bounded fallback 来源如实记录。初版允许每固定候选一个新 respond 逻辑调用、至多三个物理尝试，费用用同 DB development 子额；不用 v1 BudgetAccount，不偷偷 reconstruct。若未来确需 reconstruct，它是另行明确登记的逻辑调用，原诊断与来源仍须保持可追溯，本版不包含。

导入计划的 `expires_at-created_at` 必须严格等于 1800 秒；要求放在 respond delta 持久化之前，非恰30分钟的原模型计划拒绝保留，不编辑 expires_at、不把拒绝输出修成成功。现有 fallback 产生恰30分钟计划可按实际 `plan_source=rule_fallback` 保留；不是无条件跳过原模型或校验。

只有真实 `awaiting_approval`、`snapshot.next == ('approval',)`、合法产品 seal、ResponsePlanTable 实际行与 checkpoint 完全一致时，才写新 `case-resource.json` 并 retain。保存 `import-provenance.json`、`investigation-state.json` 和 resources receipt；新 incident/run/DB/index 身份不得称为原分析存活的 checkpoint。空计划/unknown/benign/无效/资源失败写明确终态，按现有 finally 清理，不追记 retain。

### 4.4 人工批准

复用 `RemediationReviewRequest(purpose='development')`、`read_packet` 和 `decision`；二者不构造模型、不读取 API key。运行 phase 保持 `verification`，真正 paid respond/未来 renewal 的账本 phase 为 `development`；不同维度不能混填成 f8。

一次至多一份计划等用户决定，展示新 live checkpoint 的实际计划/风险/回滚/引用/版本/哈希。用户逐计划明确批准或拒绝，实际写原 ApprovalTable/plan_version，再由 `read_persisted_approval` 核验。出站同意、用户在本次设计继续整改的授权、事实复核、测试 stub、默认准许均不能当处置批准。

初版不自动续期。待批准前已过期或计时起跑余量不足时保留状态，若需要下一版本，另外登记 renewal slot/模型上限/出站范围，走现有 `renew_plan`、新 packet 和新真实批准；不原地改时间。已开始某六枝 trial 的批准版本不能续期后续拼。

## 5. 首三次真实计时：bootstrap 与正式门禁

### 5.1 独立控制器和固定启动规则

新增 `evals/e_timing.py`，接口为 `ETimingCampaign(registration, output_dir, execution_admitter=...)` 与 `run_trial(trial_id, approved_source, run_worker=run_verification_container)`。不要调用正式 `VerificationCampaign.run_case` 生成自己的 timing 前置；后者仍要求至少三份完整真实 trial。

bootstrap 是新阶段须具体登记的启动规则，不是声称原正式余量公式已满足。预登记固定：三份候选/三份 trial，候选失败不自动替换；每份最多六个稳定 branch slot；顺序为 success(enabled,disabled)、failure(enabled,disabled)、no_change(enabled,disabled)。零模型费用不免除新范围核对、实际用户批准、隔离服务与时间门禁。

```text
mode=bootstrap
first_trial.observed_max_seconds=null
first_trial.complete_observed_trials=0
bootstrap_min_remaining_seconds=1500，起跑必须严格大于该值
bootstrap_per_branch_timeout_seconds=180
bootstrap_total_timeout_seconds=1200
hard_deadline=min(trial_started+1200s, plan.expires_at-1s)
```

这些固定值是资源保护界限，未声称实测可行，不来自合成测试/API9 耗时。首次无 M，不填 0、不在 receipt 隐藏 missing；首六枝前不调用 `observed_six_branch_max`。试跑 2/3 除上述 bootstrap gate 外，使用已有完整真实试跑的 provisional 最大值，额外要求 `remaining > 1.5*M_provisional+300`，但不输出 formal admissible。任何界限不足即停止本 trial 派发，保留原因，不自行放宽常数。

每个实际 plan 恰30分钟；起跑前已真实批准，并核对当前 DB/plan/checkpoint/approval hash。整个 trial 六枝必须共享该同一版本，各枝开始和完成都必须在原 expires_at 之前。中途过期、超时、failed/unknown 或部分完成记录成不完整 trial，剩余槽保留未执行；不跨版本、跨晚、跨到期拼接。

hard timeout 用 host 单调时钟取消并终止 inspected worker；不能仅 `asyncio.wait_for` 后遗留仍在跑的容器。容器/清理状态不明先记 unknown，不重派其 request_id；保留命令、inspect、nonce、probe、退出和回收证据。清理可在 TTL 后完成，但只有 TTL 前收到并验证的真实 branch result 能计 complete。

### 5.2 真正的六枝输入与测时

每枝复用现有 `VerificationWorkerRequest` 与 `run_verification_container`：同一批准源，从真实资源各自克隆；每枝独立 database/index、request_id、namespace、checkpoint_id、trace_id、worker_nonce、service probe。跨 trial 也不复用这些身份；三份审批 approval_id 独立。enabled/disabled 对内使用相同受控前后 observation，conditions 只在控制侧变成现有规范观察，不送模型。

每次派发前追加不可变 `branch.dispatched`，记录 UTC 和 monotonic ns；实际返回并通过既有 `_validated_worker_result`/源批准/隔离核验后追加 `branch.completed`。完整 trial 的 observed duration 定义为从第一枝派发前到第六枝成功返回并核验后，包含 worker 创建、clone、probe、队列/调度、输出落盘与控制侧验证。另列每枝 worker/probe latency 与 clean-up duration，不相互替代。UTC 用于 TTL，monotonic 用于 wall duration；若 UTC 和单调时长偏差超出预登记 2 秒，trial 标 `clock_inconsistent`，不作时间证明。

控制状态为 append-only 事件日志加可丢弃 projection；单 writer 锁不自动抢占。trial/branch 状态固定为 not_started、dispatched、completed、failed、expired、rejected、unknown、not_applicable。恢复只合并已存在记录；started 而没有终态先核对真实容器/输出，不能重新调用。试跑资源回执、批准源与原始结果都不可覆盖。

### 5.3 三份之后才能导出正式 receipt

仅在三份（或未来另外明确扩展范围中的更多）真实完整 trial 全部通过校验后，导出 `schema_version=task13-v2-six-branch-timing-v1`：保留当前 `observed_six_branch_max` 需要的每枝 request/result/dispatched_at/completed_at，trial_id，独立 approval_id，以及真实 provenance/artifact hashes。未满三份的文档仅为 bootstrap progress，不能命名或作为 formal receipt。

由原函数重新推导 `M=max(真实完整六枝耗时)`，必须为正数；不能直接相信 JSON 中手填的 maximum。正式 F8 开跑前严格执行 `remaining > 1.5*M+300`，TTL恰30分钟；等号拒绝。若即使全新计划也不能满足，就报告 TTL 时间不可行，不改公式/TTL、不伪造观测、更不缩小耗时口径。

## 6. 试跑与最终新冻结的哈希顺序

在真实 E 之前先 commit 并导出要执行的工程版本，固定镜像、依赖、997 条知识、价格、model、entrypoints、测试证据与 execution-core config。该 core config 预先包含 E 和将来 F8 的稳定协议/参数及 F8 已登记 plan 的 hash；实际阶段范围同意包独立，不能仅凭 epoch 注册派发未授权 purpose。

E trial receipt 的 identity 预先使用未来 `VerificationCampaign.identity` 的同一 campaign/F8 plan/source_commit/source_files/core config。特别区分两个现存 `source_sha256`：预算请求是 source_receipt 的 canonical hash；`VerificationCampaign.identity` 是 source_files map 的 canonical hash。manifest 和控制回执分别明确命名保存，不能把两者混当。

三次 trial 后创建独立 `final-freeze.json` wrapper，引用执行 core config、原工程 source epoch、实际 timing receipt、新门禁和价格/服务版本；不把 timing hash 回填 core config 导致 receipt 自己失配。正式冻结是核验和签入引用，并不要求修改源代码。

如 E 后又修改实际源码、entrypoint、依赖/镜像、知识、核心配置或时间相关路径，旧 timing 不自动继承。追加新 source epoch，重新免费验收，再在具体新范围内重新取得至少三份真实批准的完整六枝；不把旧 receipt 改写绑定成新版本。为避免无谓重测，所有工程修复先在合成/隔离验收中完成，真实试跑只跑准备冻结的版本。

## 7. 可执行任务和测试清单

所有下列命令在 NEW 执行，使用已安装的 backend Python 或当前受控 Linux 测试环境；不要让命令落到旧冻结树。测试 DB 位于 pytest `tmp_path`；测试事件全部带 `synthetic=true`，不能写入实际 development/trials、F8、人工复核或效果图。

### E0：source epoch 与原预算

- [ ] 新增 `evals/tests/test_source_epochs.py`，先写失败用例：legacy 构造/key 不变；首次 legacy attestation 精确绑定旧 frozen_config；缺 campaign/epoch/manifest/authority 拒绝；错 baseline/空 DB/另一路径拒绝；worker 不可调用注册；同 ID 异内容、跳号、分叉、UPDATE/DELETE 拒绝。
- [ ] 实现第3节新表、host register、只读 require 和可选 epoch account；不修改真实 DB。用 fixtures 显式构造 synthetic host authority，不用真实用户名字伪称批准。
- [ ] 写并发 fixture：legacy 与新 epoch 同时预占，在总100/dev15/整改30/子额6、16、6中任一边界均最多允许未超限者；unknown/inflight upper 留在 aggregate，held2 不变。新 epoch 不可重放旧稳定 logical/physical call，source/config 或 epoch 换值不能规避。
- [ ] 写有旧inflight时host注册新epoch拒绝、旧行结算后才可注册的用例；settled unknown仍按upper占额度。旧epoch新reserve拒绝，新account结算旧mapping拒绝；结算接口仍按原绑定验证，失败事务不得留下只有一半的reservation/mapping。
- [ ] 运行：`& services/backend/.venv/Scripts/python.exe -m pytest evals/tests/test_budget_v2.py evals/tests/test_source_epochs.py evals/tests/test_model_client.py -q`。验收为全部相关用例通过；真实表/账本/epoch 注册数均无变化。

### E1：来源审查与 graph 桥接

- [ ] 新增 `evals/tests/test_analysis_import.py` 与 `services/backend/tests/agents/test_analysis_import.py`。固定 fixture 含 failed、unknown、benign、无目标、3个合法 attack 和额外第四个；断言严格选首3，任一候选后续计划失败不补选。
- [ ] 重放实际已失败原回复的离线 validator：`10.* + external` 必须仍拒绝；原 body/result/seed/registry/knowledge 任一摘要变动、knowledge只存在returned但不在该上下文、引用不在registry、account-only无查询路径均拒绝。测试不得清洗真实文件。
- [ ] 实现第4节严格请求与产品 import node/method；验证新 incident/new resources、真实 `_seal_diagnosis`、provenance；没有 triage/collect/analyze/reconstruct 的伪完成事件；旧 ordinary workflow 行为不变。
- [ ] 用 recorded model transport 测 respond 成功、null、schema/fact错误、正常 bounded fallback 和预算拒绝。原 `<30min` 普通计划仍依产品旧约束处理，导入入口恰1800s gate拒绝非exact；不编辑原回复时间。
- [ ] 合成真实 PostgreSQL/OpenSearch/MCP 验收：导入后真实 pending checkpoint 与 ResponsePlanTable一致，read_packet来自live状态；只有明确 synthetic approval fixture 可在测试中写批准，read_persisted_approval查真实测试表；文件伪状态/删除库/checkpoint/跨case证据/重复import均拒绝。retained成功和失败清理都验证。
- [ ] 运行：`& services/backend/.venv/Scripts/python.exe -m pytest evals/tests/test_analysis_import.py evals/tests/test_remediation_review.py evals/tests/test_retained_workflow_exports.py services/backend/tests/agents/test_analysis_import.py -q`。离线与真实服务验收分别保存回执；后者关键检查 skip=0，合成批准不得计入真实3份。

### E2：runtime 与 phase/权限集成

- [ ] 修改独立新 schema 的 `_worker_request`/`_invoke_adapter` 和新容器 wrapper；不把旧 36 request 隐式改成 bridge；unknown schema拒绝。import worker与paid review均核对已登记epoch和actual mounted source。
- [ ] 测 epoch manifest/实际 source_receipt/entrypoint/image/dependencies/knowledge/budget identity 任一漂移均在密钥读取和模型构造前拒绝；host register不可由worker触发。
- [ ] 测 source read/decision与六枝verification无API key挂载、无model construction、model ledger空；respond账本phase=development，review runtime phase=verification；purpose伪装f8/regression、v1 BudgetAccount和fresh DB路径拒绝。
- [ ] 运行：`& services/backend/.venv/Scripts/python.exe -m pytest evals/tests/test_remediation_worker.py evals/tests/test_remediation_review.py evals/tests/test_worker_isolation.py evals/tests/test_analysis_import.py -q`，并运行现有真实容器隔离门禁。源码、mount、PID1、nonce、probe证据完整后才可给真实调用做审批包。

### E3：bootstrap 控制器与真实计时格式

- [ ] 新增 `evals/tests/test_e_timing.py`，先用假时钟验证首次M=null/count0；两份不能导出formal receipt；0或手填M、TTL29min59s、起跑remaining=1500、正式余量等号全部拒绝。
- [ ] 实现第5节独立控制器，复用真实 worker request/result校验。测试六枝固定顺序/同批准hash/对内observation一致/跨trial审批独立与资源唯一；复用approval_id/request/namespace/db/index/nonce或混计划均拒绝。
- [ ] 测第4枝过期、timeout/容器仍活、partial/unknown、崩溃在dispatch后、stale lock；恢复不重派，不续期拼枝。clock偏差>2秒拒绝计时证明；合成duration只验证代码。
- [ ] 用合成完整fixture导出原receipt schema并交给 `observed_six_branch_max`；原函数必须独立接受3完整真实格式fixture、拒绝全部负例。该测试通过不等于已经测得真实M。
- [ ] 运行：`& services/backend/.venv/Scripts/python.exe -m pytest evals/tests/test_e_timing.py evals/tests/test_verification_v2.py evals/tests/test_verification_observations.py -q`。随后以独立synthetic命名空间跑真实隔离容器链路，保存cleanup和零模型回执，不往真实trial目录写入。

### E4：独立 retrieval startup/query timing 与未来提示校准

- [ ] 新测时脚本分三层记录：进程/stdio/MCP启动；本地模型验证与ONNX加载；query embedding、关键词、向量、RRF、序列化与总工具耗时。每层UTC+monotonic、冷/暖进程标识、exit/error和缺测原因齐全，层计时不包含真实模型出站。
- [ ] 冷测用3个全新进程，暖测在各自同一已加载provider中再测同一查询；普通文本 semantic/hybrid独立，exact Technique ID快捷路径另列，不共享条件结果缓存。使用997块固定快照和固定工程查询，不接触36输出。
- [ ] 新增脚本测试验证层时间非负、父子口径明确、缺层为null而非0。实跑留工程回执；现有“接近10秒”只作为待检验线索，报告不得预先写成embedding冷启动导致失败。先有分层证据再决定是否另案调整timeout/cache。
- [ ] 可独立实现新树产品 `DeepSeekStructuredModel` 与eval `TrackedModel` 的analyze系统提示共用scope-grounding规则：仅引用观察到的地址；`10.0.0.0/8`、`172.16.0.0/12`、`192.168.0.0/16`、`fc00::/7`为internal；其他global地址external；其余或缺观察unknown，严格等于 `fallback.source_scope`。攻击者真实归属不能从私网地址推断。保持schema/模型/知识与 `validate_output_citations` 不变。用实际HTTP MockTransport及产品message测试规则真实送入，原 `10.*+external` 错答仍拒绝；离线通过不声称真实质量改善。此提示不进入当前36，不修原输出；若以后调用，需要新epoch/具体范围/独立付费槽。

### E5：免费验收完成后的执行关口

- [ ] 汇总E0–E4源码/测试/真实隔离回执、diff、旧树/旧产物摘要不变证明；对新代码做独立review。只测试通过且关键真实服务skip=0，才具备制作真实阶段包的工程条件。
- [ ] 以后制作具体包时列真实首3来源及全部失败/相关重复、导入manifest、实际出站日志/知识/诊断、provider/model/prompt/schema/价格、稳定slot与逻辑/物理上限、原DB身份及剩余额度、bootstrap常数、工程build/core config/hash；明确阶段scope consent与每计划批准分离。本次不提前填用户同意或decided_at。
- [ ] 实际新范围获同意后，可信host才注册source epoch并逐候选执行respond/展示/真实批准/六枝。至少3完整真实trial与真实M之后再写final-freeze wrapper。
- [ ] E完成后，176槽回归另有具体范围确认；全部176达到审计终态，失败留分母。随后F8保留88案例×3条件=264对/528枝登记，最低4AIT+4DEDALE、24完整对、8份真实批准，开发3份批准不计入8份。
- [ ] 最后固定新活动同8案例B2/B3的16槽人工复核；用户逐项真实核对、绑定新报告与引用并记录真实新时间。旧64槽不复制；客观缺失保留，AI初核和F8批准都不代替事实复核。

## 8. 完成定义与本次交付状态

本设计覆盖原 E 准备文档的三个未决接口，并给出最小工程任务与负测。其工程完成定义是新树实现和上述离线/真实隔离验收；阶段 E 真正完成还必须有具体新范围、原账本epoch真实登记、至少三份用户真实批准的完整六枝和实际时间证明。两者不能互相冒充。

截至本文件写入：这里只完成设计，真实epoch/桥接资源/新增模型/计划批准/计时回执均未由本文创建。现36续跑自己的事实、费用与终态，以其原追加记录为准。
