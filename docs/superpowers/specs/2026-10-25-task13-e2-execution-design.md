# Task13 E2 最小可执行桥接设计

> 2026-10-25；免费工程设计，待 root 确认后才实施。本文没有注册真实预算 epoch、建立真实 incident、运行 worker、发出模型请求或记录用户批准。实施树为 `D:\传智杯\.backups\task13-stage-e`；冻结 `b1666d38d5fc0467102166beafe229d87f826539` 所在 `D:\传智杯\.backups\task13-remediation` 保持只读。

**目标：** 将已合法保存的诊断通过专用隔离 worker 导入新的真实产品流程，每个登记槽真实生成一份计划，分别获得用户批准，各自完成完整六分支计时。仅度量工程链路，不重新分析或改写原36结果。

**本设计的增量：** 为 stage-e-design 第4.1节的来源短缺增加一个必须在执行前明确预登记的新阶段模式；不更改原 first-three 选择回执，不把不足三条改报成功。source epochs、免费桥接和 bootstrap/lifecycle 的现有实现继续接受独立复核；本文只规定它们的最小集成接口。

## 1. 事实与推荐

当前原36槽均已终态：25份合法分析中21 unknown、3 benign、1 attack；11 failed。实际49次物理调用，费用0.32985832元，实际费用缺失和在途均为0。完整对照与账本对账依据为：

`D:\传智杯\data\task13\supplements\task13-repair-202610-v2\development\comparisons\20261025T061519Z-e4b08c6377ab\comparison.json`

唯一合法且有可验证处置目标的 attack 为原第9槽（`order_index=8`）：`development-0444ddc74df35fc4080bd02c`，案例 `ait-f62148bdfdc29c83f078be92`，hybrid、repeat3。原 bundle SHA256 为 `9df1b069273c47128555e21a613092caceac6c7a9aceb6b0df549592f1666fac`；原 request SHA256 为 `1b3d6910b147b1eff4733bb2a3815d2ea34cbb4fcb7756afb2cc33ddc75a52a7`。

三个方案的范围如下：

| 方案 | 行为与代价 | 结论 |
| --- | --- | --- |
| 严格保留 first3 不新增模式 | 真实选择回执为 `insufficient_qualified_sources`，不执行 E trial | 合法但不能获得三次计时 |
| 同源三次重复计时 | 固定首个合法源，3个预登记 planning slot；3次真实 respond、3份独立新计划/用户批准、18个隔离分支 | 推荐的最小工程方案 |
| 另登记8个 full-B3 工程候选 | 新分析、重构、规划及更多出站数据/费用，成功数仍不能预先保证 | 留待另一次具体 scope，非本轮默认 |

推荐模式满足“至少三次真实完整试跑”的计时目标，但没有案例独立性：它是**1个关联来源、1个案例上的3次重复工程计时**。没有新增分析样本，不计入原36、176回归、F8最低8份审批或最终事实复核。不能宣称“三个独立案例”或在8份审批缺口中扣除这3份。

## 2. 机械来源选择与登记

保留现有 `select_first_three(anchors)` 与 `task13-analysis-source-selection-v1`。所有36行须原顺序、原 byte/hash、实际模型入参和原回复复核完成；不查看标签、预期分类、confidence 或检索效果挑源。

- 合格源数至少3：仍采用原 first3，mode 为 `first-three-qualified-original-36-v1`。
- 合格源数为1或2：新的具体阶段 scope 可预登记 `same-source-replicates-v1`；只采用原顺序首个合格源，登记 ordinal=1、2、3 三槽。原 selection 回执继续为 `insufficient_qualified_sources`，其 `selected_sources` 不复制、不改状态。
- 合格源数为0：拒绝创建执行登记。不得购买分析、换 repeat、用旧 manual_review 或原 AIT 计划补足。

新增 `task13-e-planning-registration-v1`，字段固定为：

```text
campaign_id, registration_id(hex32), synthetic(bool)
mode, source_selection_receipt, source_selection_receipt_sha256
qualified_source_count, distinct_source_count, distinct_case_count
epoch_id, epoch_manifest_sha256, source_commit
budget_source_receipt_sha256, config_sha256, budget_identity
core_config_sha256, source_package_manifest_sha256
selected_source_lineage, selected_source_lineage_sha256
slots[3]: {ordinal, planning_slot_id, run_id, request_id, namespace,
           incident_id, trial_id, source_identity, source_row_id, case_id,
           dataset, agent_sha256, source_package_manifest_sha256,
           source_analysis_output_sha256, original_request_sha256,
           original_artifact_manifest_sha256,
           response_call_limit:{logical:1,physical:3}}
```

`registration_id` 在制作具体包时生成一次并冻结。派生公式固定如下，不使用运行时 UUID 或新时间绕过重放保护：

```python
planning_slot_id = "development-eplan-" + canonical_hash(
    [registration_id, ordinal, "planning"]
)[:24]
run_id = CAMPAIGN + "-" + canonical_hash([planning_slot_id, 1])[:16]
request_id = canonical_hash([registration_id, ordinal, "respond-request"])[:32]
namespace = canonical_hash([registration_id, ordinal, "planning-namespace"])[:32]
incident_id = "IN-" + canonical_hash([run_id, case_id, "B3"])[:26]
trial_id = canonical_hash([registration_id, ordinal, "six-branch-trial"])[:32]
```

登记包含全部3个请求的摘要和3×6个 branch request_id/namespace；外部 scope 决定记录独立绑定登记摘要。不能将该决定本身放进登记造成循环哈希。批准范围和 source epoch authority 另有真实文件，不由 registration 自声明产生授权。

新增接口：

```python
build_e_planning_registration(selection_receipt, *, registration_id,
    package_manifest_sha256, epoch_binding, core_config, synthetic) -> dict
validate_e_planning_registration(registration: dict) -> None
```

当前只产设计；正式 registration、真实 journal 与真实 epoch 注册须等具体新范围被用户同意。合成 fixture 的所有路径、DB和回执须标明 `synthetic=true`。

新增不可变来源选择扩展回执 `task13-e-selected-source-lineage-v1`，不重写原selection v1：它引用原selection全文摘要，逐个实际使用的源绑定 `source_row_id/order_index/case_id/original_request_sha256/original_artifact_manifest_sha256/source_package_manifest_sha256/source_analysis_output_sha256`。其中最后一项是对原成功实际回复按AnalysisOutput解析后的完整 `model_dump(mode='json')`计算canonical hash；只排除外层 `sealed_at/sealed_after` 等原snapshot封装字段，不删减diagnosis/origin/classification中的任何字段。原request与原manifest的摘要不能替换成新planning request或portable manifest摘要。该lineage回执与其摘要都进入planning registration及timing v2，不能只放在top-level说明文字。

## 3. 可移植只读源包

旧审计目录 `audit/analysis-bridge-readonly-slot9-20261025` 的 anchor/manifest 原字节保持不变。该 v1 manifest 包含 Windows绝对路径，且 replay validator 摘要会随受控源码变化失效，不能直接在 Linux worker 使用，不能修改旧 manifest 追认新代码。

新增 `task13-analysis-artifacts-v2`，生成到一个**全新**目录。manifest保留原 row/order/successful_physical_request_id 和当前 `validation_source_sha256`；Artifact.path 改为规范 POSIX 相对路径，并增加原 anchor/manifest 原字节的 size/hash 与 lineage。每个原工件都按字节复制，不编辑诊断、实际HTTP body、stdout、result、seed、registry、knowledge、condition 或原源码。保留原 source_receipt 与它的 `original_source/` 相对层级，使原语法等价核对仍能成立。

worker 只挂此最小包。包内可以有原36 bundle 作为原顺序凭据，但不能带其他案例原始材料、标签、scoring、主仓库、`.git` 或整个 supplement 源目录。仅控制侧保留36行全量选择审查回执；其摘要进入请求。包的精确文件清单与内容摘要一并冻结，多余文件也拒绝。

新增接口：

```python
export_portable_analysis_package(anchor: SourceAnchor, destination: Path) -> dict
verify_portable_analysis_package(root: Path, manifest_sha256: str) -> ImportedAnalysis
```

导出在 host 先核对旧 anchor/manifest 的原 byte/hash 与每份旧工件，再按当前受控重放校验器重新验证实际 provenance、原源码语法等价和合法 attack。旧 replay-hash 失配只能通过新包新 manifest表达，不跳过实际字节与原模型输入校验。worker 每次从 v2 读实际字节独立重放，不能只相信 host 的“已通过”字段。

v2 reader拒绝绝对路径、空路径、反斜杠、盘符、`.`/`..`、重复规范路径、大小/摘要不符、缺失/多余文件、软链接、junction/reparse和多硬链接。只通过 `root / relative_parts` 得到路径；不得从包内提取任意宿主路径。现有 v1 verifier保持原严格语义；v2复用它的语义检查，路径解析走统一受限resolver，不能删掉原 `source_receipt`、actual payload或AST检查。manifest新增 `source_analysis_output_sha256`，reader须从实际成功物理回复重新推导并与lineage/slot/request同时核对，不能相信manifest自报值。

验证返回的 ImportedAnalysis，其 `source_identity` 仍由原 case/row/request摘要决定，不因导入slot改变。provenance额外记录 v2 package manifest/hash和原 anchor/manifest/hash；不能用新包hash冒充旧包hash。

## 4. 版本化专用请求与 dispatch admission

新增 `EPlanningRequest(Contract)`，schema为 `task13-e-planning-worker-v1`，extra字段拒绝：

```text
campaign_id=task13-repair-202610-v2
registration_id, registration_sha256, planning_slot_id, slot_id(相同)
run_id, request_id, namespace, incident_id, attempt=1, purpose=development
case_id, dataset, group=B3, agent_sha256
epoch_id, epoch_manifest_sha256, source_commit, source_sha256, config_sha256
budget_identity, source_selection_receipt_sha256
source_identity, source_row_id, source_package_manifest_sha256
source_analysis_output_sha256, original_request_sha256
original_artifact_manifest_sha256, selected_source_lineage_sha256
model, seed, budget, entry_prompt=现有固定ENTRY_PROMPT
response_call_limit={logical:1,physical:3}
```

`worker_spec()` 产生现有 WorkerRunSpec；`budget_binding()` 仅给原 SupplementBudgetAccount 接口提供 campaign/case/group/attempt/purpose/source/config/epoch_id。`source_sha256` 是新实际执行源码 `source_receipt.json` 的canonical hash，原分析的源码hash留在 provenance；不能混用 VerificationCampaign 的source_files-map hash。

现 ImportDispatchJournal 是 `source_identity PRIMARY KEY`，同源只能启动一次。不要删除此约束或让调用者随意附slot绕过。最小扩展采用**另两张表**，旧 `analysis_import_dispatch` 和旧 `claim(source_identity, incident_id)` 保持不变：

```text
analysis_import_planning_slots(
  planning_slot_id PRIMARY KEY, registration_sha256, source_identity,
  request_sha256 UNIQUE, incident_id UNIQUE, source_package_manifest_sha256)
analysis_import_planning_claims(
  planning_slot_id PRIMARY KEY REFERENCES analysis_import_planning_slots,
  request_sha256 UNIQUE, incident_id UNIQUE, status CHECK(status='started'))
```

两表UPDATE/DELETE trigger拒绝。host-only注册函数显式核对独立 scope 决定、原唯一journal路径、registration全文及精确3槽；一个事务只注册预定三槽。worker只允许打开已存在、已注册的journal；不得在worker自动建库/建schema/注册slot。注册入口检测PID1/worker nonce后拒绝，不能以包内同意字段当授权。

```python
ImportDispatchJournal.open_existing(path: Path) -> ImportDispatchJournal
ImportDispatchJournal.register_planning_slots(registration,
    *, trusted_host_authority) -> dict  # host-only
ImportDispatchJournal.claim_planning_slot(planning_slot_id, *,
    source_identity, request_sha256, incident_id, registration_sha256,
    source_package_manifest_sha256) -> None
```

`claim_planning_slot`在 `BEGIN IMMEDIATE` 中对已注册行逐字段相等核对，再INSERT一次claim。claim后崩溃、模型/资源失败和unknown均已消耗该slot；不删除、不新建attempt、不可换epoch后重放。三个同源slot以三条真实预登记绑定作为唯一例外；未登记第四slot仍拒绝。

产品工厂增加受限 `planning_admission` 参数，类型是该已注册slot的不可变绑定；`for_analysis_import`/`import_analysis`仍独立 revalidate 实际源与新incident、先检查checkpoint再claim。旧无planning参数路径继续走旧 source唯一claim。已有合法pending只允许只读读取与返回，不能再调用respond；其他已有checkpoint拒绝。

每次导入的产品provenance由已验证源provenance加上已注册admission的planning_slot/registration/request/lineage摘要组成；组合在受限产品入口完成，外部JSON不能覆盖source字段。源ImportedAnalysis自身的revalidate仍验证原不可变内容。pending幂等读取使用这一完整组合provenance比较，seal也封入该组合；不能因同源而把第一次incident的provenance/plan复制给第二槽。

## 5. 专用 worker 的真实产品路径

新增 `async run_e_planning(request: EPlanningRequest, agent_dir: Path) -> AdapterResult`，不得落到旧36 development analysis路由，也不调用普通full-B3 `run_case`。执行顺序固定：

1. 验证PID1、nonce、phase=development、schema、固定slot/request/incident、真实源码export、agent bytes、原budget identity、只读已登记epoch和runtime绑定；验证唯一journal的已注册行与只读source package。
2. 重放实际原seed/registry/evidence/knowledge/model payload、原输出和citation/diagnosis校验；确认导入诊断与唯一source_identity相符。密钥读取和模型构造在上述拒绝点之后。
3. 从原固定seed构造本次WorkerRunSpec，以 `case_environment(spec, seed)` 新建本次PostgreSQL数据库、OpenSearch索引与IncidentTable；不用旧分析残留库。三个run_id固定且不同，三个incident独立；DB/index真实新建且相互独立。
4. 先完成现有真实service probe，证明当前case内可访问、其他case/未授权路径被拒，nonce/source/服务实际身份和probe前后模型账本不变。probe失败不调模型、不retain。
5. 调现有 `make_model(request, budget_path, 'development', payload_sink=PayloadRecorder(output))`；其account必须是 `SupplementBudgetAccount(epoch_id=request.epoch_id)`，StableCallModel以本planning slot绑定。最多1个logical respond、3次physical；总dev6含旧0.32985832及失败/unknown/在途，不另开6元。
6. 实例化PostgresWorkflowServices、open_checkpointer、`InvestigationWorkflow.for_analysis_import(...)`；产品再hydrate真实persisted evidence、schema/citation校验、新seal、save_result，然后真实走原respond与approval interrupt。禁用新检索、triage/collect/analyze/reconstruct；不将旧分析步骤标成在新incident执行过。respond上下文只含原真实知识投影。hydration须先验证DB持久化原事件/证据完整性，再用既有固定seed投影规则比较模型侧内容；不能要求full raw与裁剪过的seed raw逐字相同，否则severity/message等合法投影会误拒。该既有桥接问题由独立review统一修复，是E2真实接入的前置验收，不由E2私自复制一套宽松校验。
7. 在close前核对graph snapshot确为 `next == ('approval',)`、status=awaiting_approval；新seal/hash合法；ResponsePlanTable实际行与checkpoint完全相等，plan TTL恰1800秒且未到期。保存实际 `investigation-state.json`、`import-provenance.json`、payload/body、model/tool ledger和 `case-resource.json`，再 `environment.retain()`。
8. 空计划、模型失败、无效计划、过期、seal/persistence不符、工具导出失败或隔离失败均不retain；保存原失败与已发生账本，case_environment原finally清理。retain后controller未收到/未验证结果记unknown，不能删claim重跑。

正常产品 bounded fallback可按实际plan_source保留，不假装模型计划成功；所有实际物理请求仍完整计费。没有物理成功的失败/预算拒绝不能改记成有效模型响应。导入和respond之间的诊断值、seal、evidence/knowledge与source provenance不可改写。

## 6. runtime、挂载与只读 review

`scripts/task13_worker_runtime.py`新增显式schema解析/adapter路由和 `run_e_planning_container` wrapper；新schema未知字段或未知schema fail-closed。runtime根据schema精确扩展mount whitelist，旧schema不能额外挂这两个目录：

| target | 权限与内容 |
| --- | --- |
| `/app/import-source` | RO，仅新portable package，精确文件manifest |
| `/app/import-dispatch` | RW，仅本E2唯一dispatch SQLite和必要sidecars；无预算副本、源码或其他阶段产物 |
| 既有 `/app/budget` | 继续绑定原绝对host budget目录与原identity；不能换副本、空DB、campaign |
| 既有source/deps/knowledge/spec/agent | 原RO；新source export/manifest包括所有新模块及entrypoint |
| 既有output | 本worker唯一RW输出 |

PID1 pre-GO probe应返回新增mount的可见性/读写属性、package manifest和dispatch注册绑定摘要；host Docker inspect核对精确source/target/RW、镜像、nonce、源码、依赖、KB与预算identity后才GO。host还需将请求epoch manifest/runtime_binding与实际image、dependencies lock/tree、knowledge、controller entrypoint逐项比较。不能只相信request给出的epoch_id或worker自报hash。

源包在GO前验证，在product revalidate时再次检查。所有实际新入口文件进入source export和epoch.entrypoints；不能在冻结后执行未纳入manifest的临时host脚本。source package不属于源码epoch本身，须在具体slot/registration/scope中另外绑定摘要。

新增 `EPlanningReviewRequest`，schema `task13-e-planning-review-worker-v1`，基于SourceReviewRequest的严格字段，追加planning registration/slot、epoch及原budget绑定；operation只接受 `read_packet|decision`。专用 `run_e_planning_review`核对实际source/epoch/reference后复用 `run_source_review`，不传model_factory，不提供renew路径。

review runtime phase=verification；密钥不挂载、不读取、无model construction，model_ledger必须空。read_packet来自新live retained DB/checkpoint；decision只处理用户当前明确的该packet决定，通过原 `workflow.approve`写真实ApprovalTable/plan_version，再由 `read_persisted_approval`对实际表核验。控制侧与review adapter同时核对Asia/Shanghai 19:00–00:00窗口。出站scope同意不代替计划批准；3份packet逐份展示、逐份决定，不能复制同一approval。

## 7. 与 E timing/lifecycle 的最小连接

新增 `task13-e-timing-registration-v2` 分支：引用planning registration全文/hash，验证恰3独立planning slot与trial映射。v1验证不放松。v2的same-source模式按原36选择回执证明短缺和首源，显式记录 `distinct_source_count=1, distinct_case_count=1, replicate_count=3`，不要求伪造3个source_row_id；first3模式仍核对真实首三行。

每次trial接收该planning slot的真实approved_source；E入口必须独立验证下列条件后才能发第一枝，不能仅相信source顶层metadata：

- `state.analysis_import_provenance`存在且entry=analysis_import；原row/case/request/manifest、portable package、source_analysis_output_sha256、slot/registration/lineage摘要与登记精确一致。
- state.diagnosis/origin/classification按原AnalysisOutput解析后的canonical hash等于原成功实际输出hash；三个字段与新diagnostic_snapshot内值逐字段相等。不得把另一份fixture诊断配上正确top-level row或改provenance标题混入。
- `diagnostic_snapshot.sealed_after == 'analysis_import'`，state中diagnostic_snapshot_sha256与真实seal hash一致；snapshot的证据/知识/claims/空attack_steps和provenance都与已验证导入一致。不能接受旧fixture_source或analyze/reconstruct seal充当新导入。
- 真正新incident/resources与该planning slot的worker retain回执一致；plan hash/version、state hash、selected lineage和实际persisted approval相互绑定。批准核验通过不能替代来源验证。

跨trial三个approval_id、incident、planning run和源DB/index不同。每个trial内部六枝原固定顺序，各自clone新DB/index、request、namespace、trace、nonce；同一个trial六枝只用同一approved plan版本。

控制器绑定：

```python
ETimingCampaign(registration_v2, output_dir,
    execution_admitter=existing_host_scope_admitter,
    worker_lifecycle_verifier=HostWorkerLifecycleVerifier(receipt_dir))
# run_verification_container的options固定包含：
# host_termination_dir=receipt_dir
```

保留bootstrap固定常数、剩余TTL、真实三完整trial、UTC/monotonic偏差、六枝wall duration以及原 `observed_six_branch_max`正式门禁。0模型不等于0资源或自动scope。缺回执、worker仍活、清理不明、unknown或partial均不计完整，不重派。失败/到期/无计划不自动替换候选、不续期、不改1800秒TTL、不拼不同版本；另行新增/续期必须新范围、新slot、新计划和新批准。

真实E前冻结core config、源码、镜像、依赖、KB与价格；真实timing只绑定该版本。三份完成后在独立 `final-freeze.json` wrapper引用timing hash，不回填core config造成循环失配。F8的≥8份真实批准及24对门槛照旧，这3份E批准不计入。

## 8. 最小文件落点与实施顺序

以下为root确认后的任务边界。新增文件可独立派工；既有受review文件的修改由root统一协调，本文不编辑任何一项代码。

| 任务 | Create | Modify | 独立验收 |
| --- | --- | --- | --- |
| A 来源包 | `evals/adapters/analysis_package.py`; `scripts/task13_export_analysis_package.py`; `evals/tests/test_analysis_package.py` | `evals/adapters/analysis_import.py`的路径resolver/manifest v2 dispatch | 原字节lineage、Docker相对路径、所有篡改/逃逸/多余文件拒绝 |
| B 请求与登记 | `evals/adapters/e_planning_contracts.py`; `evals/e_planning.py`; `scripts/task13_register_e_planning.py`; `evals/tests/test_e_planning_contracts.py` | 产品 `agents/analysis_import.py` journal与 `graph.py`受限admission | 首源规则、3固定slot、host-only注册、并发claim、第四槽/重放/未知schema拒绝 |
| C 真实planning worker | `evals/adapters/e_planning_worker.py`; `evals/tests/test_e_planning_worker.py` | 不修改旧36worker；如复用所需仅小型公开只读helper | 真实新incident/PG checkpoint、respond 1≤3、pending/table一致、retain与失败清理 |
| D runtime/review | `evals/adapters/e_planning_review.py`; `evals/tests/test_e_planning_runtime.py`; `evals/tests/test_e_planning_review.py` | runtime显式route、mount whitelist/probe/epoch绑定 | 密钥前拒绝、精确挂载、PID1/nonce/实际service probe、read/decision零模型 |
| E timing连接 | `evals/tests/test_e_timing_replicates.py` | `evals/e_timing.py` v2校验/slot交叉绑定 | 同源3批准可用；复用approval/资源/slot、改登记、partial/unknown拒绝 |

A→B→C→D→E按依赖推进；A的package parser与B的contract可并行，但须先冻结字段和模块接口。不得将A/B的注册或导出脚本实际对真实路径执行当成免费实现测试。

### 必须的负测和真实隔离测试

- 源包：原body/result/seed/registry/knowledge/condition/原source AST任一改变均拒绝；非actual context知识、unsupported target、wrong case/row/bundle拒绝。原失败的10.*+external继续拒绝。
- 登记：不足源不改原selection；2个合格也固定首源三重复并披露2合格/1使用；0合格拒绝。worker无法注册/建journal，source换值、slot换值、request换值、第四槽和并发双claim拒绝；started以后换epoch也不能重放。
- 预算：新请求有真实已登记epoch且purpose=development；固定同DB path/3350前缀identity；旧费用保留；共用6元，physical≤3、logical≤1。没有epoch在模型构造前拒绝，read/decision不预占、不造model。
- 产品：普通导入旧source唯一语义不变；新planning admission每槽仅一次；实际hydrate/seal/save_result/ResponsePlanTable/checkpoint一致；未执行的analyze/reconstruct不得出现完成事件；非1800秒、空计划、模型/持久化/隔离错误不retain。
- runtime：实际inspect精确mount，禁止全source/labels/其他case；nonce/PID1/preGO/source/image/deps/KB/epoch/entrypoint漂移拒绝。read/decision没有API key环境与model账本。离线MockTransport与真实零模型PostgreSQL/OpenSearch/容器集成分别保存synthetic回执。
- timing：3个同源但不同新计划/批准可导出；旧fixture_source、伪造top-level metadata、缺/换state provenance、改诊断却复用source hash、非analysis_import seal、原manifest/request错绑定全部在发第一枝前拒绝；实际approval verifier返回verified也不能放过这些反例。同approval_id、同incident、同源DB/index、混plan版本、跨到期、部分枝、worker存活或缺lifecycle proof不完整；原bootstrap及正式时间公式全部保留。

建议分组测试命令在root分配实现后使用新树backend Python运行新增5组测试，再运行现有analysis_import、remediation_worker/review、budget/source_epochs、worker_isolation、e_timing/verification相关回归。所有DB为tmp_path或明确synthetic服务资源；真实服务关键验收skip=0。测试通过不等于真实3次计时或实际用户批准。

## 9. root可审阅的执行关口

工程完成后，先制作具体出站包：新实际core源码/镜像/依赖/KB/price hash，portable源包与selection/slot登记，实际respond payload规则与最大1logical/3physical×3，原预算身份/剩余，19–00逐计划批准窗口、bootstrap与失败不替补策略。由用户对该具体新scope作真实决定。

其后可信host才显式注册原账本source epoch与唯一dispatch三槽，逐槽执行：真实respond→live packet→用户实际决定→同版本六枝。三个slot不一次性提前生成短TTL计划，避免等待批准导致过期；依次进入窗口、逐份执行。没有3个真实完整trial就保留进度与失败，不能导出正式timing receipt或声称E完成。

本设计交付仅此文档及audit同字节副本；真实费用、DB、epoch、approval和模型调用新增数均为0。
