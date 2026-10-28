# Task13 Model Identity Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use subagent-driven-development to implement this plan task-by-task. Steps use checkbox syntax for tracking.

**Goal:** 在保留原账本、身份和停机历史的前提下，支持未来由控制侧明确采用的新模型身份阶段；本轮只免费工程和候选准备。

**Architecture:** model_identities模块管理独立追加登记、请求映射和持久停机；预算复用原事务核算，host/worker共同校验显式引用。core描述符与后生成的登记hash分离，旧请求缺省字段省略，来源和处置语义不变。

**Tech Stack:** Python3.12.14、SQLite、Pydantic2.13.5、pytest、现有Task13隔离worker和host控制器。

## Global Constraints

- 本轮新增模型请求0，真实身份/source epoch/槽登记0，真实停机迁移0；工程A决定不能作为真实采用authority。
- 原campaign.sqlite只读。测试预算限于独有临时目录，禁止.env/模型密钥/外部网络。不得重置原100/15/30/6/16/6/2限额或3350行前缀。
- 旧global身份/halt、原source epoch0/1/2、两次实际规划、51次补充开发物理请求及原36/旧704不改写，旧2未用槽不继续。
- 不改ModelConfig、project_context、backend节点/模型/fallback和原分析AST语义。合法null不重试、不强制计划、不获得计时信用；未接受模型原文和rule_fallback无信用。
- 新身份所有关键引用和authority必须独立核验，不允许构造器或worker自动登记；source epoch登记不是模型采用；身份采用不是出站批准或具体计划批准。
- base3e58411，独立工作树D:/传智杯/.backups/task13-model-identity；文档、检查点和报告留存后再进入下一任务。

## Task 1：显式身份登记与同账本预算

**Files:** Create evals/adapters/model_identities.py、evals/tests/test_model_identities.py；Modify evals/adapters/model_client.py、evals/adapters/budget_v2.py；Test evals/tests/test_model_client.py、test_budget_v2.py、test_source_epochs.py。

**Interfaces:**

```python
register_model_identity(path, manifest, *, expected_manifest_sha256,
    budget_identity, authority, expected_authority_sha256) -> dict
require_model_identity_in_transaction(db, model_epoch_id, *, epoch_id,
    source_sha256, config_sha256, purpose, manifest_sha256=None, latest=False) -> dict
require_registered_model_identity(path, model_epoch_id, **bindings) -> dict
```

SupplementBudgetAccount接受成对可选model_epoch_id/model_identity_sha256，要求epoch_id；request_binding的审计可显式加入引用，但physical_request_key必须使用旧binding形状。冻结manifest字段/authority/schema在实现报告中完整列出，Task2据此接入，不得另猜接口。manifest至少绑定设计列明预算、source epoch、scope、身份、继承停机证据及前任；authority单独绑定manifest及实际采用决定，拒绝工程consent类型。

- [x] 先写临时原预算fixture上的行为负例：未登记/无authority/工程决定冒充拒绝、合法显式登记后新身份可预留而旧global仍halt、登记/映射篡改拒绝。运行新文件并保存RED，不改真实预算。
- [x] 为全局停机检查加入最小扩展点，保持原核算：

```python
def _check_dispatch_in_transaction(self, db):
    halt = db.execute("SELECT value FROM config WHERE key='halt'").fetchone()
    if halt:
        raise RuntimeError("campaign halted: " + halt[0])
# reserve的BEGIN IMMEDIATE之后调用此hook，后续原总额/开发求和不复制。
```

- [x] 新module按source_epochs相同的host-only/pin/原预算/根锁/事务顺序登记，保存manifest+authority追加链、request-model映射和model halt，禁止UPDATE/DELETE。全局非身份halt通过持久SQL事件捕获，缺schema/链拒绝。
- [x] 先写缺失/不同model/fingerprint、隐藏的provider/超额halt、并发跨身份限额、退役请求正常结算、映射失败原子回滚、旧稳定键不变和跨身份重放负例，再实现 scoped account 与 TrackedModel结构解析前核验。actual usage必须结算，停机先提交。
- [x] 新文件及原model/budget/source三组GREEN，Ruff/check/format及diff检查通过。临时预算和mock transport，无供应商调用。
- [x] 完整实现报告写D:/传智杯/.tmp/task13-identity-task1-report-20261028.md，给出精确schema、接口、RED/GREEN命令/结果/源码SHA；独立spec+quality审查关闭后本地提交。

## Task 2：E与176入口一致绑定

**Files:** Modify evals/e_planning.py、evals/adapters/e_planning_contracts.py、e_planning_worker.py、e_planning_no_plan.py、e_planning_review.py按需、evals/e_timing.py、evals/adapters/epoch_remediation.py、scripts/task13_worker_runtime.py、task13_e_trial.py、task13_regression.py；Create evals/tests/test_model_identity_runtime.py；在现有相关测试中增加实际接口负例。

**Interfaces:** core_config.model_identity精确{id,response_model,fingerprint}，不含最终登记hash。EpochBinding及EPlanningRequest、EpochRemediationRequest可选model_identity_binding={model_epoch_id,model_identity_sha256}。缺省必须从嵌套model_dump省略，不能改变旧哈希。budget_binding将该引用拆成Task1账户kwargs；claim provenance和审计保留相同引用。

- [x] 先写旧注册/请求逐字节dump相等、新core/reference冲突、未采用identity在preGO拒绝、runtime options/request串用、宿主raw/ledger身份篡改、null/计时来源串用负例，保存RED。
- [x] 用Pydantic可选字段省略机制保持旧字节；新registration builder在core有描述符时要求epoch_binding显式引用，身份id一致。禁止把最终identity manifestSHA放入core形成环。
- [x] E host历史锚点保留，显式模式从Task1只读查询取得有效模型身份及作用域halt；预算/global非身份halt仍阻止。host启动前和worker admission独立核验source+model，runtime options须与request一致，新增校验module纳入冻结入口清单。
- [x] _claim_binding和e_timing固定admission字段条件加入相同引用，no_plan验证先核对可信采用记录和raw响应身份，不相信ledger自己声明。合法null及fallback边界保持；review和六分支来源拒绝跨身份。
- [x] 176 v3 request及host读取同一显式身份守卫；E计时、core、model/pricing与新请求一致，旧入口保持拒绝。这里只免费测试，不运行真实176/F8。
- [x] 运行新测试与现有E contract/journal/worker/no_plan/runtime/host/timing/epoch/regression/analysis-import相关组，保存精确范围结果。Ruff和diff检查，完整报告D:/传智杯/.tmp/task13-identity-task2-report-20261028.md，独立spec+quality审查后提交。

## Task 3：免费验收、冻结导出与候选

**Files:** docs/evaluations/task13-model-identity-verification-20261028.md、此计划及.superpowers/sdd/progress.md；主工作区活动根下全新候选/审计目录。工程辅助脚本放主工作区.tmp，不写原候选。

- [x] 固定最终受检源码，适当相关联合回归和必要免费本机服务/真实Linux只读导出验收；不因旧通过的无关范围重复全量测试，源码变化则重测覆盖范围。
- [x] 全分支独立审查关闭Critical/Important，覆盖权限、核算、真实环境边界、null/fallback、旧兼容；修复后仅重测必要覆盖组。
- [x] 本地提交最终源码并导出实际Git archive，重新执行该提交必要R1/R2和最小Linux导入/原便携分析重验；需补齐被忽略fixture时按权威hash复制，原件不改。
- [x] 只读复核原账本及旧工件前后不变，51次/0.35657016元、原halt、epoch0/1/2、旧槽及0/3信用不变。
- [x] 准备新候选的确切source/core/源epoch提案/model manifest提案和具体发送确认单。旧bc19仅作拟采用值，明确尚未真实采用；外部采用authority和发送决定均待用户，不制造实际批准、不运行登记CLI。新规划限额须另列新增3逻辑/最多9物理以及此前实际2次，共最多11规划物理，费用仍计开发6元。
- [x] 候选依赖顺序固定为core/source epoch → identity manifest → 具体确认单 → 外部采用authority → host manifest；确认单不直接或间接固定authority摘要。
- [x] 工程报告、精确hash机器回执和进度清楚区分完成工程与待真实采用/发送/三次批准计时/TTL/176正式准入；不标整体Task13已完成。
