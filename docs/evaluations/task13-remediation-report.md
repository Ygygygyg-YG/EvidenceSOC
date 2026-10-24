# Task13 v2 整改进展报告

更新于2026-10-24（北京时间），活动 `task13-repair-202610-v2`。已完成基线登记、采集/响应修复、预算与F8编排、真实检索/服务验收及开发分析输入一致性整改；最终全量1570项通过。工程源码随本报告提交，开发候选及其commit/hash另存新产物目录。**36项真实开发、176行新回归、真实F8与16槽新人工复核均未执行，Task13整体验收未完成**。补充协议见 [task13-remediation-protocol.md](task13-remediation-protocol.md)。

实施位于 `D:\传智杯\.backups\task13-remediation` 的 `codex/task13-remediation` 分支，起点 `11aff6cf08e5d4246e252c4b0031126716e761bb`。主仓保留用户三份未提交修改和新增整改计划；四份文档的保留哈希、工作树信息、原产物哈希及验证结果位于 `D:\传智杯\data\task13\supplements\task13-repair-202610-v2\audit\baseline.json` 与 `receipts/task-a-validation.json`。任务 A 不运行模型、服务、产品审批或模拟动作，不写旧费用账本。

## 原 v1 基线与结论边界

原主矩阵 704/704 已终态，638 有效诊断、66 失败；64 个人工槽已归档，60 有事实可复核、4 保留原诊断失败。原 F8 最低覆盖不满足，原 Task13 整体验收未完成。原评分文件是当时的自动中间评分，不能把其中人审为零字段当成最终 64 槽人工统计，也不能将 64 槽表述为 64 份有效事实报告。

原冻结清单有 283 文件；原知识快照为 997 唯一 ATT&CK 块。任务 A 全量登记原 runs、automatic、human、知识、原控制和缺口路径的哈希；原 704 行各已保存尝试的模型请求 ID/角色/请求哈希、工具事件和保存的工作流状态建立独立索引。该范围是元数据审计，不等于 704 份报告重新接受了语义审阅。

原费用通过 SQLite `mode=ro` 加 `PRAGMA query_only=ON` 读取，快照保留逐物理预占记录与来源哈希。历史参考为已知 40.54025952 元、保守 40.65803752 元，3350 请求、2 用量未知、0 在途；实际值以新只读快照为准。它不是供应商实付账单，每次新派发前还需重新检查。

## 六问题状态

| 问题 | 当前真实证据与可作结论 | 后续缺口 |
| --- | --- | --- |
| 固定六类 F1 | AIT credential 支持数为 0，空类 F1=0，使主指标上限 5/6 低于 0.85；保留原主指标、目标和 supported-class 补充指标 | 新回归结果尚无，不得换分母宣布达标 |
| F8 无结果 | 原 88 B3 状态缺口与 DEDALE 66 案例原因审计保留；四个 AIT 原计划已过期，DEDALE 无可提交审批的合法计划 | 新计划、真实批准、TTL 实测和真实前后观测均待完成 |
| F4 资源和单位 | 新评分代码保留已知物理费用小计及缺失项，图表由毫秒派生秒；67 项评分/指标及 10 项图表测试通过 | 新实际数据、最终对账与逐图视觉验收仍待完成 |
| unknown 过多 | 采集器提供真实 MCP schema，区分精确拒绝码；参数拒绝可在原剩余预算内纠正，不再误触发无新证据停止；78 项采集与服务行为测试通过 | 尚不能证明真实新模型调用能降低 unknown；合理弃答保留 |
| 检索/阶段隔离 | 最终真实 R1/R2 及完整知识库验收通过，保存最终 HTTP body；6 份原案例录制回放中 B3/A4 封存前请求和诊断一致 | HTTP 录制响应不等于付费效果；原停机失败保留，新36项效果对比待执行 |
| 人工和 UCR | 64 原槽与八案例范围、supported/unsupported/undetermined 及缺失保留 | 新 16 槽尚无输出和实际用户判断；单审阅人、抽样限制不能推广 |

逐问题的真实证据路径、评分字段、请求/工具/状态映射和未覆盖部分见 `audit/issues-evidence-map.json`，全部原行映射见 `audit/row-evidence-index.json`。历史计数和请求哈希不能证明 backend HTTP 实际发生，也不能替代最终序列化模型输入。

## 已登记、尚未执行的 v2 范围

| 范围 | 登记量 | 当前状态 |
| --- | ---: | --- |
| 已知案例 B2/B3 回归 | 88 案例、176 行，seed42 配对相邻顺序 | 全部 not_started |
| RAG 开发比较 | 4 已知案例×3 条件×3 重复=36 分析级执行 | 全部 not_started；不是36独立案例 |
| 新人工事实复核 | 原8案例×B2/B3=16盲组槽 | 等待新实际输出，未复制旧判断 |
| F8 | 原全部88候选、264对、528分支 | 全部 not_started，包含所有失败/不适用候选 |
| R1/R2、源码冻结、出站与预算子账 | 最终真实 R1/R2 已通过；预算身份与运行入口已实现 | 源码冻结/新出站确认未齐，保持 non-executable |

开发固定 AIT `ait-f62148bdfdc29c83f078be92`、`ait-01cf26383c40c0635e8bf88f`；DEDALE `dedale-48c547812ab3dff1`、`dedale-17269286f7d83f21`。初始字面查询、入口 prompt、顺序与重复已登记；未来收集器模型动态生成的 query 尚不存在，只固定无标签生成策略及后续实际查询/payload 留存要求。控制侧选样分层不得送至 worker。

开发 RAG 条件为 empty/semantic/hybrid；F8 三条件沿用原 success/failure/no_change，双分支为 enabled/disabled，两者不能混同。F8 最低需要4 AIT+4 DEDALE、24完整对、至少8份真实计划审批；开发至少3次六分支真实试运行另计。所有新增执行仍需具体出站确认和有效逐计划实际审批。

## 工程修复与审查证据

证据根目录为 `D:\传智杯\data\task13\supplements\task13-repair-202610-v2`。各次失败回执与后续重验分别留存，不覆盖失败。

| 项目 | 实现与已核验证据 | 仍需核验 |
| --- | --- | --- |
| 采集参数与范围 | 实际 MCP 工具 schema、incident/时间/目标/limit 的精确拒绝；拒绝保留记录和调用计数；已纳入369项真实集成轮。`audit/collection-recorded-replay.json`、`collection-empty-{red,green}.txt` | 尚无真实新模型调用的改善幅度 |
| 诊断与响应 | 只消费封存诊断；fallback 仅对有引用主机的攻击生成，保留来源、影响、回滚、验证条件及 30 分钟 TTL；空计划/无目标/无效草稿分开保存。`response-recorded-replay.json`、`response-fix-report.md` | 实际新模型生成可审批计划的比例未知 |
| 阶段隔离 | 6 份真实原输出录制响应回放形成 12 份 B3/A4 执行；封存前请求与诊断一致。2 份非法计划转为有证据的 fallback，4 份主动空计划保持为空 | 回放不构成新审批或真实模型质量结果 |
| R1/R2 | 最终真实重验通过，见 `gates/gate-index-20261023T125227Z.json`；绑定最终 model_client SHA，已确认自建数据库和索引均不存在。3 项完整原知识库验收另通过，见 `rag-full-corpus-final-20261023.txt` | Docker 停机失败尝试 `attempt-20261023T123459Z-47a0c1cd63` 保留；录制模型响应不代表新模型效果 |
| 预算与新执行入口 | 100/15 与新增 6/16/6 原子约束，2 元保留不可自动使用；强制匹配原3350历史行摘要及active路径。F8/开发续期已接专用wrapper，开发真实计费development，读包/决定零模型。22新测试及140相关回归通过，见 `remediation-review-report.md` | 实际调用前仍须源码冻结、逐次真实隔离及具体出站确认 |
| 控制器与恢复 | 完整 36/176 矩阵、冻结配置、单写锁、持久 start、未知不重放；派发前中断可恢复，每次实际 gate 单独留存并由 start 绑定。23 项合同测试通过，见 `controller-red4.txt`、`controller-green4.txt` | 合同测试为离线合成，不计入真实运行 |
| F8 v2 | 全264/528追加状态、实际审批入口、同计划六分支、TTL与隔离约束；到期资源及坏回执恢复修复主代理独立重验60通过。旧opt-in夹具改为生产完整seal，fresh真实服务1通过0跳过，回执 `live-acceptance-80315c8cb01a46ff815b498a1bc1b13a.json` | 开发三次真实预演、实际新计划和审批、正式最低覆盖均为0；合成审批不计覆盖 |
| API 验收 | 原生产 verify/runner 与冻结起点一致；无效果观测应 manual_review/insufficient_evidence。旧测试预期与 crash hook 参数已修，最终 9 项真实隔离验收全部通过、0 跳过 | 回执 `live-acceptance-95e9a799b8f6469489bdf61ce76788d9.json`，cleanup=true、付费0；不构成真实用户审批 |

10月23日全量 evals 稳定轮为 **1515通过、3跳过**（不含已隔离另跑的2项environment_services，后者2通过0跳过）。3跳过分别为Windows无特权symlink、两个未显式开启的真实服务用例；后两项已分别补开通过，合成审批链的完整seal夹具修复未放宽生产校验。平台symlink限制保留。首次1394/4失败/3跳过及中途改fixture导致的1496/11失败/3跳过均保留。10月24日的新AnalysisOutput与输入序列化整改完成后，另行绑定最终全量证据，不用旧计数冒充新源码已验收。

最终后端采集/响应/RAG/domain/API/Task12 集成轮 369 通过、3跳过，回执 `live-acceptance-2fc225bce1a14c71b04636cde3372074.json`；3跳过为显式原知识全量RAG，已另行开启并3项通过。真实Task12安全检查在该轮均执行；自建数据库清理完成，付费调用为0。冻结测试缺少的被忽略输入已逐文件哈希复制到独立工作树，原数据未改。

独立原产物保护核验通过：七类原库存2734文件、4份主仓用户文档、283冻结主仓文件、预算3350行逻辑记录及原DB整体哈希均匹配，见 `audit/preservation-final-20261023T130223Z-512e30a9b4.json`。旧通用verify脚本曾因v2测试源码后续正常变动而失败，日志保留；该失败不表示旧v1产物被修改。

## 检查、限制与下一步

任务 A 使用生成脚本回读全部登记 JSON，验证数量、唯一性、初始状态、顺序哈希、盲组隐藏字段、文档保留、原 283 文件和所有旧产物绑定。结果以 `receipts/task-a-validation.json` 为准，验证命令和实际输出记录见 `audit/task-a-report.md`。没有新增产品测试，也没有付费调用。

父任务提供的先前基线记录为：verification plan / collection planner / collect policy 共49通过；freeze 为24通过、1项因隔离工作树缺少被忽略原数据而失败；沙箱临时文件权限另出现 WinError 5。任务 A 未重跑这些产品检查，不能把环境失败隐去或改写为全绿。后续修复仍需适当行为测试和真实 PostgreSQL/OpenSearch/MCP/Task12 服务验收。

开发分析已按原登记改用产品AnalysisOutput，保留完整引用及事实校验、合法unknown、单逻辑/最多3物理尝试且无fallback；仅模型分析上下文省略真实隔离incident资源ID，真实MCP仍引用原资源。不同PYTHONHASHSEED导致JSON键顺序变化的问题已在专用开发入口修复，v1默认payload不变。独立6进程真实HTTP录制证明仅替换knowledge字段后逐字一致，同条件重复原始请求体也一致，见 `analysis-context-exact-probe.json`、`analysis-helper-independent-review.md`；原RED保留。最后联合回归205通过0跳过，见 `runtime-v2-analysis-targeted-20261024-02.json`及其原始日志。

2026-10-24最终全量在fresh隔离数据库中执行，并显式开启实际服务探针及合成live verification：**1570 passed / 1 skipped / 0 failed，219.36秒**，见 `audit/evals-isolated-final-20261024.txt`与对应live-acceptance回执。唯一skip为`test_dedale_leak_inventory.py`的平台无特权symlink限制，必需服务检查均实际运行。40个新增/修改Python文件的Ruff检查通过，见 `ruff-changed-final-20261024.txt`。所有测试为零付费；数据库已清理，不计真实审批或F8覆盖。

10月24日再次只读核验原2734文件、4份主仓用户文档、283冻结主仓文件与3350原预算行，全部保持不变，见 `preservation-final-20261024T012104Z-0818199ab8.json`。当前公开模型版本/价格文件已重新取得并绑定，见 `provider-public-check-001a6e63fd79404bb891f7333a7477fa/receipt.json`；没有升级模型或知识。

下一步在具体新增出站确认及每次隔离/预算检查后执行36分析，保留所有成功、失败与unknown；开发六分支预演的源计划与用户实际审批另办。随后依序进行正式新冻结及出站确认、176回归、F8、16新人工判断、独立评分/费用对账及图表视觉检查。新增预算开发6、回归16、F8/续期6、未知保留2，共30元，仍受原总额100与累计开发15约束；新增付费调用为0，源码未合并回主仓。
