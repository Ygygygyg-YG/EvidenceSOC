# Task13 v2 独立工程回归与模拟处置补充协议

2026-10-23（北京时间）。活动：`task13-repair-202610-v2`。本协议为任务 A 的调用前登记，当前 **non-executable / registered_not_executable**；保存协议与样本不表示通过门禁、出站确认、预算预占或计划审批。

工程验收的后续状态以 [整改进展报告](task13-remediation-report.md) 及逐项回执为准；本协议中“pending”指登记时状态，原登记 JSON 不回写成审批或可执行授权。最终真实 R1/R2 已通过，原预算历史身份与控制侧 active 路径均已接线；开发/回归的新出站确认、实际实验与人审仍未发生。

原研究保留在 `task13-campaign`，起点源码为 `11aff6cf08e5d4246e252c4b0031126716e761bb`。实施分支为 `codex/task13-remediation`，工作树为 `D:\传智杯\.backups\task13-remediation`。原主仓的三份已修改文档及新增整改计划逐字节哈希保存在 `D:\传智杯\data\task13\supplements\task13-repair-202610-v2\audit\baseline.json`，不得覆盖。原 704 行、评分、64 槽人工记录、失败/unknown/中断尝试和原 F8/G6/G7 未通过状态均保留。

本轮只用于已知案例上的工程回归、故障复现和模拟处置链路复验。正式数据已经被查看，不能重新称为未见测试集，也不能由本轮结果推出未见数据泛化能力。质量目标保持原定义，不通过换指标或删失败宣布达标。

## 登记文件和状态

控制目录是 `D:\传智杯\data\task13\control\task13-repair-202610-v2`，产物目录是 `D:\传智杯\data\task13\supplements\task13-repair-202610-v2`。下表全部是新 v2 文件，原 `preregister-.../final-20261020` 不变。

| 文件 | 内容 |
| --- | --- |
| `control/.../registration.json` | 禁止执行的总登记、原模型/上下文/调用上限参考、费用子额和全部 pending 门禁 |
| `control/.../regression-plan.json` | seed42 的 88 对、176 行 B2/B3 配对顺序及原输入哈希 |
| `control/.../development-plan.json` | 4 案例、36 分析级执行、固定字面查询、控制侧选择分层 |
| `control/.../query-prompt-plan.json` | 初始查询规则、入口 prompt 和原指令模板来源；未来动态查询的明确边界 |
| `control/.../human-plan.json` | 8 原案例、16 新槽、B2/B3 对照映射，仅控制侧使用 |
| `supplements/.../human/presentation-order.json` | 无组别和案例标识的 16 槽呈现顺序，等待实际新输出 |
| `control/.../verification-plan.json` | F8 全量 88 候选、264 对、528 分支和顺序 |
| `supplements/.../verification/candidate-status.json` | 每对/每分支的初始 not_started 状态；后续只按稳定 ID 幂等合并 |
| `supplements/.../audit/baseline.json` | 原 283 冻结文件、输出、评分、人审、997 知识块及缺口的只读哈希清单 |
| `supplements/.../audit/row-evidence-index.json` | 原 704 行所有已保存尝试的请求 ID、工具事件、工作流状态及来源哈希 |
| `supplements/.../audit/issues-evidence-map.json` | 六问题与真实路径/评分字段/请求/工具/状态的映射及审计未覆盖部分 |
| `supplements/.../receipts/budget-readonly-snapshot.json` | 原 SQLite 的 mode=ro、query_only 读取快照；未写旧账本 |
| `supplements/.../receipts/task-a-validation.json` | JSON 回读、数量/唯一性/顺序/绑定哈希核验回执 |

新源码冻结、R1、R2、新增开发出站、新增正式回归出站、预算子账预占、真实审批/TTL 试运行和真实服务安全检查全部待完成。原 528 行 DEDALE 出站授权不覆盖新增调用。所有登记 JSON 均无可直接派发的 `WorkerRunSpec`，控制侧分层、标签、评分、F8 真值和人审映射不得进入 worker。

## 176 行已知案例配对回归

沿用原 `ait-plan.json` 的 22 个案例和 `dedale-plan.json` 的 66 个案例，仅取 B2、B3 各一次。原 agent 输入哈希和 v1 行 ID 均保留，新增 slot ID 独立。

排序算法固定为 Python `random.Random(42)`：按原 AIT 然后 DEDALE 的 B3 案例顺序建立 88 案例列表，洗牌一次；对洗牌后每案例，用同一个 RNG 分别洗牌 `[B2,B3]`，相邻派发形成 88 对。顺序字面清单与 `order_sha256` 已登记，执行时不能重新随机化。

每槽保留成功、失败、unknown、拒绝、预算停止、全部物理尝试和费用。分数不好不构成重试理由。只允许在证据足够且协议允许时办理基础设施恢复；已经派发但状态未知的操作不自动重放，原 started/失败/费用均保留。176 槽全部达到可审计终态才算本项完成。

## 36 项开发分析与查询约束

开发案例按原 `review-plan.json` 的案例首次出现顺序，在各数据集中选择首个攻击和首个正常案例；分层只在控制侧由原 selection 核对。固定以下四例：

| 顺序 | 数据集 | case_id | 控制侧选样分层 |
| --- | --- | --- | --- |
| 1 | AIT | `ait-f62148bdfdc29c83f078be92` | attack |
| 2 | AIT | `ait-01cf26383c40c0635e8bf88f` | normal |
| 3 | DEDALE | `dedale-48c547812ab3dff1` | attack |
| 4 | DEDALE | `dedale-17269286f7d83f21` | normal |

每例依次执行空知识 `empty`、纯语义 `semantic`、混合 `hybrid`；每条件按重复 1、2、3 排列，共 4×3×3=36 项分析级执行。重复不是独立案例；一次分析可以有多次物理模型请求和重试，均须单独记录和计费，不取最好输出。

四条初始查询的完整字面值和 SHA256 位于 `development-plan.json`。规则为使用原冻结源码的纯离线 `load_seed`，读取哈希匹配的原 agent events，生成 `raw_seed_v1` 的前三条 summary，按原规范化 seed 的 `(observed_at,event_id)` 顺序，用 ASCII 空格连接，截取前 300 个 Python 字符。同案例三个条件和三次重复必须消费同一个已登记字面查询；不得用金标或条件真值改写查询。查询 provenance 绑定原 seed 代码、seed evidence ID 和 agent 输入哈希。原结果 registry 的 provenance 可被 scoped_tool 覆盖，因此不能靠过滤该 registry 重建 seed。

入口 prompt 的登记字面值为：`Use only supplied observable evidence and retrieved knowledge. Keep facts traceable to registered evidence_ids. Keep unknown when the evidence is insufficient. Never read control-side labels or case strata.` 原 model client 指令模板及源码哈希同时保存。修复后的开发 harness 需显式集成该入口契约，并在新源码冻结时绑定完整 schema、模板、上下文投影和最终 payload。

收集器后续由模型动态生成的查询尚不存在，不能声称其字面值已固定。本轮固定的是：真实参数 schema、原数据、工具权限、incident/时间/目标 scope、逻辑/物理预算、上下文限制和无标签的生成策略；新源码冻结后才能确定完整实现。真实执行必须保存每条实际查询及最终序列化 `payload.messages`。初始查询集成和条件间一致性须由无付费 R1/R2 验收；当前只是登记，不是该链路已经实现的声明。

## R1/R2、开发审批和正式冻结门禁

R1 在隔离开发数据库和原 997 条 ATT&CK 冻结块上，分别用精确 Technique ID 与普通文本验证通道；证明允许、真实 backend 请求、返回、打包、最终模型输入五个阶段。只看配置、`knowledge` 中间对象、历史 `knowledge_sent` 计数或请求哈希不足以通过。拦截真实 HTTP 发送边界，返回录制响应，保存完整 `payload.messages` 并覆盖前五块及字节裁剪。

R2 对每条件创建全新状态和独立结果缓存。空知识必须最终 0 块；纯语义真实走向量且精确 ID/关键词/回退调用为 0；普通文本混合真实走关键词与向量及现有 RRF，精确 ID 快捷路径另测。实际返回相同知识允许保留，不能人为制造差异或由相同最终知识推断知识内容改进判断。R1/R2 回执均通过且付费请求为 0 后，才可能开放开发批次。

在具体新增数据范围、端点、预算和子额确认后执行 36 分析和至少三次完整六分支真实试运行；实际用户审批与隔离服务均不能用合成观测替代。保持计划 TTL 30 分钟。每案例六分支开始前，剩余 TTL 必须严格大于 `1.5×实测完整六分支最大耗时+300 秒`。不足时在派发前按合法流程获取新审批；不能修改时钟或拼接跨到期结果。

开发完成后冻结修复源码、依赖、镜像、模型服务版本、知识、配置、价格、协议、样本及证据哈希，再进行正式新增出站范围确认。开发调用前确认和正式回归确认是两个阶段；当前均 pending。

## F8 全量候选与实际审批

F8 沿用原 `verification-plan.json` 的 **success / failure / no_change** 三种模拟观测条件，以及 **enabled / disabled** 双分支。它们与开发 RAG 的 empty / semantic / hybrid 是两个不同条件族。全量 88 候选、264 对、528 分支均登记；无计划、不适用、拒绝、过期、失败、unknown 和未执行必须保留，不按金标强造处置或换例。

按原 verification plan 中案例首次出现顺序，保留各案例内的原条件/双分支顺序，逐案例滚动；新的 pair/branch ID 独立，历史 ID 仅用于溯源，不复用旧 request ID 或 namespace。每案例先封存新 B3 诊断、形成可审核计划，由用户实际决定，再以同一个已批准计划版本和哈希执行六个隔离分支。最多一份待审批计划。F8 条件真值在控制侧，不进入模型输入。

用户可参与时段为北京时间 19:00–00:00。事实复核、出站确认、计划文档和 AI 初核均不构成处置批准。已完成终态不重跑，已派发未知不自动重放。执行中到期保留失败/不完整，不续期后拼接。事件追加并按稳定 ID 幂等合并，不能用末批覆盖原 264/528 的全量状态。

最低覆盖为 4 AIT+4 DEDALE，每例三条件，共 24 完整对和至少八份真实计划审批，开发审批另计。达最低覆盖仍继续处理其余候选，预算/期限停止时剩余保留原因。只由真实前后观测判定模拟有效/无效/不确定，模型计划与 fallback 分开报告，不能称为真实阻断。旧 v1 缺口保持不变。

## 16 槽新人工复核

原八案例固定为 AIT `f62148bdfdc29c83f078be92`、`21887c24004c4b9fc9237268`、`01cf26383c40c0635e8bf88f`、`65ca384561a7baac71075258`；DEDALE `48c547812ab3dff1`、`31366901ab5d8a44`、`17269286f7d83f21`、`e6f1903e5383e50a`（均带对应数据集前缀）。每案例 B2/B3 共 16 槽。

顺序是原 `presentation_order` 过滤至原 B2/B3 槽后的相对顺序。呈现文件仅含不透明 ID、R01–R16 编码和待填的实际输出字段；组别/案例/数据集/标签保留在控制侧，worker 不得读取。当前没有新报告或新人工判断，所有槽等待实际新输出。

用户逐项阅读新声明及引用后给出 supported/unsupported/undetermined，绑定实际输出、报告和引用哈希，并记录真实耗时与最终确认。不可复核保留客观缺失和原因，不换样本、不复制旧判断、不伪造时长。报告有效覆盖、UCR 上下界，明确单审阅人与样本限制；自动引用有效性不等于人工证据支持性。

## 费用、停止与交付

新增总额硬上限 30 元，开发 6、回归 16、F8/合法续期 6、未知及机动保留 2；仍受原总额 100 元和累计开发 15 元约束。子额均为计划值，目前未预占、未派发，不能自动转移。所有失败、重试、用量未知和在途预占均计入。旧 SQLite 只读快照不能代替每次派发前重新核对，历史缺失不可填零。

发生 R1/R2 未通过、源/模型/价格漂移、隔离失败、无效审批、TTL 不足、下次请求无法被所有适用上限保守覆盖或新数据出站尚未确认时，停止新的依赖派发并保留证据；可继续独立离线整理。停止不是实验通过，不能触发质量重跑。

原 F4 毫秒字段保留，派生显示秒数除以 1000；控制器、worker 和物理请求耗时分别报告，列计划 n/观察 n/缺测。AIT 固定六类 Macro F1、credential 支持 0、5/6 上限与原 0.85 目标同时报告，supported-class 指标仅补充。实际服务安全验收、36 项开发、176 行回归、F8、16 槽人审和图表视觉 QA 尚需后续真实证据。最迟 2026-10-31 如实交付结果与未解决事项，不能降低门槛以满足排期。
