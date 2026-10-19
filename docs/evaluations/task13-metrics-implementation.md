# Task13 指标与图片实现说明

本说明记录实现与合成反例验证，不表示真实实验、人工审核或效果目标已经完成。测试图片只写入测试临时目录；未生成冒充正式结果的数值或图片。

## 评分输入与分母

`evals.metrics.score_rows(rows)` 接收控制/评分侧规范化字典，不读数据目录、不调用模型。每行包括 `case_id`、`applicability`、`gold`、`diagnosis`、`diagnostic_status`、`execution_status`，以及可选的可信 `evidence_registry`、`human_review`、累计 `usage`、`latency_ms`、`model_calls`、`tool_calls`。也接受实际 `AdapterResult` 的 `result.diagnosis_status` 与 `result.diagnostic_snapshot`，以及原图快照的 `diagnosis` 内层。`diagnostic_status` 与 `diagnosis_status` 兼容，但控制侧应统一使用已校验契约。

返回 `classification`、`evidence`、`attack_chain`、`resources`、`coverage`。主结果选择与所有尝试成本累计由运行器完成，评分器不选择更高分尝试。

- 二分类只读取明确适用的布尔 `gold.is_attack`；unknown、诊断失败、missing 均保留主分母，正类未答计漏检，正常未答计总体准确率错误。另报作答覆盖、条件准确率、FPR、正常正确判定率及正常未答率。处置/模拟后失败不抹掉已经成功的诊断。
- 六类固定为 `reconnaissance`、`credential_attack`、`webshell_upload`、`remote_command_execution`、`privilege_escalation`、`data_exfiltration`。零金标且零预测类 F1=0，保留六类平均，同时给出支持类平均。不可映射攻击依明确掩码排除，正常适用案例仍参与误报计数。unknown/failed/missing 的附带标签不计成功预测。
- 技术与阶段只使用明确冻结的适用掩码。当前 AIT taxonomy builder 没有提供独立 ATT&CK 技术及可区分阶段实例金标；不能从类名、选择窗口标题或知识库推造金标。DEDALE 六类/技术/阶段/来源掩码保持 false，其5/8阶段可观察覆盖不是逐案阶段评分授权。
- 引用有效率以全部引用出现次数为分母，可信注册表必须匹配本案、引用ID和有效64位 `content_sha256`（或兼容 `sha256`）。规范化评分输入如额外带可选 `evidence_hashes` 映射，则对应摘要也必须与可信内容摘要相符；该兼容字段不是规范 `Diagnosis` 的必需/新增模型输出。引用遍历顺序冻结为外层 `evidence_ids` → `origin` → `stage_instances` → `claims`，有效率保留重复。零引用为 N/A，另报零引用报告率。语义 P@5按此顺序去重、截取5条、不足补空；相关性只来自控制侧已校验的人审记录，存在性不能代替支持性。人审不确定项形成上下界。
- UCR 按实际审核的声明计算不支持下界与含无法判定的上界。审核导入器负责样本名单、报告哈希、人工身份、全部声明/引用覆盖和完整性的准入；未审核资料不能标为 `reviewed=true`。结果限预登记样本，不能宣布全量 UCR 达标。
- 阶段通过相同 phase 与至少一条相同冻结证据锚点建立候选，确定性最大二分匹配保持重复阶段实例独立。顺序只计算冻结DAG的传递闭包；缺失阶段/逆序关系计错，不可比较关系不计；零可比较关系 N/A。重复实例ID、非法关系与环拒绝评分。
- Token/费用缺失保持 null，另列已知小计、缺失数及原因。模型调用记录为逻辑调用列表，`physical_attempts`记录含重试的物理尝试数；工具台账兼容 `attempts`，仅累计实际收费逻辑调用及其尝试，`charged=false` / `source_call_id` 复用项不重复计费；预留槽位单列。延迟 p50/p95 为线性插值分位数，不是置信区间。

适用 case ID 列表保留在评分表中，消融图要求案例集合及分母一致。公开输出应使用中性案例 ID。

## 独立验证配对

`score_verification(records, planned_slots)` 单独评分 F8，不能回写诊断。预登记槽位为 `{pair_id,case_id,condition}`，condition只在控制/评分侧取 `success|failure|no_change`；分支记录为 `{pair_id,branch,status,approval_status,outcome,cost}`。

仅同一槽位的 enabled/disabled 两分支均完成且获批，并且启用分支有合法观测判定、禁用分支明确 `unverified` 时，形成共同可执行配对分母。缺少启用分支判定的“completed”记录不能计为完整配对或三条件完整案例。全部计划槽位、失败/missing、未验证和额外费用仍保留。禁用分支必须未验证，不能记为零误报达标。完整完成三条件的案例数单列；每数据集至少4案三条件完整是功能覆盖门槛，由最终验收结合真实计划与审核记录判断。

## 图片输入与重放

最终评分JSON固定外层：

```json
{
  "schema_version": 1,
  "run_id": "opaque-run-id",
  "metadata": {"model": "实际模型版本", "system_commit": "实际SHA"},
  "source_hashes": {"protocol": "实际sha256", "score_inputs": "实际sha256"},
  "groups": {"ait": {"B0": {}}, "dedale": {}},
  "verification": {"ait": {}, "dedale": {}}
}
```

每个组的值为 `score_rows` 的返回值；verification各数据集值为 `score_verification` 的返回值。绘图不调用模型、不重新评分、不更换主attempt。主分组固定 `B0 B1 B2 B3 A1 A2 A3 A4`。

```powershell
uv run --project services/backend python -m evals.plots.generate --scores <冻结评分JSON> --output-root docs/evaluations/figures
```

两数据集分别封存评分文件时，可重复传入 `--scores <AIT评分JSON> --scores <DEDALE评分JSON>`。合并要求相同 `run_id`、实际系统提交和模型身份；拒绝重复数据集，清单保留两个原文件的路径与原始字节SHA256。已存在同run输出如绑定不同评分输入，或存在未绑定的输出文件，绘图在写入前拒绝，防止单数据集空面板覆盖另一数据集已有结果。

按 `docs/evaluations/figures/<run_id>/<dataset>/` 导出 F1～F6、F8 各两组，F7仅AIT，共15张，均有300dpi且宽度至少1800像素的PNG、保留文字的SVG、同名CSV和图注。F2固定消融−B3，转百分点，负值保留，无法证明同案例集合时不画差值。F3人审上下界与程序引用校验分面；F4单位分开；F5执行与诊断独立面板；F6保留unknown/failed/missing列；F8读取最终配对汇总，八个面板展示成功判定、失败与无变化的误报成功、失败识别、无变化证据不足、三条件未验证率、计划/共同可执行槽位及独立模拟总费用/已知小计。禁用验证未答保持N/A，不能画为零误报；摘要图脚之外的完整说明保存在同名图注。

`figure_manifest.json` 绑定原评分JSON字节、上游来源哈希、绘图源码、固定配置、Matplotlib版本、实际中文字体文件及每个输出SHA256。Windows默认微软雅黑，其他环境可传 `--font-path` 指定中文字体；缺中文字体拒绝导出。缺数据仍输出明确 N/A/未完成状态，清单为 `incomplete`；空图不能作为实验完成证据。DEDALE F7只在清单注明N/A与冻结掩码原因，不生成零分图。

## 验证与现有冻结路径

手算反例覆盖二分类弃答/失败分母、六类零支持、无适用掩码、重复引用/跨案引用、空证据、人工不确定、缺用量、阶段重复实例/传递部分序/环，以及共同配对与禁用验证。绘图测试验证15组产物、哈希、PNG尺寸/dpi、缺失非零、负差值、不同案例拒绝差值及不安全run ID。

2026-10-19增量复核增加嵌套引用顺序/P@5、显式可选摘要不匹配、工具复用不重复计费、重复 `--scores` CLI、真实测试输出禁止覆盖、SVG文字保留、长中文图脚边界，以及F8未验证/费用实际绘制与缺少观测判定不算完整配对的回归。完整命令 `services/backend/.venv/Scripts/python.exe .tmp/pytest_inherited.py evals/tests/test_metrics.py evals/tests/test_plots.py -p no:cacheprovider --basetemp D:/传智杯/.tmp/metrics-plots-lint-final -q` 结果为 **26 passed in 19.53s**，同范围 `ruff check` 为 **All checks passed**。所有合成评分和图片仅落入该 `.tmp` 测试目录，没有写入正式figures目录。Windows沙箱内使用只对工作区 `.tmp` 下新测试目录保留继承ACL的临时启动器 `.tmp/pytest_inherited.py`；该工具不改产品权限校验，不导出给worker。对负差值、N/A及F4/F5/F8样图进行了中文、图例与边界目视核对；正式15张图仍须在真实评分冻结后逐张验收。

AIT已验收中性包位于 `D:\传智杯\.backups\task12-readiness\data\ait\cases\test\ait-*`，不是根目录 `data/ait/cases/test` 中保全的旧答案命名包；选择清单冻结SHA256为 `bbabb8b072c29a770863c4a6a88537e446305ba7006ff40afa2cf1229fdbbd3b`。依据 `docs/acceptance/task12-ait-hashes.json`。

DEDALE已验收原包位于 `D:\传智杯\data\dedale\priority-cases-v4`，selection SHA256为 `047c2887a8057a348fc0c07fd6c3773c9e61f39302f7f9d4b1f4979d4e9b5c79`。其内嵌 `prepared_not_frozen` 状态按原字节保全，冻结权威是外层验收receipt，不能为Task13改写原包。依据 `docs/acceptance/task12-dedale-freeze-2026-10-17.json`。
