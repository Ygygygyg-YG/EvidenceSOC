# Task13 E 空计划原因与终态修补设计

用户已明确选择“先完善后验证再进入真实计时”。本设计落实此前提出的空计划理由记录和失败分支处理，不新增模型发送、真实批准或计时。基线为4953a40dadfa4341ed05222fc28723e92e35f346，实施树为独立的task13-null-plan；旧冻结树、请求、结果及原账本保持原字节。

## 与整改计划的对应

原整改计划任务E要求至少三次完整六分支真实试运行，并在正式六分支派发前满足 `remaining > 1.5*M+300`，其中M来自真实完整六分支耗时。计时用于证明原1800秒TTL是否足够，不是模型效果实验、unknown阈值或F8覆盖；完整六分支最大耗时须含创建、隔离探针、克隆、调度、落盘与控制侧验证。现有第一次真实响应合法返回null，三次计时仍0/3。

## 方案选择与授权边界

只重发相同配置不能保证解决合法null。强制生成计划或把无理由null当schema错误重试会改写其合法语义。本次选择增加可选理由、如实记录缺失，并将无候选明确报告为阻塞终态。未知、真正异常和无候选分开；不自动推进剩余槽，也不自动替补、续期或重放。

## 产品理由

ResponseOutput新增可选`no_plan_reason: str | None = None`。旧的`{"response_plan":null}`保持合法，一次valid响应不得因缺理由重试或调用fallback。两套模型提示（实际评估TrackedModel和产品DeepSeekStructuredModel）请求模型在null时尽量附理由；该自然语言只标记为模型陈述，不当作已验证事实。

响应状态增加`no_plan_reason: str | None`和`no_plan_reason_missing: bool`。缺失、空字符串或空白按缺失记录；非空原理由可保留，显示时不可执行。稳定机器原因码`response_reason=model_returned_null`保持。有计划、非攻击及无效封印提前退出分支清除旧理由，避免检查点遗留。TypedDict与AgentRun.output_summary白名单同步扩展。不得修改导入诊断、证据、知识或封印。

## 专用E worker无候选终态

在成功计划保留检查前单独识别真实合法模型null。条件包括：实际received/valid模型记录与raw null对应、产品manual_review/model_returned_null/plan_source=model、无计划与批准、无异常、原导入来源与诊断封印一致、实际计划表无行。异常状态、封印不符或无效响应不得被这条路径掩盖。

不扩展AdapterResult顶层字段。复用verification字典报告`status=no_plan`、`response_reason=model_returned_null`、`no_plan_reason`、`no_plan_reason_missing`、`timing_eligible=false`及实际state摘要。产品状态manual_review，诊断succeeded；只有服务关闭、必要工件导出和资源清理均成功后，worker执行状态才为completed。这里的completed只表示有界产品操作正常结束，绝不表示有计划、计时完成或正式实验通过。

这条路径保存实际state、provenance、模型载荷与完整物理账本、工具账本，不retain，不生成case-resource。任何保存、关闭或清理异常仍为failed，保留原异常与实际费用，不能被无候选状态覆盖。正常有计划路径继续原有持久化、引用、TTL及retain检查。

## 宿主阻塞与恢复边界

ETrialController仅在原始stdout/worker结果相符、实际响应模型和指纹核对以及必要无候选工件核对后，将合法no_plan写为持久`status=blocked`，原因model_returned_null，并保存理由及缺失标识。重复plan同槽只返回原终态；status说明该批次没有计时候选。

read/decision/trial不得为blocked槽创建批准、保留资源或ETimingCampaign；后续ordinal不得写start、claim或发送，返回可解释阻塞。unknown、真正失败、预算/身份/来源漂移仍按原安全停机，不得伪造已知无候选结果。blocked不是timing终态，计时记录和成功计数不增加，正式导出仍要求三个真正完整trial。

用户之后若选择新模型发送，须以最终新源码与其实际schema/提示词生成新的具体范围确认、epoch和槽位；旧4953同配置替补提案不能覆盖修改后的版本。

## 验证

真实原分析的回放验收发现必要兼容边界：旧验证器要求models/nodes整个AST相等，新的纯说明字段亦被拒绝。新增严格正规化只消去本次已复核的ResponseOutput可选Field声明、respond内确切三条理由赋值语句、提前退出的None/False说明键和最终确切缺失标识表达式；禁止忽略整个类/函数，任何不同默认值、类型、调用或诊断/引用/目标/控制流变化仍不等价。原始Python只解析，不执行；新验证器自身字节进入artifact_verifier pin，新来源包必须另行导出，不修改旧manifest。全模块其余AST仍逐项相等，并保留原固定scope tuple校验。该兼容修补不允许更改旧诊断或增加真实模型调用。

先失败后通过的测试覆盖有理由/缺理由/空白、旧null一次valid且无fallback、审计持久化与遗留清理、worker无候选及清理/导出/关闭失败、host原始结果/指纹/来源核对、阻塞重开/后续槽无派发、review/decision/trial无计时信用。回放本次保存的实际null只作为录制响应离线输入，不能计真实三次计时。

保持旧有计划、严格TTL、产品批准、未知状态、隔离和正式176来源门禁回归。测试使用合成预算和明确隔离的临时目录；免费真实服务验收仅合成数据、无模型密钥。先完成离线验证及独立复核，再考虑实际服务验证和新冻结；本设计不授予新付费出站范围。
