# Task13 整改：36 项开发分析实录

本记录只描述活动 `task13-repair-202610-v2` 的已执行开发分析。原 704 行结果、64 槽人工记录、旧 F8 缺口和主工作区未提交文档保持不变。

36 项已于北京时间 2026-10-25 10:23:45 全部终态。模型执行使用原冻结提交 `b1666d38d5fc0467102166beafe229d87f826539`，当前下一版免费工程位于另一工作树 `D:/传智杯/.backups/task13-stage-e`，不能将其修改归入本批已运行条件。

## 实际结果与分母

固定 4 个已知案例 × 3 个知识条件 × 3 次重复，共 36 项，不是 36 个独立案例。25 项通过原输出、引用及事实校验，11 项失败。合法诊断为 attack 1、benign 3、unknown 21；unknown 占全部登记槽 21/36=58.3%，占合法诊断 21/25=84.0%。通过校验不等于人工证明所有声明均正确，也不等于质量目标达成。

| 条件 | attack | benign | unknown | 失败 | 合计 |
| --- | ---: | ---: | ---: | ---: | ---: |
| empty / disabled | 0 | 1 | 8 | 3 | 12 |
| semantic_only | 0 | 2 | 4 | 6 | 12 |
| hybrid | 1 | 0 | 9 | 2 | 12 |
| 合计 | 1 | 3 | 21 | 11 | 36 |

7 个失败槽耗尽物理分析尝试，保存的 21 份候选均经冻结校验离线重放证明来源范围与观察地址不符；另 4 槽在模型调用前失败。第 5 槽未保存足以追认具体底层原因的历史错误内容，不补写原因。失败不能归为合法 unknown。

共发生 32 次逻辑分析、49 次物理模型请求。全部新请求已结算，已知费用和保守占用均为 0.32985832 元，新增用量未知 0、在途 0。新增开发合计 6 元中剩余保守空间为 5.67014168 元，仍受原累计开发 15、原总额 100、整改合计 30 及各子额约束；这是账本记录，不是供应商实付账单。历史 3350 行前缀及其中原有两笔用量未知保持不变。

## unknown 的已知线索与解释边界

本批仅运行分析：使用既有机械 seed 和固定查询，不执行完整 B3 收集补证流程。`load_seed` 从时间排序事件开头选最多 20 项，并受字节上限约束；检索知识是背景材料，不是现场行为证据。DEDALE 两案各有 8 项 unknown、1 项模型前失败。模型保存的声明主要描述浏览器、DNS、更新程序及服务活动，未给出足够支持攻击的行为链。此为实际输入和模型叙述线索，不代表人工已判定这些弃答均合理。

AIT 正常维护案例在 empty 条件的三次请求拥有相同实际 HTTP body 摘要 `104ad759343a2ecd6e5cbb5f5945de64c7abc9ab37b302bc19b5f0f8812664fd`，结果分别为 benign、unknown、unknown。说明相同输入下存在实际判定变化，不能将全部 unknown 单归因于检索失败；已有五块知识入上下文的请求也仍可弃答。不能从四个已知案例的重复次数推断总体弃答率或知识条件的因果效果。

下一版提示补充了原地址范围约定，并明确来源归属、ATT&CK 映射与 verdict 分开：缺少来源或技术 ID 本身不强制 unknown；benign 需要现场证据正向解释正常行为，单纯未见攻击不够。相关 44 项离线测试通过，验证系统消息进入真实序列化发送边界及原事实约束仍拒绝错误来源范围；未声称真实 unknown 率已因此降低。完整收集闭环的真实表现由随后登记的 176 行补充回归保留和验证，不追加重跑原 36 项来取得更好的结果。

## 试跑和正式回归条件

只有第 9 槽 `development-0444ddc74df35fc4080bd02c` 提供合法 attack。现有“取原顺序前三个合法来源”的设计尚不能得到三份来源，不能伪造来源或把同一审批复制三次。若采用同一合法来源、三个独立新计划/审批/资源的工程计时方案，必须作为新阶段明确预登记其相关重复，并完成新入口、真实服务验收及具体调用确认；不能更改本批结果或冒充三个独立案例。

尚未完成：至少三次真实用户审批的完整六分支计时试跑、TTL 可行性、新版本冻结、176 项正式补充回归、F8 最低 24 完整对和八份正式真实审批、16 槽新人工复核、正式评分图表及最终交付报告。

协议没有“unknown 低于某百分比即可正式开跑”的规定。开跑仍要求工程/检索/隔离门禁、完整开发核验、真实审批试跑、预算与数据出站确认；质量目标与功能完成分别报告。

2026-10-26 范围澄清：这里的正式补充回归仅指原 88 案例的 B2/B3 共 176 行；不恢复或重跑原 704 行。F8 最低覆盖和新 16 槽人工复核属于之后的补充验收，不要求在 176 行开始前全部完成。原 36 项开发分析已结束；开跑前未完成项为试跑入口验收、3 次真实批准的完整六分支试跑、TTL 可行性、最终冻结及具体出站确认。免费工程的新证据见 [阶段 E 工程进展](task13-stage-e-engineering-20261026.md)。

## 绑定证据

- [终态回执](D:/传智杯/data/task13/supplements/task13-repair-202610-v2/development/preflight-b1666d38d5fc0467102166beafe229d87f826539/execution-analysis36/continuation-result.json)
- [实际续跑和退出记录](D:/传智杯/data/task13/supplements/task13-repair-202610-v2/audit/analysis36-real-continuation-20261025-01.json)
- [完整只读比较](D:/传智杯/data/task13/supplements/task13-repair-202610-v2/development/comparisons/20261025T061519Z-e4b08c6377ab/comparison.json)
- [36 行 CSV](D:/传智杯/data/task13/supplements/task13-repair-202610-v2/development/comparisons/20261025T061519Z-e4b08c6377ab/analysis36.csv)
- [比较文件清单](D:/传智杯/data/task13/supplements/task13-repair-202610-v2/development/comparisons/20261025T061519Z-e4b08c6377ab/manifest.json)
- [开发诊断分布图（已视觉检查）](D:/传智杯/data/task13/supplements/task13-repair-202610-v2/development/figures/analysis36-20261025T063919Z/analysis36-distribution.png)
- [分布图 SVG](D:/传智杯/data/task13/supplements/task13-repair-202610-v2/development/figures/analysis36-20261025T063919Z/analysis36-distribution.svg) · [图表 CSV](D:/传智杯/data/task13/supplements/task13-repair-202610-v2/development/figures/analysis36-20261025T063919Z/analysis36-distribution.csv)
