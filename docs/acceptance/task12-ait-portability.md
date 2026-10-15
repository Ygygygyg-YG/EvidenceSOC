# Task 12 Step 5：AIT 异路径重建验收

验收日期：2026-10-15。测试代码及冻结选择清单版本：`69c0d1e1d578ab1907a14c1fdb056e19151c41f9`。原工作区 `D:\传智杯`、其 AIT 数据和 Task 13 文件未改动；本步正式模型运行次数为 0，未开始 Task 13。

## 结果与证据

当前工作区为 `D:\传智杯\.backups\task12-readiness`，分支为 `task12-readiness`；另一目录为全新 detached checkout `D:\传智杯\.backups\ait-portable-checkout`。两目录以同一版本执行。另一目录在获取输入前和完成重建后 `git status --porcelain` 均为空。

按来源清单复制并校验 **149 个文件、13,873,020,979 字节**；18 个来源 profile 均重新验证官方归档 MD5、六类输入（archive/raw/labels/events/gold/join_report）的 SHA256 及原始归档绑定。来源清单 SHA256 为 `dd18477824146bf83c5dfc31f02a389d04ce97b22492dda43a4070c7cc1b699a`，两处相同。原始数据和生成包均留在 Git 忽略目录。

当前目录与另一目录各实际重建全部 **22 个测试包**，Agent manifest/events、评分 manifest/gold 及额外 source-gold 五项逐包 SHA256 全部一致；选择清单重新生成后的 SHA256 亦相同：`bbabb8b072c29a770863c4a6a88537e446305ba7006ff40afa2cf1229fdbbd3b`。每个案例的完整当前/异路径 SHA256 对照、旧/新哈希、原始日志路径和日志哈希见 [机器证据](task12-ait-hashes.json)，其中 `test_cases` 含要求的 22 × 4 项对照及额外 source-gold。

两次真实包审计均断言：development/validation/test 场景数为 5/1/2 且无交集，测试攻击 11、正常 11、消融 22，窗口互不重叠，身份连接完整，Agent 无金标。当前活跃测试包目录恰好 22 个中性名称，没有额外 legacy 包。

22 个测试包与 8 个开发/验证包合计 **9,800 条事件**：攻击 8,707、正常 1,093，评分 unknown 为 0。逐行验证 dataset/log/line/external_id/raw_hash 连接。原始 join 中未标注行仍保留 `unlabeled_unknown` 原值；完整性断言为 parse_errors=0、unmatched_annotation_lines=0、raw_line_count=read_events，评分侧继续使用既有完整标注缺席政策，没有重写原始标签。

全量 `evals/tests`：当前工作区 **538 passed，0 failed/skip，70.73 秒**；最终同版本 clean alternate checkout 亦 **538 passed，0 failed/skip**（JUnit 记录 73.138 秒）。AIT Ruff check 通过，9 个修改 Python 文件的格式检查通过。回归覆盖原路径输入移除后的异根重建、非规范路径/逃逸、六输入哈希篡改、答案 ID/目录拒绝、标签无关的中性 ID、选择清单重新生成与旧版默认行为兼容。

## 机械变更与保全

`build.source_config`、`build.splits`、`input_sha256` 键以及 completeness proof v2 的 dataset_root/六输入路径均以显式 data_root 解析。数据根路径和 proof 生成时钟不进入新哈希；旧生成时间、proof 哈希和绝对来源只存准备侧 provenance。

中性 ID 为 dataset/scenario/split/window/来源相对日志路径/max_records 的 SHA256 前 24 位，加 `ait-` 前缀。标签、攻击阶段、答案类型和 legacy ID 不参与计算。portable builder 强制 ID 与目录匹配，准备侧选择清单保留 legacy→new 映射。30 个包的 events/gold/source-gold 字节与旧包完全一致，Agent manifest 仅 case_id 改变；评分 manifest 随路径、proof hash 与 ID 机械更新。

| 选择清单 | 原始文件 SHA256 | UTF-8 LF 规范化后 SHA256 | portable 与中性 ID 冻结后 SHA256 |
|---|---|---|---|
| `ait-task11-test-selection.json` | `3be08f6a7b787c70ffe61fca7d96ec8bc51d61778b7e7f20194df89439de46ec` | `464cce85138f768154b439c644dfddeb8a4f4cc756b99697f1d89bc5045a862d` | `bbabb8b072c29a770863c4a6a88537e446305ba7006ff40afa2cf1229fdbbd3b` |
| `ait-task11-dev-validation-selection.json` | `59499849152a8cf45ce44e251d9098450dad5afe076a7acd761db1fdfc53ba5e` | `d43d802e0a69d2d40c1b5611d66fa11ed385533fc29d0326f50b8f8078d4c706` | `668ece29256f7f75acc093808af351d5c277ca8951ff14881b019c83a241da9f` |

中断时生成的两个 legacy 临时包已逐文件 SHA256 校验后，保全到当前工作区 `.backups/ait-portability/legacy-interrupted-cases`。原 `D:\传智杯\data\ait` 的 30 个旧包和元数据 SHA256 再次核对均未变。详细移动证据保留在机器记录的 `preserved_interrupted_legacy_packs`。

## 实际命令

以下采用本机 Python 3.12 虚拟环境；新机器可替换解释器路径。data_root/frozen_root 均是显式参数，取得同一验证输入镜像及冻结参考包后可在任意新绝对目录执行。`acquire` 是逐哈希验证的复制入口，数据解析以传入的根为准。输出采用不覆盖策略，复跑使用新的目标目录。

```powershell
$python = 'D:\传智杯\services\backend\.venv\Scripts\python.exe'
$art = 'C:\Users\31209\.codex\visualizations\2026\10\14\01a1382b-4bcc-7043-8631-40087915f690'
Set-Location 'D:\传智杯\.backups\task12-readiness'
& $python -X utf8 scripts/ait_task12_portable_rebuild.py acquire --source-data-root 'D:\传智杯\data' --data-root 'D:\传智杯\.backups\task12-readiness\data' --report "$art\step5-canonical-acquisition.json"
& $python -X utf8 scripts/ait_task12_portable_rebuild.py freeze --data-root 'D:\传智杯\.backups\task12-readiness\data' --legacy-cases-root 'D:\传智杯\data\ait\cases' --report "$art\step5-test-freeze-neutral.json"
& $python -X utf8 scripts/ait_task12_portable_rebuild.py freeze --data-root 'D:\传智杯\.backups\task12-readiness\data' --selection 'manifests/ait-task11-dev-validation-selection.json' --legacy-cases-root 'D:\传智杯\data\ait\cases' --report "$art\step5-dev-validation-freeze-neutral.json"
& $python -X utf8 scripts/ait_task12_portable_rebuild.py rebuild --data-root 'D:\传智杯\.backups\task12-readiness\data' --frozen-root 'D:\传智杯\.backups\task12-readiness\data' --report "$art\step5-canonical-rebuild.json"
& $python -X utf8 scripts/ait_task11_audit.py
Set-Location 'D:\传智杯\.backups\ait-portable-checkout'
& $python -X utf8 scripts/ait_task12_portable_rebuild.py acquire --source-data-root 'D:\传智杯\.backups\task12-readiness\data' --data-root 'D:\传智杯\.backups\ait-portable-checkout\data' --report "$art\step5-alternate-acquisition.json"
& $python -X utf8 scripts/ait_task12_portable_rebuild.py rebuild --data-root 'D:\传智杯\.backups\ait-portable-checkout\data' --frozen-root 'D:\传智杯\.backups\task12-readiness\data' --report "$art\step5-alternate-rebuild.json"
& $python -X utf8 scripts/ait_task11_audit.py --data-root 'D:\传智杯\.backups\ait-portable-checkout\data' --case-root 'D:\传智杯\.backups\task12-readiness\data\ait\cases\test' --rebuild-root 'D:\传智杯\.backups\ait-portable-checkout\data\ait\rebuilds\test'
& $python -X utf8 -m pytest evals/tests -q --basetemp 'D:\传智杯\.backups\task12-runtime\ait-alternate-final-tests' --junitxml "$art\step5-evals-alternate-final.xml"
```

实际先从 `9cc4d51066ca9a22c5befd52beb3286624495038` 建立全新 checkout 并复制输入，再切换到含最终测试选择的 `69c0d1e1d578ab1907a14c1fdb056e19151c41f9` 后执行重建；两提交的 AIT 实现相同。复制日志、命令结果、两组逐包重建日志及其 SHA256 均见机器证据 `artifact_logs`。

## 来源归档

| 文件 | 字节数 | 官方 MD5（实际验证） | SHA256（两处实际验证） |
|---|---:|---|---|
| `ait/downloads/harrison_no-pcaps.zip` | 667,985,140 | `4e837053ce4c5496227e0a3b65048c1c` | `03aeaf16acc79c8e89bb4ac147d3273bfcef4134d301aa62cb6cdd79e77084f1` |
| `ait/downloads/santos_no-pcaps.zip` | 576,734,274 | `cb484a2c55ea03c63c556f0531fe8367` | `af69973fbf4edeb6a26f1e4ebeae97b577f0263cec15bda0d987cc470425be5d` |
| `ait/downloads/shaw_no-pcaps.zip` | 1,319,137,852 | `f890a1f52bc9f893b44254ad86118e39` | `825ef8ac66cffeb9f799df18621ce7f35a4b3225350d10768ae80305310b8e0b` |
| `ait/downloads/wardbeck_no-pcaps.zip` | 818,462,147 | `14eeacd83571a83615c2cce1f6a6eacf` | `07fe8955e39d2c3531b31903cab3200d19db5d291159ba1485ac30a0a937cb58` |
| `ait/downloads/wheeler_no-pcaps.zip` | 767,673,839 | `774a146275a22707ee78bcb4574aca23` | `01f49e8c66b453fca8d3ebb3e4b35788acef150c8bbfc412085f53e0308aea0d` |
| `ait/downloads/wilson_no-pcaps.zip` | 1,083,526,183 | `98285593473dc05d0a6899f7cdefcd2d` | `e7a6e0d3d7ac3cde9354ada2e593dd0e3d9c50007adae426f9f5979e2d697c20` |

AIT 正式计划仍为 `4N + 4M = 176` 次，未为补足原 288 次目标切分重复窗口。这些模型比较属于 Task 13。本记录仅关闭 Task 12 Step 5；Step 6 与主分支推进另行验收。
