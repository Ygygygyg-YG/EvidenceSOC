# Task 12 前三项集成记录

日期：2026-10-14（Asia/Shanghai）。本轮范围对应用户选定的 Task 12 Step 1～3。其余关口继续待验收，本记录不代表完整 Task 12 通过，也不授权开始 Task 13。

Step 1～3：已验收。原工作区的 60 个文件及 Git 状态复核保持不变。

受测源码提交：`1e857709d2c02d4e0643e6f5dbefe913e60b4cd9`。本记录提交只补充文档，未更改受测源码；本地 `main` 仍为 `1f1dbfa`。

## 1. 文件保全

原工作区 `D:\传智杯` 保持在 `task11-ait`，起始提交 `f21dda13b7997fc040b29bf3d3c3704a9db98fb2`。逐文件盘点确认 29 个已跟踪修改、31 个未跟踪文件，共 60 个；备份通过 ZIP CRC 与逐文件 SHA256 校验。

保全目录：`C:\Users\31209\.codex\visualizations\2026\10\14\01a1382b-4bcc-7043-8631-40087915f690\pre-integration-backup`。

| 分类 | 文件数 | 去向 |
| --- | ---: | --- |
| Task 6/8 增强、测试、映射及集成迁移 | 38 | 三方合并到集成分支 |
| Task 10 的迁移与样例导入 | 4 | 三个迁移与 Task 10 分支字节一致，沿用合并版本；导入脚本保留并支持指定 API |
| 文档与保全配置 | 5 | 保留来源文件和本次记录 |
| 来源待核实的评测文件 | 13 | 保留在原工作区与备份，不进入集成分支 |

最后一组原本已存在于工作区，抽查其中三份文件的时间显示生成于 2026-10-12，部分修改于 10-13。时间戳不能证明作者，也不能证明用户已经开始 Task 13。本轮未开发或执行这些文件；执行的 `evals/tests` 来自已提交的 Task 11。

恢复资料包括 `working-files-verified.zip`、原始字节差异 `working-tree.patch`、`git-status.bin`、`inventory.json`、`classified-inventory.json`、分支图及 `untracked-disposition.json`。在新目录解压 ZIP 后按 inventory 校验哈希；需要重建原状态时，以上述 Task 11 提交建立独立工作树，再应用原始差异和未跟踪文件。不要整文件覆盖已有共享改动。

## 2. 提交与迁移整合

使用已被 `.gitignore` 忽略的独立工作树 `D:\传智杯\.backups\task12-readiness`，分支 `codex/task12-readiness`。从 `main` 的 `1f1dbfa` 开始，分别以保留历史的合并提交纳入 Task 10 `3d8880f` 与 Task 11 `f21dda1`。

核对全部九个重叠路径，解决 `agents/model.py`、`agents/services.py`、`persistence/tables.py`、`tests/agents/test_services.py` 四处三方合并冲突。保留 Task 10 的审批身份、方案版本、幂等回执、响应复核字段、逐动作验证；同时纳入 Task 6/8 的有限取证、恢复台账、证据幂等、预算及数据集边界。

实际接口修复：MCP 查询参数只包含白名单字段，`source_scopes` 留在调查上下文中；它仍为审批后多目标验证提供范围依据。另修复集成版本的 Python 类型检查，不放宽模型输入验证。

审查后补充恢复修复：同一次验证中已失败的调用复用原台账，保留已用物理尝试次数，不在恢复时重新获得重试额度；新的验证运行仍可独立查询。回归先复现两项失败，再通过全部 30 项台账与服务测试。

Alembic 历史保持两个既有父链，在 `e902c4b7a1d6` 汇合，只有一个 head。原开发库先备份为 `development-database.dump`，再恢复为隔离副本 `evidencesoc_task12_20261014`。升级和 `alembic check` 均通过；升级前后原库及隔离副本全部 20 张受核对表的行数一致。单独的空测试库也从初始迁移通过两条父链升级到同一 head。OpenSearch 使用独立索引 `task12-readiness-20261014`，保留 `dataset_id: keyword` 映射。

数据库证据位于同一 artifacts 目录的 `database-before.json`、`database-after-integration.json` 和 `task68-fresh-migration.log`。测试设置与含凭据的本地运行配置存放在被忽略的 `.backups/task12-runtime`，不提交。

## 3. 攻击链与浏览器闭环

React Flow、阶段列表和详情同时显示阶段、主机/服务、时间和置信度。主机、服务仅投影节点引用且内容哈希一致的持久化事件；信息冲突或缺失时显示“未提供”。时间明确按 UTC+8 展示；步骤缺少独立置信度时显示“置信度未提供”，不借用案件分类置信度。

真实浏览器分别使用独立告警、调查和方案验证批准、拒绝。页面代理与直连后端均为 `http://127.0.0.1:8012`，新 Web 进程为 `http://127.0.0.1:3012`；`CI=1` 且配置禁止复用旧 Web 进程。启用本地演示账户后从告警列表启动调查，核验原始证据来源、查询和重新计算的 SHA256。检查 1440×900、1920×1080 两种视口、刷新后的持久化记录及控制台错误。

批准必须实际记录六角色完成、逐动作模拟结果和效果验证；拒绝必须记录理由并终止调查，既无模拟执行也无验证结果，拒绝后的批准请求返回 409。缺少真实验收变量或代理地址不一致时明确失败。

真实运行发现并修复前端引用边界错误：审批输入引用属于原方案；验证输出可引用新查询产生的证据，检查项必须引用 `validation_result.evidence_ids`。保留方案 ID、检查 ID、枚举、日期及证据注册表的一致性校验。回归先复现实际响应的 `INVALID_RESPONSE`，再验证合法新证据能解析、注册表外引用仍被拒绝。

| 支路 | 调查 ID | 方案 ID | 持久化结果 |
| --- | --- | --- | --- |
| 批准 | `IV-01M4WYFPBXN3DBPQXEYCB4FM5A` | `RP-87adbd161d868d47c0e1b3c6` | completed；10 条证据，1 个模拟动作，验证 success |
| 拒绝 | `IV-01M4WYGBQG7Z62194G986B5AX9` | `RP-1eaa89e5025b77fc623a604a` | rejected；10 条证据，0 个模拟动作，无验证结果 |

两支路均验证 1440×900、1920×1080，无横向溢出，控制台错误数组为空。详细证据见 artifacts 中的 `browser-acceptance-summary.json`、`approved-live-flow.json`、`rejected-live-flow.json`、`playwright-final-report.json` 与截图。

## 4. 验证结果

| 检查 | 本轮结果 |
| --- | --- |
| Task 11 已提交的数据处理测试 | 522 passed，0 failed，0 skipped |
| 最终完整后端测试（真实 PG/OpenSearch/MCP 开启） | 684 passed，0 failed，3 skipped；仅完整锁定 RAG 语料/模型验收的显式 opt-in 用例跳过 |
| 类型修复覆盖回归 | 181 passed，0 failed，1 skipped（真实数据库标志未开启时的存储用例） |
| 前端单元测试 | 105 passed，0 failed |
| 前端 lint、项目 typecheck | 退出码 0 |
| 后端 Ruff | 退出码 0 |
| 后端 Mypy | 74 个源文件通过 |
| 生产构建 | `pnpm --dir apps/web build` 退出码 0 |
| 完整 Chromium 回归 | 61 passed，0 failed，0 skipped；包含两条真实支路，最终一次运行 156.776 秒 |
| 最终代码审查 | 通过；台账恢复及新证据契约修复均已复核，无未解决的重要问题 |

真实 API 的审批、拒绝、并发审批、重启，以及 collect 内三个中断点恢复均实际执行。三个可选 RAG 用例的跳过不记作完整 Task 12 Step 4 的通过。本轮第一次浏览器验收在两处重复审批理由文本的定位上失败，已限定到人工决定区域。后续运行保留了服务中断、页面超时以及实际证据契约错误的失败记录；最终使用受控后端生命周期与单 worker，避免共享统计的并行写入。失败和重跑信息保存在 `browser-run-history`、`playwright-interrupted-report.json` 与 `contract-failure-approve.md`，不把失败尝试记为通过。

本轮未作性能达标判断。后端最终回归跨越客户端中断，墙钟时长 9043.54 秒；该值不能当作系统吞吐或延迟指标。

复验命令（Python 使用已有 venv，并让 `PYTHONPATH` 指向本集成工作树）：

```powershell
Set-Location 'D:\传智杯\.backups\task12-readiness'
python -m pytest services/backend/tests -q -rs
python -m pytest evals/tests -q -rs
python -m ruff check services/backend
python -m mypy services/backend/src
python -m alembic -c services/backend/alembic.ini heads
python -m alembic -c services/backend/alembic.ini upgrade head
python -m alembic -c services/backend/alembic.ini check
pnpm --dir apps/web lint
pnpm --dir apps/web typecheck
pnpm --dir apps/web test
pnpm --dir apps/web exec playwright test --workers=1
pnpm --dir apps/web build
```

真实后端测试显式设置 `EVIDENCESOC_TEST_POSTGRES=1`、`EVIDENCESOC_TEST_OPENSEARCH=1`，使用可丢弃测试库。浏览器设置 `TASK10_LIVE_ISOLATED_BACKEND`、`TASK10_LIVE_SEED_ALERT_ID`、相同的 `BACKEND_URL`、`PLAYWRIGHT_BASE_URL` 及 `CI=1`；演示账户后端的 `FRONTEND_ORIGIN` 匹配 Web 来源。样例导入使用 `scripts/seed-task10.py --api-url http://127.0.0.1:8012`。当前本机受控启动入口保存在被忽略的 `.backups/task12-runtime/run_browser.py`。凭据配置不进入报告或 Git。

## 5. 后续关口

本轮结束后保留集成分支与干净工作树。依原计划，完整 Task 12 仍需 Step 4 遗留服务与环境验收、Step 5 AIT 异路径重建、Step 6 DEDALE 数据准入和冻结；全部通过后才推进本地 `main`。本轮不把前三项通过写成整个 Task 12 完成。
