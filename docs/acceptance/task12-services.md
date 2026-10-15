# Task 12 Step 4：集成服务验收

检查日期：2026-10-14～15，Asia/Shanghai。集成工作树为 `D:\传智杯\.backups\task12-readiness`，分支 `codex/task12-readiness`。本记录只覆盖 Step 4；完整 Task 12 仍受 Step 6 约束。

证据根目录：`C:\Users\31209\.codex\visualizations\2026\10\14\01a1382b-4bcc-7043-8631-40087915f690`。含密码的连接配置只在被忽略的 `D:\传智杯\.backups\task12-runtime` 中保存。

## 环境与持久化

当前路径、CPU、宿主机内存、Docker 资源及工具版本见 [环境核验](../environment-verification.md)，原始结果为 `step4-environment.json`。新增 `infra/acceptance.compose.yaml` 使用独立 Compose 项目、独立卷和本地端口 5433 / 9202；原开发服务继续使用 5432 / 9201。

PostgreSQL 17.11 和 OpenSearch 3.8.0 均健康。单节点 OpenSearch 的 yellow 表示副本无第二节点可分配，主分片可用。先在两套隔离存储写入同一标记，再实际执行 `docker compose -f infra/acceptance.compose.yaml restart postgres opensearch`，等待健康后读回；2026-10-15 宿主机重启后再次读回。每次均核对内容，并从读回的 JSON 重新计算 SHA256：`38d8f3879417c339378618a95044bec3c4c3b3cec5f8e218f1bf1609e228c76d`。

证据：`step4-persistence-before.json`、`step4-persistence-after.json`、`step4-original-and-host-readback.json`。验收脚本只重启隔离项目，未重启原开发项目。

独立索引服务按仓库模板安装 `security-events`，源文件 SHA256 为 `5ee21101f1513495217bde5429f395aa60a013719f860eef2df1ada97ff0fa80`，读回确认 `dataset_id` 为 `keyword`。安装应答和映射保存在 `step4-opensearch-template-setup.json`。

## 数据库迁移与原数据

先对原开发数据库 `evidencesoc` 做只读备份，再恢复到 5433 的全新可丢弃库 `evidencesoc_task12_migration_rows_20261015`；所有降级只在该副本执行。备份 `step4-development-20261015.dump` 为 2,605,372 字节，SHA256：`f7948ebdbb43aec06fbafa43d31ad05e73ad6f063cf99166b973d19e171e4cc6`。此前的备份仍保留。

实际命令顺序为：

```powershell
# DATABASE_URL 必须指向上述 5433 可丢弃副本。
python -X utf8 -m alembic -c services/backend/alembic.ini upgrade head
python -X utf8 -m alembic -c services/backend/alembic.ini downgrade -1
# 上一条在双父 merge head 报 Ambiguous walk，退出非零且未改变数据。
python -X utf8 -m alembic -c services/backend/alembic.ini downgrade f3f8c2a59010
python -X utf8 -m alembic -c services/backend/alembic.ini upgrade head
python -X utf8 -m alembic -c services/backend/alembic.ini check
python -X utf8 -m alembic -c services/backend/alembic.ini heads
```

`e902c4b7a1d6` 有两个父版本，不能用不指定分支的 `-1` 唯一选择父节点；指定父节点后撤销的只有这个 merge revision，版本表恢复两个父 head，再升级汇合为唯一 head。迁移文件和历史保持不变。该处理与 [Alembic 的分支与合并说明](https://alembic.sqlalchemy.org/en/latest/branches.html)一致；不把失败的相对降级命令记作成功。

原开发库、恢复副本的升级前与最终升级后，全部 24 张表的行数及逐行内容摘要一致；显式降级中间态的 23 张非版本表也一致。其中包括原先 20 张受核对表及 4 张 checkpoint 表。最终唯一 head 为 `e902c4b7a1d6`，`alembic check` 退出码为 0。完整命令输出及各表摘要见 `step4-migration-replay.json`、`step4-fresh-clone.json`、`step4-original-and-host-readback.json`。

## 真实服务与回归结果

最终完整后端回归为 **694 passed、0 failed、0 errors、0 skipped**，pytest 耗时 236.46 秒。23 个关键真实服务用例全部实际通过：新增服务/预算 7、真实 TCP API 7、checkpoint 1、OpenSearch 场景边界 1、完整 RAG 3、依赖 3、PostgreSQL readiness 1。1 条 warning 为第三方 Starlette 的 AnyIO 弃用提示，不影响断言。

| 测量 | 样本数 | 实测结果 | 既定门槛 |
| --- | ---: | ---: | ---: |
| 首个 SSE 事件 | 1 | 65.0084 ms | < 2,000 ms |
| 普通告警列表 TCP GET P95 | 100 | 9.1274 ms | < 500 ms |
| 普通案件详情 TCP GET P95 | 100 | 21.6829 ms | < 500 ms |
| 完整固定知识库 Recall@8 | 12 条预设查询，997 个匹配来源/模型的 chunk | 1.000 | ≥ 0.80 |

API 数据为本机环境测量，SSE 只有一个样本，不推算生产吞吐或尾延迟。完整 corpus 副本共有 999 行，其中 997 行符合锁定 STIX 哈希及嵌入模型筛选；未筛除合格数据来调整结果。引用支持/拒绝、无效技术 ID 和嵌入模型缓存验收均通过。Ruff 退出码 0，Mypy 的 74 个源文件无错误。

原始证据：`step4-backend-full-06.log` / `.xml` / `.json`、`step4-backend-full-06-performance-1.json`（全部 201 个延迟值）、`step4-service-acceptance.md` / `.json`（源码、日志、JUnit、模板哈希及逐组计数）。总验收记录 [task12-readiness.md](task12-readiness.md) 列出受测提交。日志中个别 Windows 子进程错误文本采用 GBK，原始字节及 SHA 完整保留，摘要使用替换解码；通过计数读取 JUnit，不依赖错误文本解码。

验收使用专用空测试库；完整 RAG 的三个测试单独读取已备份恢复的知识库副本。`EVIDENCESOC_RAG_ACCEPTANCE_DATABASE_URL` 只在 RAG 模块 fixture 中临时替换数据库，并在进入、退出时清理配置与嵌入模型缓存，避免污染空知识库工作流测试。

```powershell
# 先配置隔离环境 DATABASE_URL、OPENSEARCH_URL、RAG_DATA_DIRECTORY；不输出凭据。
$env:EVIDENCESOC_TEST_POSTGRES = '1'
$env:EVIDENCESOC_TEST_OPENSEARCH = '1'
$env:RUN_RAG_ACCEPTANCE = '1'
# EVIDENCESOC_RAG_ACCEPTANCE_DATABASE_URL 指向完整知识库的独立副本。
python -X utf8 -m pytest services/backend/tests -q -rs -s
python -X utf8 -m ruff check services/backend
python -X utf8 -m mypy services/backend/src
```

新增服务用例通过真实 PostgreSQL、OpenSearch 和 stdio MCP 验证三工具及边界、原文/哈希、失败与空结果计费、重复指纹复用、并发预占、每轮 3 次/累计 6 次预算和单独验证计数。物理重试用 TCP 转发代理中断连接，恢复时将查询转发到真实 OpenSearch；不以返回假搜索结果代替服务。规则降级测试在缺少外部模型凭据时走有界规则路径，不请求云模型。

测试审查修正了第二轮 MCP session 错绑上一轮 run 的问题，逐 run 物理审计断言为 2 / 3 / 1；第三个 run 为验证阶段。按测试唯一 source 删除接入数据，覆盖接入中途失败的清理。修复后的专项为 1 passed / 8.23 秒，证据 `step4-budget-binding-04.*`。

失败留证：首轮新增服务测试中存在 Windows GBK 子进程错误输出按 UTF-8 解码的问题，测试捕获改为允许替换无法解码字符后专项通过。完整回归 `step4-backend-full-05` 为 693 passed、1 failed、0 skipped，唯一失败为隔离 OpenSearch 缺少仓库索引模板；安装模板后依赖专项 `step4-dependencies-05a` 为 3 passed。失败日志均保留，未弱化断言。
