# SQL 注入双模式演示

样例包含一条正常请求和四条 SQL 注入探测的合成 Nginx 日志。导入脚本按运行编号生成独立主机名和事件编号，并将事件时间放到导入时刻附近。规则调查与 DeepSeek 调查共用这五条输入日志，各有自己的告警、审批和验证记录。

## 从仓库根目录启动

以下命令在仓库根目录的三个 CMD 窗口执行。首次运行先安装锁定依赖，并从模板复制本地环境配置。

```cmd
pnpm install --frozen-lockfile
uv sync --project services/backend --locked
copy .env.example .env
```

如已有 `.env`，沿用本机配置，核对 PostgreSQL 与 OpenSearch 的地址和端口。规则模式可留空 `DEEPSEEK_API_KEY`。在第一个窗口启动依赖、迁移数据库并启动规则模式后端。

```cmd
set "SSLKEYLOGFILE="
docker compose up -d --wait postgres opensearch
uv run --project services/backend alembic -c services/backend/alembic.ini upgrade head
uv run --project services/backend python -m evidencesoc.rag.cli prepare
set "LLM_MODE=fixture"
set "DEMO_SESSION_ENABLED=true"
set "DEMO_SQLI_ENABLED=true"
set "FRONTEND_ORIGIN=http://127.0.0.1:3000"
uv run --project services/backend uvicorn evidencesoc.main:app --app-dir services/backend/src --host 127.0.0.1 --port 8000
```

在第二个 CMD 窗口启动前端。前后端的 `FRONTEND_ORIGIN` 都应和浏览器访问地址一致。

```cmd
set "BACKEND_URL=http://127.0.0.1:8000"
set "FRONTEND_ORIGIN=http://127.0.0.1:3000"
pnpm --dir apps/web dev
```

在第三个 CMD 窗口确认后端 ready 后导入。默认创建规则、DeepSeek 两条告警，`--include-reject` 另建一条拒绝分支用的规则告警。

```cmd
set "SSLKEYLOGFILE="
curl.exe -f http://127.0.0.1:8000/health/ready
uv run --project services/backend python scripts/seed-sqli-demo.py --include-reject
```

脚本输出 `run_id` 和各条告警的 `url`。重跑时加 `--run-id` 和原编号可复用同批日志、时间和告警。需要新一轮时直接运行上面的导入命令。若设置了自定义 `DEMO_SQLI_DIRECTORY`，后端和导入窗口使用同一路径。

## 页面演示顺序

1. 打开导入结果的 `alerts.fixture.url`，启用本地演示账户并启动调查。
2. 查看攻击链，点击证据编号打开原始日志和 SHA-256 校验。
3. 检查响应目标、影响、回滚和验证条件。输入审核理由并批准模拟方案。
4. 在效果验证中打开两条 `simulated-control-observation` 证据。确认 `network_blocked` 从 `false` 变为 `true`，且两条记录通过完整性校验。
5. 如需展示拒绝，打开 `alerts.reject.url`，在独立案件中拒绝方案并查看终止状态。
6. 等规则案件进入终态，在第一个 CMD 窗口按 Ctrl+C 停止后端，设置 `LLM_MODE=deepseek` 并执行下面的启动命令。重新启用本地演示账户，再打开同批导入的 `alerts.deepseek.url`。恢复未完成的调查时，使用该案件对应的运行模式。

```cmd
set "LLM_MODE=deepseek"
uv run --project services/backend uvicorn evidencesoc.main:app --app-dir services/backend/src --host 127.0.0.1 --port 8000
```

先确认 DeepSeek 调查的错误和回退提示，再审批。ATT&CK 编号来自本轮检索到的知识条目。封禁只改变本地演示模拟器的控制状态。

## 模型用量与诊断

演示模式下，模型调用账本默认位于 `.tmp\sqli-demo\model-budget.sqlite3`。它为每次请求预留费用，按响应中的 token 用量保守结算，总上限 3 元。用量未知时保留预留并暂停进一步请求。

```cmd
uv run --project services/backend python -m evidencesoc.agents.demo_budget ".tmp\sqli-demo\model-budget.sqlite3"
```

终端的 `structured_model_attempt_failed` 记录提供失败角色、次数、字段位置和固定错误码。模型分析使用当前证据和已检索的技术编号，处置方案使用后端提供的当前 UTC 时间窗口。

## 2026 年 11 月 11 日独立演示验收记录

使用本地 PostgreSQL、OpenSearch 和 FastAPI，在独立数据库和索引中测试。以下三个案件共用运行 `25d8c128e916428084b5ec56fdb4407a` 的五条已核验输入。

| 案件 | 调查与审批结果 | 效果验证 |
| --- | --- | --- |
| `IN-01M747QSY0ZWAV80G6D90F8408` | 规则调查，批准 | 成功，两条控制观测哈希通过 |
| `IN-01M747R61EAPZYDT2VEZD5F6E4` | 规则调查，拒绝 | 拒绝后停止 |
| `IN-01M747SBPPSZABFMVQ49SDKTRX` | DeepSeek 调查，批准，未触发回退 | 成功，两条控制观测哈希通过 |

DeepSeek 验收案件实际调用 5 次，取证规划 2 次，分析、重构和响应各 1 次。该案件未检索到知识条目，页面的 ATT&CK 技术保持未提供。

包含定位问题的试跑，独立账本共记录并结算 17 次请求，按保守单价核算 **0.212450 元**，未知用量和在途请求均为 0。试跑中定位并解决了演示分类与评测诊断字段混用、模型生成的跨案件步骤编号重复两项问题。[DeepSeek 官方单价](https://api-docs.deepseek.com/zh-cn/quick_start/pricing/)

重复导入复用全部五条事件。模式不符时返回 409，且告警可在对应模式下重新启动。模拟观测重放复用原证据，错误方案版本和被修改的观测无法通过核验。

后端回归 208 项通过，2 项已有 API 测试失败。两项失败均已用改动前的 `11aff6cf` 源码复现，测试桩只返回原始请求日志，断言却要求效果验证成功。
