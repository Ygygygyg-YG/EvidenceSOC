# EvidenceSOC 前端

EvidenceSOC 的本地运营与调查工作台，提供总览、告警、调查证据、人工审批和模拟处置验证。浏览器通过 Next.js 同源 `/api/v1/*` 代理访问 FastAPI。

以下 PowerShell 命令均从当前仓库根目录执行，无需固定盘符或本机路径。项目使用锁定的 pnpm 版本；新环境按锁文件运行 `pnpm install --frozen-lockfile`。日常启动前须已准备 PostgreSQL、OpenSearch、数据库迁移及调查所需知识库，后端 `/health/ready` 应返回成功。已有环境无需重新运行历史页面生成器或依赖追加命令。

## 本地开发

在后端终端启动规则演示，并显式启用本地演示会话：

```powershell
$env:LLM_MODE = 'fixture'
$env:DEMO_SESSION_ENABLED = 'true'
$env:FRONTEND_ORIGIN = 'http://127.0.0.1:3000'
uv run --project services/backend uvicorn evidencesoc.main:app --app-dir services/backend/src --host 127.0.0.1 --port 8000
```

[后端配置](../../services/backend/src/evidencesoc/config.py)的源码默认值为 `LLM_MODE=fixture`、`DEMO_SESSION_ENABLED=false`。`fixture` 是离线规则演示；上面的 `true` 是本机演示显式设置。需要启动调查、读取授权原文或审批时，在界面启用演示账户；这不代表接入真实模型或执行真实处置。

在另一个前端终端运行：

```powershell
$env:BACKEND_URL = 'http://127.0.0.1:8000'
$env:FRONTEND_ORIGIN = 'http://127.0.0.1:3000'
pnpm --dir apps/web dev
```

打开 [http://127.0.0.1:3000](http://127.0.0.1:3000)。`BACKEND_URL` 是前端服务进程读取的代理上游地址，不是浏览器公开配置。前端和后端进程的 `FRONTEND_ORIGIN` 必须与实际浏览器来源精确一致，包括协议、主机和端口，且不带末尾斜杠。`localhost` 与 `127.0.0.1` 是不同来源；改端口时同时更新两个进程并重启，避免会话和写请求被拒绝。数据库及密钥配置沿用本地安全配置，不写入本说明或验收报告。

## 构建与生产进程

在已设置上述前端环境变量的终端停止开发服务，然后构建：

```powershell
pnpm --dir apps/web build
```

仅在构建退出码为 0 后启动生产进程；此时后端仍需运行，两个进程的来源配置保持一致：

```powershell
pnpm --dir apps/web start
```

当前 `dev` 和 `start` 脚本均绑定 `127.0.0.1`，默认端口为 3000。构建成功与生产进程启动成功应分别核查；完整生产验收使用下方统一入口。本轮 `maintenance_prod_b` 已通过生产构建及 62 项浏览器验收，无失败、跳过、flaky 或重试，源码/知识输入未变且各项自有资源清理成功。

## 质量检查与浏览器回归

已有静态检查和单元测试入口：

```powershell
pnpm --dir apps/web lint
pnpm --dir apps/web typecheck
pnpm --dir apps/web test
```

完整浏览器回归包含模拟接口及真实后端用例。统一使用已实现的 [验收脚本](../../scripts/task10_browser_acceptance.py)，在独立 checkout/worktree 中执行，避免与日常开发共享 `.next`。先通过安全的进程环境提供以下三个变量；不要把凭据写进命令行、文档或报告：

| 必需变量 | 准备要求 |
| --- | --- |
| `TASK10_POSTGRES_ADMIN_URL` | 本地 PostgreSQL 管理连接，具备创建/删除本轮测试库及准备 `vector` 扩展的权限；脚本派生独立验收库 |
| `OPENSEARCH_URL` | 本地 OpenSearch 地址，允许创建/删除本轮独立索引 |
| `RAG_DATA_DIRECTORY` | 已准备的离线知识目录，包含固定 ATT&CK 源文件、manifest 及完整已校验模型 |

两个服务 URL 仅允许回环地址，拒绝 query/fragment，避免连接目标被覆盖。脚本按文件存在性拒绝 checkout 内的隐式 `.env*` 输入（`.env.example` 除外），不读取它们；运行前校验固定知识输入，不依赖现场下载。下面先检查变量是否已安全注入，再选择生产或开发模式；报告目录可替换为受控归档目录，且不应纳入源码提交：

```powershell
foreach ($name in @('TASK10_POSTGRES_ADMIN_URL', 'OPENSEARCH_URL', 'RAG_DATA_DIRECTORY')) {
  if ([string]::IsNullOrWhiteSpace([Environment]::GetEnvironmentVariable($name))) { throw "缺少验收变量：$name" }
}
uv run --project services/backend python scripts/task10_browser_acceptance.py --web-mode production --api-port 8018 --web-port 3018 --artifacts-root .backups/task12-browser-acceptance
```

如需单独验证开发模式，使用另一组空闲端口和独立运行目录：

```powershell
uv run --project services/backend python scripts/task10_browser_acceptance.py --web-mode dev --api-port 8019 --web-port 3019 --artifacts-root .backups/task12-browser-acceptance
```

脚本生成独立运行 ID、数据库、索引和报告目录，完成扩展/迁移、知识导入、样例及进程准备，自动设置真实用例变量、代理地址及两个进程完全一致的 `FRONTEND_ORIGIN`。生产模式先构建，构建失败不启动旧产物；开发模式用 `pnpm dev`。Playwright 配置使用 `PLAYWRIGHT_WEB_MODE=dev|production`，默认 `dev`，未知值失败；统一脚本默认 `production`。两种模式均禁止复用已有 Web 服务，并使用单 worker、零重试；端口占用即失败。真实用例缺少准备信息时失败而非 skip。

真实续办用例已实现，观察原生 EventSource 的 `status`、新方案 `approval.required`、游标恢复及无 `UNKNOWN_EVENT` reset。失败时保留报告；各项自有资源独立清理，清理失败也会否决验收，且不终止或删除其他运行的资源。结束时复核源码和知识输入 hash。退出码、浏览器报告、实际数量和清理结果共同决定验收，不能以单独 build 或最终 REST 快照代替。

维护代码提交为 `5646db4`。本轮后端 747 项、搜索相关 215 项、SSE 21 项、验收入口 18 项、前端 110 项通过，静态检查通过；后端全量无跳过。首轮生产发现并修复了审批后轮询提前停止：验证结果可能先落库，页面现在持续轮询至案件终态，避免遗漏随后落库的模拟执行快照。最终生产 62 项分为 6 项真实服务契约/流程、7 项真实服务外壳 smoke 和 49 项模拟 API 边界；首轮 60 通过、2 失败的记录仍保留。历史 Task10 的 105 项单元测试及 61 项浏览器通过数量不改写。所有真实调查仍使用 `fixture` 规则模式，Task13 正式模型运行数为 0。详见 [Task10 操作指南](../../docs/superpowers/plans/2026-09-27-task10-operation-guide.md)及已验收的 [维护记录](../../docs/acceptance/task12-maintenance-2026-10-18.json)。本轮已快进整合到本地 `main`，提交及主目录文件核对见[整合记录](../../docs/acceptance/task12-maintenance-integration-2026-10-18.json)。
