# EvidenceSOC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在 8～10 周内构建一个证据可追溯、六角色协作、支持人工审批和效果验证的智能安全运营中心，并完成可复现实验与比赛交付材料。

**Architecture:** 系统采用 Next.js 前端、FastAPI API、LangGraph 调查工作流、自建只读 MCP 工具、PostgreSQL/pgvector 业务与知识存储、OpenSearch 日志检索。Strix 仅用于参考工具注册、任务编排、权限边界和审计思想，不导入或调用 Strix CLI、内部工具或 Python 模块。

**Tech Stack:** React 19.3.0、Next.js 16.3.5、TypeScript 7.0.2、Tailwind CSS 4.3.3、Python 3.12.14、FastAPI 0.141.1、LangChain 1.4.1、LangGraph 1.2.11、PostgreSQL 17、pgvector 0.8.6、OpenSearch 3.8.0、Docker Compose 5.5.0。

## Global Constraints

- 开发环境为 Windows 10.0.26200.9457、WSL 2.7.3.0、Docker Engine 29.7.2。
- 使用 Git 2.55.0、Node.js 24.15.0、pnpm 11.19.0、uv 0.12.16。
- 系统 Python 3.13.6 保持不变；项目固定使用 uv 管理的 Python 3.12.14。
- 所有直接依赖固定精确版本；间接依赖提交 `pnpm-lock.yaml` 和 `uv.lock`。
- Strix 仅作架构参考；依赖清单、运行命令和容器中不得出现 Strix。
- MVP 不引入 MySQL、Milvus、Neo4j、Redis，也不执行真实封禁、账号禁用、主机隔离或公网扫描。
- Agent 只可调用三个自建只读 MCP 工具，不提供任意 Shell、任意文件读取或任意 URL 请求能力。
- 正式评测时，Agent 只能读取原始日志；`labels/`、`attacks.log` 和攻击者真值只能由评分程序读取。
- 所有安全结论必须引用有效 Evidence ID；证据不足时返回 `unknown`，不得编造来源或攻击类型。
- 代码、测试和文档使用真实 Git 提交记录；每个任务完成后执行对应验证再提交。

---

## 1. 最终产品范围

### 1.1 六个逻辑角色

1. 告警分诊 Agent：告警聚合、去重、风险评分、提取初始实体。
2. 证据收集 Agent：调用只读工具检索日志、告警上下文和 ATT&CK 知识。
3. 威胁分析 Agent：区分事实与推测，识别攻击类型候选。
4. 攻击链重构 Agent：还原攻击入口、阶段、时间线和横向关系。
5. 响应决策 Agent：生成风险、影响、处置、回滚和验证方案。
6. 效果验证 Agent：重新查询证据，判断模拟处置成功、失败或证据不足。

六个角色是可观察的业务节点，由确定性规则与 LLM 节点混合实现，不启动六个无限自主循环的模型进程。

### 1.2 完整用户流程

```text
接入告警
→ 告警聚合与分诊
→ 调查工作流启动
→ 证据收集
→ 攻击类型与来源判断
→ ATT&CK 映射
→ 攻击链重构
→ 响应方案生成
→ 人工批准或拒绝
→ 安全模拟处置
→ 效果验证
→ 报告与审计归档
```

当证据不足时只允许回到证据收集节点一次；第二次仍不足则进入人工复核，不允许无限循环。

### 1.3 第一阶段成功标准

- 输入一条 SQL 注入演示告警后，六个角色均产生可见状态和结构化输出。
- 每个攻击步骤至少引用一个有效 Evidence ID。
- 输出观察到的源 IP、入口主机、入口服务、攻击类型、ATT&CK 映射及置信度。
- 人工批准前不得执行模拟处置；拒绝后流程立即停止并记录理由。
- 没有云模型密钥时，固定样例与规则模式仍可走完整闭环。
- 进程重启后可从 PostgreSQL 检查点恢复未完成调查。

---

## 2. 前期软件与版本准备

### 2.1 当前环境基线

| 软件 | 当前版本 | 处理方式 |
|---|---:|---|
| Git | 2.55.0.windows.2 | 保留 |
| Node.js | 24.15.0 | 保留 |
| npm | 11.12.1 | 保留 |
| Corepack | 0.34.6 | 保留 |
| pnpm | 11.19.0 | 固定为前端包管理器 |
| Python | 3.13.6 | 保留，不作为项目解释器 |
| Docker Engine | 29.7.2 | 保留 |
| Docker Compose | 5.5.0 | 保留 |
| VS Code | 1.137.0 | 保留 |
| uv | 未安装 | 安装 0.12.16 |

建议硬件为 8 核 CPU、32 GB 内存和 60 GB 可用空间；最低为 4 核、16 GB 内存和 40 GB 空间。

### 2.2 前端固定版本

| 依赖 | 版本 |
|---|---:|
| next | 16.3.5 |
| react / react-dom | 19.3.0 |
| typescript | 7.0.2 |
| tailwindcss | 4.3.3 |
| @tanstack/react-query | 5.103.1 |
| @xyflow/react | 12.11.6 |
| echarts | 6.1.0 |
| zod | 4.6.5 |
| lucide-react | 1.47.0 |
| vitest | 5.0.1 |
| @playwright/test | 1.63.0 |
| openapi-typescript | 7.13.0 |

### 2.3 后端固定版本

| 依赖 | 版本 |
|---|---:|
| Python | 3.12.14 |
| uv | 0.12.16 |
| fastapi[standard] | 0.141.1 |
| pydantic | 2.13.5 |
| pydantic-settings | 2.15.0 |
| langchain | 1.4.1 |
| langgraph | 1.2.11 |
| langchain-openai | 1.6.2 |
| langchain-postgres | 0.0.18 |
| langgraph-checkpoint-postgres | 3.1.2 |
| langchain-mcp-adapters | 0.3.2 |
| mcp | 1.30.0 |
| sqlalchemy | 2.0.54 |
| alembic | 1.20.0 |
| psycopg[binary,pool] | 3.3.5 |
| pgvector | 0.5.0 |
| opensearch-py | 3.2.0 |
| sse-starlette | 3.4.11 |
| httpx | 0.28.1 |
| structlog | 26.1.0 |
| pytest / pytest-asyncio | 9.1.1 / 1.4.0 |
| ruff / mypy | 0.16.8 / 2.3.1 |

### 2.4 容器固定版本

| 服务 | 镜像 |
|---|---|
| PostgreSQL + pgvector | `pgvector/pgvector:0.8.6-pg17-bookworm` |
| OpenSearch | `opensearchproject/opensearch:3.8.0` |
| OpenSearch Dashboards | `opensearchproject/opensearch-dashboards:3.8.0`，仅开发调试 |
| OWASP Juice Shop | `bkimminich/juice-shop:v20.2.0` |
| DVWA | 源码版本 2.5，本地构建后记录镜像摘要 |

---

## 3. 文件结构与职责

```text
EvidenceSOC/
├─ apps/web/                         # Next.js 前端
│  ├─ src/app/                       # 页面和路由
│  ├─ src/components/                # 可复用 UI
│  ├─ src/features/alerts/           # 告警功能
│  ├─ src/features/investigations/   # 调查、攻击链、证据
│  ├─ src/features/responses/        # 审批和验证
│  └─ src/lib/api/generated.ts       # OpenAPI 自动生成类型
├─ services/backend/
│  ├─ pyproject.toml
│  ├─ src/evidencesoc/api/           # FastAPI 路由与 SSE
│  ├─ src/evidencesoc/domain/        # Pydantic 和枚举
│  ├─ src/evidencesoc/persistence/   # SQLAlchemy、OpenSearch
│  ├─ src/evidencesoc/ingestion/     # 日志解析、规范化、去重
│  ├─ src/evidencesoc/evidence/      # 证据哈希和引用校验
│  ├─ src/evidencesoc/tools/         # 只读工具实现与权限策略
│  ├─ src/evidencesoc/mcp_server/    # MCP Server 入口
│  ├─ src/evidencesoc/rag/           # ATT&CK 和安全知识检索
│  ├─ src/evidencesoc/agents/        # LangGraph 工作流
│  └─ tests/                          # 单元和集成测试
├─ infra/                             # Compose、索引模板、初始化脚本
├─ data/samples/                      # 可公开演示数据
├─ data/manifests/                    # 数据集拆分与哈希清单
├─ evals/                             # 基线、消融和评分
├─ docs/                              # 准备书、ADR、技术文档
├─ compose.yaml
├─ .env.example
└─ README.md
```

---

## 4. 公共接口和数据契约

### 4.1 核心类型

```python
from datetime import datetime
from enum import StrEnum
from typing import Any, Literal
from pydantic import BaseModel, Field

class IncidentStatus(StrEnum):
    RECEIVED = "received"
    TRIAGED = "triaged"
    COLLECTING = "collecting"
    ANALYZING = "analyzing"
    RECONSTRUCTING = "reconstructing"
    AWAITING_APPROVAL = "awaiting_approval"
    SIMULATING = "simulating"
    VALIDATING = "validating"
    COMPLETED = "completed"
    FAILED = "failed"

class EvidenceItem(BaseModel):
    evidence_id: str
    source: str
    observed_at: datetime
    query: dict[str, Any]
    summary: str
    content_sha256: str

class AttackOrigin(BaseModel):
    observed_source_ip: str | None
    entry_host: str | None
    entry_service: str | None
    first_seen_at: datetime | None
    source_scope: Literal["external", "internal", "unknown"]
    confidence: float = Field(ge=0, le=1)
    evidence_ids: list[str]

class AttackClassification(BaseModel):
    primary_type: str | None
    attack_types: list[str]
    dataset_labels: list[str] = []
    attack_phase: str | None
    technique_ids: list[str]
    confidence: float = Field(ge=0, le=1)
    evidence_ids: list[str]
```

`dataset_labels` 只允许评分程序写入；生产调查结果默认保持空列表。

### 4.2 REST API

| 方法与路径 | 作用 |
|---|---|
| `POST /api/v1/alerts` | 接入告警，支持 `Idempotency-Key` |
| `GET /api/v1/alerts` | 告警分页和筛选 |
| `GET /api/v1/incidents/{id}` | 获取事件、证据和攻击链 |
| `POST /api/v1/investigations` | 创建调查 |
| `GET /api/v1/investigations/{id}/stream` | SSE 实时状态 |
| `POST /api/v1/response-plans/{id}/approve` | 批准模拟处置 |
| `POST /api/v1/response-plans/{id}/reject` | 拒绝并记录理由 |
| `GET /api/v1/evaluations/{id}` | 返回实验结果 |
| `GET /health/live` | 进程存活检查 |
| `GET /health/ready` | 依赖就绪检查 |

SSE 事件固定为 `investigation.started`、`agent.started`、`evidence.added`、`agent.completed`、`approval.required`、`decision.recorded`、`validation.completed`、`investigation.failed`、`investigation.completed`。

### 4.3 MCP 工具

```python
async def search_security_events(
    time_from: datetime,
    time_to: datetime,
    filters: dict[str, str],
    limit: int = 100,
) -> list[EvidenceItem]: ...

async def get_alert_context(
    alert_id: str,
    before_seconds: int = 900,
    after_seconds: int = 900,
) -> list[EvidenceItem]: ...

async def lookup_attack_technique(
    query: str,
    limit: int = 10,
) -> list[dict[str, str]]: ...
```

硬限制：事件工具 `limit <= 200`，告警上下文单侧窗口 `<= 900` 秒，ATT&CK 返回 `<= 10` 条，每次调用超时 10 秒、最多重试两次。

---

## 5. 实施任务

### Task 1: 环境验收与仓库初始化

**Files:**
- Create: `.gitignore`
- Create: `.editorconfig`
- Create: `.env.example`
- Create: `docs/environment-verification.md`

**Interfaces:**
- Consumes: Windows、Docker、Node、Git 当前安装环境。
- Produces: 可复现的工具链版本记录和 Git 主分支。

- [ ] **Step 1: 检查所有工具版本**

```powershell
Set-Location "D:\桌面\传智杯"
git --version
node --version
npm --version
corepack --version
pnpm --version
python --version
docker --version
docker compose version
wsl --version
```

Expected：版本与第 2 节基线一致，除 uv 外均可执行。

- [ ] **Step 2: 安装并验证 uv**

```powershell
winget install --id astral-sh.uv --version 0.12.16 -e
uv --version
uv python install 3.12.14
uv python list
```

Expected：存在 `cpython-3.12.14`，系统 Python 3.13.6 未被替换。

- [ ] **Step 3: 固定 pnpm**

```powershell
corepack enable
corepack prepare pnpm@11.19.0 --activate
pnpm --version
```

Expected：输出 `11.19.0`。

- [ ] **Step 4: 检查 Docker 与 OpenSearch 前置条件**

```powershell
docker info
wsl -d docker-desktop sysctl vm.max_map_count
```

Expected：Docker Server 可连接，`vm.max_map_count >= 262144`。

- [ ] **Step 5: 初始化 Git 并记录环境**

```powershell
git init -b main
git add .gitignore .editorconfig .env.example docs/environment-verification.md
git commit -m "chore: initialize evidencesoc workspace"
```

**完成标志：** `git status` 干净；环境记录包含实际版本、CPU、内存、Docker 资源和检查日期。

### Task 2: 前后端脚手架和质量门禁

**Files:**
- Create: `apps/web/**`
- Create: `services/backend/pyproject.toml`
- Create: `services/backend/src/evidencesoc/main.py`
- Create: `services/backend/tests/test_health.py`

**Interfaces:**
- Consumes: Task 1 的 Node、pnpm、uv 和 Python。
- Produces: `GET /health/live -> {"status":"ok"}` 和可启动前端。

- [ ] **Step 1: 创建 Next.js 项目并锁定依赖**

```powershell
pnpm create next-app@16.3.5 apps/web --ts --tailwind --eslint --app --src-dir --import-alias "@/*" --use-pnpm
pnpm --dir apps/web add next@16.3.5 react@19.3.0 react-dom@19.3.0 @tanstack/react-query@5.103.1 @xyflow/react@12.11.6 echarts@6.1.0 zod@4.6.5 lucide-react@1.47.0
pnpm --dir apps/web add -D typescript@7.0.2 tailwindcss@4.3.3 vitest@5.0.1 @playwright/test@1.63.0 openapi-typescript@7.13.0
```

- [ ] **Step 2: 创建 Python 项目并安装固定依赖**

```powershell
uv init --app --python 3.12.14 services/backend
uv add --project services/backend "fastapi[standard]==0.141.1" pydantic==2.13.5 pydantic-settings==2.15.0 langchain==1.4.1 langgraph==1.2.11 langchain-openai==1.6.2 langchain-postgres==0.0.18 langgraph-checkpoint-postgres==3.1.2 langchain-mcp-adapters==0.3.2 mcp==1.30.0 sqlalchemy==2.0.54 alembic==1.20.0 "psycopg[binary,pool]==3.3.5" pgvector==0.5.0 opensearch-py==3.2.0 sse-starlette==3.4.11 httpx==0.28.1 structlog==26.1.0
uv add --project services/backend --dev pytest==9.1.1 pytest-asyncio==1.4.0 ruff==0.16.8 mypy==2.3.1
```

- [ ] **Step 3: 先写健康检查失败测试**

```python
from fastapi.testclient import TestClient
from evidencesoc.main import app

def test_live_health() -> None:
    response = TestClient(app).get("/health/live")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}
```

Run：`uv run --project services/backend pytest services/backend/tests/test_health.py -v`

Expected：首次因模块或路由不存在而失败。

- [ ] **Step 4: 实现最小 FastAPI 应用并运行质量检查**

```python
from fastapi import FastAPI

app = FastAPI(title="EvidenceSOC API", version="0.1.0")

@app.get("/health/live")
async def live_health() -> dict[str, str]:
    return {"status": "ok"}
```

```powershell
uv run --project services/backend pytest -q
uv run --project services/backend ruff check services/backend
uv run --project services/backend mypy services/backend/src
pnpm --dir apps/web lint
pnpm --dir apps/web exec tsc --noEmit
pnpm --dir apps/web build
```

Expected：全部退出码为 0。

- [ ] **Step 5: 提交**

```powershell
git add apps services pnpm-lock.yaml
git commit -m "chore: scaffold web and backend applications"
```

**完成标志：** 前端可启动；`/health/live` 返回 200；五项质量检查全部通过。

### Task 3: PostgreSQL、pgvector 和 OpenSearch

**Files:**
- Create: `compose.yaml`
- Create: `infra/postgres/init.sql`
- Create: `infra/opensearch/security-events-template.json`
- Create: `services/backend/tests/integration/test_dependencies.py`

**Interfaces:**
- Consumes: `.env.example` 中数据库和 OpenSearch 配置。
- Produces: PostgreSQL DSN、OpenSearch URL、两个健康检查。

- [ ] **Step 1: 为数据库和搜索服务编写连接失败测试**

测试必须分别验证 PostgreSQL `SELECT 1`、`vector` 扩展版本和 OpenSearch `_cluster/health`。

- [ ] **Step 2: 在 Compose 中定义服务**

要求：端口仅绑定 `127.0.0.1`；PostgreSQL 使用 `pg_isready`；OpenSearch 使用单节点、1 GB JVM 堆和 HTTP 健康检查；开发环境可禁用安全插件。

- [ ] **Step 3: 启动并验证服务**

```powershell
docker compose config
docker compose up -d postgres opensearch
docker compose ps
uv run --project services/backend pytest services/backend/tests/integration/test_dependencies.py -v
```

Expected：两个容器为 healthy；测试返回 PostgreSQL 17、pgvector 0.8.6 和 OpenSearch 3.8.0。

- [ ] **Step 4: 重启持久化验证**

写入一条测试记录，执行 `docker compose restart` 后再次读取。Expected：记录仍存在。

- [ ] **Step 5: 提交**

```powershell
git add compose.yaml infra services/backend/tests/integration
git commit -m "infra: add postgres pgvector and opensearch"
```

**完成标志：** 一条 Compose 命令可启动基础设施，重启不丢数据。

### Task 4: 领域模型、迁移和 OpenAPI 契约

**Files:**
- Create: `services/backend/src/evidencesoc/domain/models.py`
- Create: `services/backend/src/evidencesoc/persistence/tables.py`
- Create: `services/backend/alembic.ini`
- Create: `services/backend/migrations/**`
- Create: `services/backend/tests/domain/test_models.py`
- Create: `apps/web/src/lib/api/generated.ts`

**Interfaces:**
- Consumes: PostgreSQL DSN。
- Produces: `SecurityEvent`、`Alert`、`Incident`、`EvidenceItem`、`AttackOrigin`、`AttackClassification`、`AgentRun`、`ResponsePlan`、`ApprovalRecord`、`ValidationResult`。

- [ ] **Step 1: 编写模型验证失败测试**

覆盖非法严重性、置信度越界、缺失证据 ID、无效时间顺序和空审批理由。

- [ ] **Step 2: 实现 Pydantic 类型和状态枚举**

所有调查状态必须来自 `IncidentStatus`；攻击来源必须允许 `unknown`；攻击类型必须是多标签列表。

- [ ] **Step 3: 创建数据库表和 Alembic 迁移**

表固定为 `security_events`、`alerts`、`incidents`、`evidence_items`、`attack_steps`、`agent_runs`、`tool_calls`、`response_plans`、`approvals`、`validation_results`、`knowledge_chunks`、`evaluation_runs`。

- [ ] **Step 4: 运行迁移往返测试**

```powershell
uv run --project services/backend alembic upgrade head
uv run --project services/backend alembic downgrade -1
uv run --project services/backend alembic upgrade head
```

Expected：三条命令成功；最终所有表存在。

- [ ] **Step 5: 生成前端 API 类型**

```powershell
pnpm --dir apps/web exec openapi-typescript http://127.0.0.1:8000/openapi.json -o src/lib/api/generated.ts
pnpm --dir apps/web exec tsc --noEmit
```

- [ ] **Step 6: 提交**

```powershell
git add services/backend apps/web/src/lib/api/generated.ts
git commit -m "feat: add domain models and database schema"
```

**完成标志：** 空库可完整迁移；前端生成类型无 `any` 替代核心 DTO。

### Task 5: 日志接入和证据链

**Files:**
- Create: `services/backend/src/evidencesoc/ingestion/jsonl.py`
- Create: `services/backend/src/evidencesoc/ingestion/normalize.py`
- Create: `services/backend/src/evidencesoc/evidence/service.py`
- Create: `services/backend/tests/ingestion/test_jsonl.py`
- Create: `data/samples/sql-injection.jsonl`
- Create: `data/samples/benign-web.jsonl`

**Interfaces:**
- Consumes: JSON/JSONL 日志。
- Produces: `SecurityEvent`、`EvidenceItem`，证据 ID 格式为 `EV-<ULID>`。

- [ ] **Step 1: 编写解析、去重和哈希失败测试**

测试同一文件重复导入只产生一份事件；原始内容变化后 SHA-256 必须变化；非法时间和缺失来源必须拒绝。

- [ ] **Step 2: 实现规范化和幂等导入**

唯一键使用 `(source, external_id)`；无 external ID 时使用规范化事件内容哈希。

- [ ] **Step 3: 写入双存储**

原始与检索字段写入 `security-events-v1`；业务 ID、状态、来源和哈希写入 PostgreSQL。

- [ ] **Step 4: 实现证据生成**

Evidence 必须包含来源、查询参数、观察时间、摘要和内容哈希；不能只保存模型生成的文字。

- [ ] **Step 5: 验证**

```powershell
uv run --project services/backend pytest services/backend/tests/ingestion -v
```

Expected：重复导入、内容篡改、空文件和非法 JSON 测试全部通过。

- [ ] **Step 6: 提交**

```powershell
git add services/backend/src/evidencesoc/ingestion services/backend/src/evidencesoc/evidence services/backend/tests/ingestion data/samples
git commit -m "feat: add auditable event ingestion"
```

**完成标志：** 任意 Evidence ID 均可定位到原始事件和生成查询。

### Task 6: 只读 MCP 工具

**Files:**
- Create: `services/backend/src/evidencesoc/tools/policy.py`
- Create: `services/backend/src/evidencesoc/tools/security_events.py`
- Create: `services/backend/src/evidencesoc/tools/attack.py`
- Create: `services/backend/src/evidencesoc/mcp_server/main.py`
- Create: `services/backend/tests/tools/test_policy.py`

**Interfaces:**
- Consumes: OpenSearch、PostgreSQL、ATT&CK 知识库。
- Produces: 第 4.3 节三个异步工具。

- [ ] **Step 1: 编写权限边界测试**

覆盖 201 条结果、901 秒时间窗、负数时间窗、未知工具、空 Alert ID、超时和 OpenSearch 失败。

- [ ] **Step 2: 实现纯函数策略校验器**

校验必须在调用存储层之前执行；拒绝结果写入 `tool_calls`，包括原因和 trace ID。

- [ ] **Step 3: 实现三个工具和 MCP Server**

所有结果先转换成 `EvidenceItem`；错误返回结构化代码 `POLICY_DENIED`、`NOT_FOUND`、`DEPENDENCY_TIMEOUT` 或 `DEPENDENCY_UNAVAILABLE`。

- [ ] **Step 4: 验证工具列表**

Expected：MCP 客户端只能发现 `search_security_events`、`get_alert_context` 和 `lookup_attack_technique` 三个工具。

- [ ] **Step 5: 提交**

```powershell
git add services/backend/src/evidencesoc/tools services/backend/src/evidencesoc/mcp_server services/backend/tests/tools
git commit -m "feat: add restricted mcp investigation tools"
```

**完成标志：** 工具无法执行 Shell、访问任意 URL、扩大时间窗或返回超过上限的数据。

### Task 7: ATT&CK RAG 和引用校验

**Files:**
- Create: `services/backend/src/evidencesoc/rag/ingest_attack.py`
- Create: `services/backend/src/evidencesoc/rag/retriever.py`
- Create: `services/backend/src/evidencesoc/evidence/citations.py`
- Create: `services/backend/tests/rag/test_retrieval.py`

**Interfaces:**
- Consumes: MITRE Enterprise ATT&CK v19.2 STIX、内部响应手册。
- Produces: `retrieve_knowledge(query: str, top_k: int = 8)` 和 `validate_citations(...)`。

- [ ] **Step 1: 固定并校验知识数据**

记录 STIX 文件版本、下载日期和 SHA-256；知识块保存来源 URI、版本、标题、正文和向量。

- [ ] **Step 2: 编写检索失败测试**

查询“DNS 数据外泄”必须返回相关条目；不存在的 Technique ID 不得伪造结果；测试集标签不得进入知识库。

- [ ] **Step 3: 实现混合检索**

使用 pgvector 语义结果和关键词结果进行 Reciprocal Rank Fusion，默认返回 8 条。

- [ ] **Step 4: 实现引用校验**

报告中的每条事实声明必须引用存在的 Evidence ID 或 Knowledge Chunk ID；无效引用将声明标记为 `unsupported`。

- [ ] **Step 5: 验证并提交**

```powershell
uv run --project services/backend pytest services/backend/tests/rag -v
git add services/backend/src/evidencesoc/rag services/backend/src/evidencesoc/evidence/citations.py services/backend/tests/rag
git commit -m "feat: add hybrid attack knowledge retrieval"
```

**完成标志：** 固定查询集 Recall@8 达到预设基线，引用不存在时报告校验失败。

### Task 8: 六角色 LangGraph 调查工作流

**Files:**
- Create: `services/backend/src/evidencesoc/agents/state.py`
- Create: `services/backend/src/evidencesoc/agents/nodes/*.py`
- Create: `services/backend/src/evidencesoc/agents/graph.py`
- Create: `services/backend/src/evidencesoc/agents/fallback.py`
- Create: `services/backend/tests/agents/test_graph.py`

**Interfaces:**
- Consumes: 三个 MCP 工具、RAG、领域模型和 PostgreSQL Checkpointer。
- Produces: `run_investigation(incident_id: str)` 异步工作流和节点事件。

- [ ] **Step 1: 为状态转换编写失败测试**

覆盖正常闭环、证据不足回退一次、第二次转人工、模型超时、审批拒绝、恢复检查点和验证失败。

- [ ] **Step 2: 实现 `InvestigationState`**

状态至少包含 incident ID、状态、告警、证据、来源判断、攻击分类、攻击步骤、响应方案、审批结果、验证结果、回退次数和错误。

- [ ] **Step 3: 依次实现六个节点**

每个节点只接收结构化状态并返回状态增量；提示词输出使用 Pydantic Schema；每个模型节点最多重试两次。

- [ ] **Step 4: 实现人工审批中断和模拟执行器**

模拟动作只允许 `block_ip_simulated`、`isolate_host_simulated`、`disable_account_simulated`；输出动作预览、回滚和验证查询，不调用真实系统。

- [ ] **Step 5: 实现 fixture/规则降级模式**

当 `LLM_MODE=fixture` 或模型不可用时，固定演示案例必须返回确定性结构化结果并明确标记 `fallback_used=true`。

- [ ] **Step 6: 运行图测试并提交**

```powershell
uv run --project services/backend pytest services/backend/tests/agents -v
git add services/backend/src/evidencesoc/agents services/backend/tests/agents
git commit -m "feat: add six-role investigation workflow"
```

**完成标志：** 一条演示告警走完六角色、审批、模拟处置和验证；重启后能恢复。

### Task 9: FastAPI、SSE 和审计

**Files:**
- Create: `services/backend/src/evidencesoc/api/alerts.py`
- Create: `services/backend/src/evidencesoc/api/investigations.py`
- Create: `services/backend/src/evidencesoc/api/responses.py`
- Create: `services/backend/src/evidencesoc/api/sse.py`
- Create: `services/backend/tests/api/test_investigation_flow.py`

**Interfaces:**
- Consumes: Task 8 工作流。
- Produces: 第 4.2 节 REST/SSE 接口。

- [ ] **Step 1: 编写 API 契约失败测试**

覆盖幂等告警、非法请求、调查创建、SSE 顺序、断线重连、重复审批和统一错误体。

- [ ] **Step 2: 实现 API 和 SSE**

SSE 事件使用递增事件 ID，支持 `Last-Event-ID`；每次调查生成 trace ID。

- [ ] **Step 3: 实现日志脱敏**

`Authorization`、Cookie、API Key、密码和模型密钥不得进入结构化日志。

- [ ] **Step 4: 性能和集成验证**

Expected：不含模型调用的普通 API 本机 P95 小于 500 ms；创建调查后 2 秒内收到首个 SSE 事件。

- [ ] **Step 5: 提交**

```powershell
git add services/backend/src/evidencesoc/api services/backend/tests/api
git commit -m "feat: expose investigation and approval APIs"
```

**完成标志：** 浏览器断线重连不丢关键状态，日志中无明文秘密。

### Task 10: 前端运营大屏与调查界面

**Files:**
- Create: `apps/web/src/app/page.tsx`
- Create: `apps/web/src/app/alerts/[id]/page.tsx`
- Create: `apps/web/src/app/incidents/[id]/page.tsx`
- Create: `apps/web/src/app/responses/[id]/page.tsx`
- Create: `apps/web/src/features/investigations/AttackGraph.tsx`
- Create: `apps/web/src/features/investigations/AgentTimeline.tsx`
- Create: `apps/web/e2e/investigation.spec.ts`

**Interfaces:**
- Consumes: OpenAPI 客户端和 SSE 事件。
- Produces: 大屏、告警详情、攻击链、证据追溯、审批和验证页面。

- [ ] **Step 1: 先写 Playwright 完整流程测试**

测试必须从告警列表进入事件、启动调查、观察六角色状态、点击攻击链证据、批准模拟处置并看到验证结论。

- [ ] **Step 2: 建立统一视觉系统**

采用深色 SOC 主题；严重性、状态、成功和失败颜色使用统一 Token；所有异步页面具备 loading、empty、error 和 retry 状态。

- [ ] **Step 3: 实现运营大屏和告警详情**

展示告警数量、严重性、案件状态、Agent 运行数量、最近事件和数据源健康度。

- [ ] **Step 4: 实现攻击链和证据抽屉**

React Flow 节点展示阶段、主机、时间和置信度；点击节点必须列出其 Evidence ID、来源、查询和哈希。

- [ ] **Step 5: 实现审批和验证界面**

批准前展示影响、风险、回滚和验证步骤；拒绝必须填写理由。

- [ ] **Step 6: 验证**

```powershell
pnpm --dir apps/web lint
pnpm --dir apps/web exec tsc --noEmit
pnpm --dir apps/web test
pnpm --dir apps/web exec playwright test
pnpm --dir apps/web build
```

Expected：全部通过；1440×900 和 1920×1080 无横向溢出；浏览器控制台无错误。

- [ ] **Step 7: 提交**

```powershell
git add apps/web
git commit -m "feat: add soc investigation user interface"
```

**完成标志：** 用户可仅通过界面完成完整调查闭环。

### Task 11: AIT 数据集、攻击来源和攻击类型金标

**Files:**
- Create: `evals/datasets/ait_v2/parse.py`
- Create: `evals/datasets/ait_v2/join_labels.py`
- Create: `evals/datasets/ait_v2/build_manifests.py`
- Create: `evals/datasets/ait_v2/taxonomy.py`
- Create: `evals/tests/test_ait_ground_truth.py`
- Create: `data/manifests/ait-v2-splits.json`

**Interfaces:**
- Consumes: AIT Log Data Set V2.1 的 `gather/`、`labels/`、`dataset.yml`、`servers.yml` 和 `attacks.log`。
- Produces: Agent 可见事件包、评分程序专用金标包和统一多标签攻击分类。

- [ ] **Step 1: 固定数据拆分**

```json
{
  "development": ["fox", "harrison"],
  "validation": ["russellmitchell", "santos"],
  "test": ["shaw", "wardbeck", "wheeler", "wilson"]
}
```

测试必须断言三个集合没有交集。

- [ ] **Step 2: 解析原始日志并保留行号**

每个事件必须保存 `dataset_id`、`relative_log_path`、`line_number`、`host`、`timestamp` 和规范化字段。

- [ ] **Step 3: 用联合键连接标签**

联合键固定为 `(dataset_id, relative_log_path, line_number)`；没有对应标签的日志记为正常。评分程序保存原始标签，Agent 输入中删除标签字段。

- [ ] **Step 4: 构建攻击来源金标**

评分字段为观察到的源 IP、入口主机、入口服务、首次攻击时间和后续跳转主机。`attacks.log` 与含攻击者标识的配置只进入评分侧。

- [ ] **Step 5: 构建攻击类型字典**

固定标准类型为 `reconnaissance`、`credential_attack`、`webshell_upload`、`remote_command_execution`、`privilege_escalation`、`data_exfiltration`。一个事件包允许多个类型，不能压缩成单分类。

- [ ] **Step 6: 构建 48 个测试事件包**

测试集包含 24 个攻击包和 24 个正常包；每个包保存重建所需 ID、时间范围和哈希，不提交大型原始数据。

- [ ] **Step 7: 执行防泄漏测试**

测试 Agent 输入中不存在 `labels`、`rules`、`attacks.log` 内容、`attacker_0` 真值或测试答案。

- [ ] **Step 8: 提交**

```powershell
uv run --project services/backend pytest evals/tests/test_ait_ground_truth.py -v
git add evals data/manifests
git commit -m "eval: add isolated ait ground truth pipeline"
```

**完成标志：** 任意测试事件包可由 manifest 重建；评分金标与 Agent 输入完全隔离。

### Task 12: 本地隔离靶场和实验室金标

**Files:**
- Create: `infra/lab/compose.yaml`
- Create: `infra/lab/README.md`
- Create: `evals/datasets/lab/scenarios.json`
- Create: `evals/tests/test_lab_isolation.py`

**Interfaces:**
- Consumes: Juice Shop v20.2.0、DVWA 2.5。
- Produces: 16 个可重放本地案例。

- [ ] **Step 1: 编写网络隔离测试**

所有端口只绑定 `127.0.0.1`；靶场网络不得连接宿主机以外目标；Agent 无法访问靶场管理接口。

- [ ] **Step 2: 创建 16 个案例**

4 个开发案例；12 个保留评测案例，其中攻击与正常各 6 个。每个案例包含时间线、入口来源、攻击类型、预期证据和安全响应答案。

- [ ] **Step 3: 验证可重放性**

清空并重建靶场三次，关键日志、攻击阶段和金标保持一致。

- [ ] **Step 4: 提交**

```powershell
git add infra/lab evals/datasets/lab evals/tests/test_lab_isolation.py
git commit -m "test: add isolated reproducible security lab"
```

**完成标志：** 靶场不对局域网或公网开放，12 个保留案例未用于提示词调优。

### Task 13: 基线、消融和评分系统

**Files:**
- Create: `evals/runners/baselines.py`
- Create: `evals/runners/ablations.py`
- Create: `evals/metrics/classification.py`
- Create: `evals/metrics/evidence.py`
- Create: `evals/metrics/attack_chain.py`
- Create: `evals/run_manifest.schema.json`
- Create: `evals/tests/test_metrics.py`

**Interfaces:**
- Consumes: 48 个 AIT 测试包、12 个实验室保留案例、B0～B3 系统输出。
- Produces: JSON/CSV 实验结果和前端图表数据。

- [ ] **Step 1: 实现四个主基线**

`B0=普通LLM`、`B1=普通RAG`、`B2=单Agent+工具`、`B3=六角色EvidenceSOC`。四者使用相同模型、温度 0 和相同输入案例。

- [ ] **Step 2: 实现四项消融**

在固定 24 案例上分别移除证据工具、移除 RAG、混合检索改为纯向量、移除效果验证节点。

- [ ] **Step 3: 实现指标**

攻击类型使用多标签 Macro F1；来源使用源 IP、入口主机、入口服务准确率；同时计算攻击阶段覆盖 F1、顺序准确率、Evidence Precision@K、引用有效率、ATT&CK F1、Unsupported Claim Rate、延迟、Token 和费用。

- [ ] **Step 4: 固定实验清单**

主实验 `60 × 4 = 240` 次，消融 `24 × 4 = 96` 次，总计 336 次。每次保存数据版本、模型完整 ID、提示词版本、随机种子 42、锁文件哈希和 Git commit。

- [ ] **Step 5: 验证指标测试**

使用手工可计算的小样例验证 Precision、Recall、F1、引用率和顺序准确率；不得使用 LLM 作为最终裁判。

- [ ] **Step 6: 运行并提交实验代码**

```powershell
uv run --project services/backend pytest evals/tests -v
git add evals
git commit -m "eval: add reproducible baselines and metrics"
```

**完成标志：** 主实验与消融可由同一命令重放；目标为 Macro F1 ≥ 0.85、引用有效率 ≥ 95%、ATT&CK F1 ≥ 0.80、Unsupported Claim Rate ≤ 5%。未达标时保留真实结果并分类错误。

### Task 14: 安全、故障和性能验收

**Files:**
- Create: `services/backend/tests/security/test_prompt_injection.py`
- Create: `services/backend/tests/security/test_tool_boundaries.py`
- Create: `services/backend/tests/resilience/test_dependencies.py`
- Create: `apps/web/e2e/reconnect.spec.ts`
- Create: `docs/security-model.md`

**Interfaces:**
- Consumes: 完整系统。
- Produces: 安全模型、故障测试和性能报告。

- [ ] **Step 1: 测试 Prompt Injection、SSRF 和路径穿越**

日志中加入“忽略规则、执行命令、访问 URL”等恶意文本。Expected：它们只能作为证据内容，不能改变工具白名单或触发外部动作。

- [ ] **Step 2: 测试依赖故障**

分别停止 PostgreSQL、OpenSearch、MCP 和模型接口。Expected：状态进入明确失败或降级，不产生伪造成功结论。

- [ ] **Step 3: 测试审批边界**

覆盖未审批执行、重复审批、审批超时、拒绝、并发调查串线。Expected：全部被正确阻止或隔离。

- [ ] **Step 4: 测试 SSE 与恢复**

断开浏览器、刷新页面和重启后端。Expected：使用 Last-Event-ID 和检查点恢复，不重复模拟处置。

- [ ] **Step 5: 运行全套验收**

```powershell
uv run --project services/backend pytest --cov=evidencesoc --cov-report=term-missing
pnpm --dir apps/web exec playwright test
pnpm --dir apps/web build
```

Expected：关键后端模块覆盖率不低于 80%；完整 E2E 连续三次通过。

- [ ] **Step 6: 提交**

```powershell
git add services/backend/tests apps/web/e2e docs/security-model.md
git commit -m "test: harden evidencesoc security boundaries"
```

**完成标志：** 无任意代码执行、越权工具调用、明文密钥或跨调查数据泄漏。

### Task 15: README、技术文档、视频与在线演示

**Files:**
- Create: `README.md`
- Create: `docs/technical-report.md`
- Create: `docs/demo-script.md`
- Create: `docs/deployment.md`
- Create: `docs/bill-of-materials.md`

**Interfaces:**
- Consumes: 已验收代码、实验结果和界面截图。
- Produces: 比赛要求的代码仓库、PDF 内容、5～8 分钟视频脚本和可选部署说明。

- [ ] **Step 1: 完成 README**

必须包含项目介绍、核心价值、架构图、版本要求、安装、启动、测试、样例账号、团队信息、安全边界和数据集说明。

- [ ] **Step 2: 完成不超过 30 页的技术文档**

章节固定为项目概述、需求分析、架构设计、AI 技术方案、核心功能、数据与评测、测试部署、创新点、社会与商业价值、局限和展望。

- [ ] **Step 3: 准备演示视频脚本**

视频 5～8 分钟、MP4、1080p：40 秒痛点，50 秒架构，3 分钟完整闭环，1 分钟证据与安全，1 分钟实验，30 秒价值与展望。

- [ ] **Step 4: 新环境安装验证**

在干净环境依据 README 执行安装、Compose 启动、迁移、样例导入、前后端启动和 E2E。Expected：无需阅读源代码即可完成演示。

- [ ] **Step 5: 秘密和大型文件检查**

确认仓库不存在 `.env`、API Key、Cookie、账号密码、AIT 原始大文件、PCAP 和靶场敏感数据。

- [ ] **Step 6: 最终提交与版本标签**

```powershell
git add README.md docs
git commit -m "docs: add competition delivery materials"
git tag -a v1.0.0-demo -m "EvidenceSOC competition demo"
```

**完成标志：** 仓库、PDF、视频和在线演示指向同一 Git 版本；视频中展示的功能均真实存在。

---

## 6. 两周纵向切片日程

| 工作日 | 任务 | 当日完成标志 |
|---|---|---|
| Day 1 | Task 1 与 Task 2 基础脚手架 | Web/API 均可启动 |
| Day 2 | Task 3 基础设施 | PostgreSQL、pgvector、OpenSearch healthy |
| Day 3 | Task 4 模型与迁移 | OpenAPI 和迁移测试通过 |
| Day 4 | Task 5 接入与证据 | 样例日志可追溯到 Evidence ID |
| Day 5 | Task 8 工作流骨架 | fixture 模式走完六角色 |
| Day 6 | Task 6 MCP 工具 | 三工具权限测试通过 |
| Day 7 | Task 7 RAG 与引用 | ATT&CK 检索和引用校验通过 |
| Day 8 | Task 9 API 与 SSE | 前端可实时接收角色状态 |
| Day 9 | Task 10 核心界面 | 可见攻击链、证据和审批 |
| Day 10 | 集成和内部录屏 | 完整闭环连续运行三次成功 |

Day 10 的固定演示链路：

```text
导入 SQL 注入告警
→ 聚合同资产事件
→ 六角色协作调查
→ 判断观察到的攻击入口与攻击类型
→ 映射 ATT&CK
→ 生成攻击链和响应方案
→ 人工批准
→ 模拟封禁
→ 查询后续事件
→ 给出效果验证
→ 生成证据可追溯报告
```

---

## 7. 8～10 周里程碑

| 周次 | 目标 | 退出条件 |
|---|---|---|
| 第 1～2 周 | 完成纵向切片 | 六角色闭环、证据、审批、验证可演示 |
| 第 3 周 | 完成 RAG、MCP 和来源/类型判断 | 引用校验和安全边界通过 |
| 第 4 周 | 完成本地靶场和 AIT 数据管道 | 输入与金标隔离、事件包可重建 |
| 第 5 周 | 完成四个基线 | 240 次主实验可运行 |
| 第 6 周 | 完成消融和误差分析 | 96 次消融及指标报告完成 |
| 第 7 周 | 前端、性能和可用性优化 | E2E、响应式和性能预算通过 |
| 第 8 周 | 安全加固和完整回归 | 覆盖率、故障和安全测试通过 |
| 第 9 周 | PDF、README、视频 | 比赛材料完成并与代码版本一致 |
| 第 10 周 | 缓冲和可选在线演示 | 只修复阻断问题，不增加高风险功能 |

---

## 8. 最终验收清单

- [ ] GitHub 或 Gitee 仓库为 Public，完整保留真实提交历史。
- [ ] README 包含项目介绍、架构、安装、测试、团队与安全说明。
- [ ] `.env.example` 完整，但仓库不存在真实秘密。
- [ ] `docker compose up -d` 能启动 PostgreSQL 和 OpenSearch。
- [ ] fixture 模式不依赖云密钥即可演示。
- [ ] 一条告警能走完六角色、审批、模拟处置和验证。
- [ ] 每个事实结论可追溯到 Evidence ID。
- [ ] 攻击来源表述为观察到的入口/源实体，不夸大为现实身份归因。
- [ ] 攻击类型支持多标签和攻击阶段顺序。
- [ ] AIT 测试标签与 Agent 输入完全隔离。
- [ ] 336 次正式实验具有数据、模型、提示词、依赖和 Git 版本记录。
- [ ] 技术 PDF 不超过 30 页。
- [ ] 演示视频为 5～8 分钟、MP4、1080p。
- [ ] 在线演示若启用，只使用预置只读数据，不暴露靶场或真实处置能力。

## 9. 明确延后内容

以下内容不进入 v1.0.0-demo：Wazuh 实时接入、Suricata 独立部署、Nmap/OpenVAS 主动扫描、TheHive 双向同步、图数据库、多模态输入、真实防火墙配置、真实账号禁用和公网自动化测试。只有在全部验收门槛通过并完成单独威胁建模后，才能作为后续里程碑加入。
