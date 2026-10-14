# EvidenceSOC Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 在已有六角色调查闭环、RAG、MCP、API 和前端基础上，以比赛交付和可信实验为优先目标，完成有限自主取证、AIT 与 DEDALE 评测、安全验收及交付材料。5～8 周为原收尾估算；采用 DEDALE 后须按下载、解压、适配试验的实测结果更新工期，不从头重做已实现任务。

**本次修订：** 仅维护本实施计划；原 Task 12 靶场接入取消，编号 12 重新用于 Task 13 前的集成与数据准入验收。本期调优现有 AI 系统，不开展模型权重训练；人工整理的长期经验库在完整交付后视时间可选添加。

**进度基线（2026-10-09，历史快照）：** 当时的 Task 10 代码版本为 `3d8880f`。Task 1～10 的主要实现已存在，但不能据此认定所有验收项通过；Task 8 的有限自主取证为新增待办，Task 11/13 的 AIT 管道及正式实验待完成，Task 14 在已有安全、恢复和性能测试上补充验收，Task 15 完成交付材料。已有勾选记录保留，未勾选的历史步骤须核对实际代码与验证证据，不自动重建或自动标记完成。

**补充进度（2026-10-13）：** Task 6/8 的有限自主取证、逐调用台账与恢复已实现并完成兼容性验收；开发库升级至合并迁移 `e902c4b7a1d6`，升级前备份为 `evidencesoc_backup_before_task68_20261013`。AIT 冻结测试集的评测清单与离线评分程序已准备，正式模型运行及近期补充集评测仍按后续任务执行。

**集成复核（2026-10-13）：** 本地 `main` 停在 `1f1dbfa`；Task 10 的 `3d8880f` 位于 `codex/task10-frontend`，Task 11 的 `f21dda1` 位于 `task11-ait`，二者尚未整合。Task 6/8 增强、合并迁移和来源待核实的评测文件仍在未提交工作区；评测文件的存在不能认定用户已开始 Task 13。上述本机验收记录不能代替统一提交版本上的复验；Task 12 全部关口通过后才可启动 Task 13。

**数据方案修订（2026-10-14）：** 保留 AIT 冻结测试/消融各 22 包，近期补充集首选第三方公开的 DEDALE。本期不要求自行开展攻击采集，取消此前讨论的自建 32 包及 8/8/16 拆分；DEDALE 按作者建议使用前两周正常背景校准、后两周冻结测试，实际包数由日志可观察性和预先登记的选择规则确定。Windows-APT 等其他数据源仅为后续可选扩展，不增加本次 Task 12 验收门槛。

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
- 自主选择工具和补查仅发生在取证阶段；外层六角色流程、人工审批和证据不足最多回退一次的规则不变，不引入全流程自由循环。
- 每次 `collect` 最多 3 次逻辑工具调用，包含初始上下文；同一调查取证累计最多 6 次。失败和空结果消耗预算，重复查询复用结果；回退、降级与重启均不重置预算。物理重试受独立上限约束并单独统计，审批后的处置验证查询另计。
- 正式评测时，Agent 只能读取获准的原始日志和已冻结的知识库；`labels/`、`attacks.log` 和攻击者真值仅限隔离的数据准备、金标复核及评分流程读取，不能进入模型上下文、检索索引或知识库。
- 按完整 AIT 场景隔离调优、内部验证和冻结测试；不按日志行随机拆分，不用最终测试结果反向修改提示词、工具策略或知识库。本期不进行模型权重训练。
- 先用 AIT 跑通基础流程；Task 12 验收前接入、审计并冻结 DEDALE 近期第三方公开日志。保留采集/事件日期与发布版本，明确它是研究机构实验环境中的攻击仿真采集；AIT 与 DEDALE 分别报告，不将公开发布等同于真实企业入侵，也不以单一攻击场景证明覆盖全部当前攻击。
- 所有安全结论必须引用有效 Evidence ID；证据不足时返回 `unknown`，不得编造来源或攻击类型。
- 代码、测试和文档使用真实 Git 提交记录；每个任务完成后执行对应验证再提交。

---

## 1. 最终产品范围

### 1.1 六个逻辑角色

1. 告警分诊 Agent：告警聚合、去重、风险评分、提取初始实体。
2. 证据收集 Agent：在代码规定的范围和预算内，自主选择只读工具检索日志、告警上下文和 ATT&CK 知识，并按证据缺口补查或停止。
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
→ 证据收集（有限自主选择工具与补查）
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

取证首先读取固定告警上下文，之后由模型输出工具名称、参数和补查依据，或选择结束；代码负责校验并执行。每轮 `collect` 包含种子查询在内最多 3 次逻辑调用，第二轮继承调查累计预算，上限为 6 次；完成的重复查询复用台账结果，反复重复或无新增证据时结束本轮。工具依赖失败、预算耗尽或证据不足必须如实记录，不包装为成功结论。

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

本期有限自主取证沿用现有 REST、SSE 和审批契约，不新增公共端点或 SSE 事件名称；决策依据、预算消耗、停止原因与降级信息写入内部状态及现有 AgentRun 输出摘要。下表为原规划契约，尚未实现的实验接口随 Task 13 核对，不能视为当前已上线。

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

硬限制：事件工具 `limit <= 200`，告警上下文单侧窗口 `<= 900` 秒，ATT&CK 返回 `<= 10` 条；每次工具物理尝试超时 10 秒，每个逻辑调用最多重试两次，即最多 3 次物理尝试。模型结构化输出重试沿用 Task 8 的最多两次限制，分别记录模型与工具的实际尝试数。

取证调用规则：

- 每次 `collect` 最多 3 次逻辑工具调用，同一调查取证累计最多 6 次；固定 `get_alert_context` 种子查询计入额度，`lookup_attack_technique` 知识查询同样计入。
- 新逻辑调用执行前原子预占预算并写入持久化台账；失败、空结果及策略拒绝不退还额度。重复指纹复用已完成结果，不重复执行或重新获得额度；物理重试属于原逻辑调用，不另扣逻辑预算，但受物理尝试上限约束。
- 工具名称、参数类型、案件/场景归属、时间范围、过滤字段和返回数量由代码校验；模型不得指定其他案件、测试场景、底层索引或真值数据路径。
- 调用台账逐次保存调查 ID、取证轮次、查询指纹、预算、状态、物理尝试数和结果引用；重启复用已完成结果。未确认完成的调用只在原额度和剩余物理尝试内恢复，无法恢复时明确失败或进入人工复核。
- 审批后的处置验证查询沿用原受限流程，单独记录调用数、尝试数与耗时，不占取证预算；必须重新验证，不能用审批前缓存冒充处置后的证据。

---

## 5. 实施任务

**执行口径：** Task 1～10 保留历史实现步骤与已有勾选，不要求重新创建已存在文件。收尾时先核对实现和验收证据，仅补缺口；Task 6/8 标注的收尾补充、Task 12 集成与数据准入、Task 13 评测、安全补测及比赛材料才是剩余安排。文件清单中的 `Create` 对已存在文件按维护或修改处理。

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

**当前状态（2026-10-13）：** 三个受限工具与 MCP Server 已实现；预算和恢复台账增强已有本机验收记录，部分代码仍在未提交工作区。以下记录保留，Task 12 负责提交整合及统一版本复验，不能据此直接认定集成验收完成。

**Files:**
- Create: `services/backend/src/evidencesoc/tools/policy.py`
- Create: `services/backend/src/evidencesoc/tools/security_events.py`
- Create: `services/backend/src/evidencesoc/tools/attack.py`
- Create: `services/backend/src/evidencesoc/mcp_server/main.py`
- Create: `services/backend/tests/tools/test_policy.py`

**Interfaces:**
- Consumes: OpenSearch、PostgreSQL、ATT&CK 知识库。
- Produces: 第 4.3 节三个异步工具，以及供有限取证使用的预算、去重与持久化调用台账。

- [x] **Step 1: 编写权限边界测试**

覆盖 201 条结果、901 秒时间窗、负数时间窗、未知工具、空 Alert ID、超时和 OpenSearch 失败。

- [x] **Step 2: 实现纯函数策略校验器**

校验必须在调用存储层之前执行；拒绝结果写入 `tool_calls`，包括原因和 trace ID。

- [x] **Step 3: 实现三个工具和 MCP Server**

所有结果先转换成 `EvidenceItem`；错误返回结构化代码 `POLICY_DENIED`、`NOT_FOUND`、`DEPENDENCY_TIMEOUT` 或 `DEPENDENCY_UNAVAILABLE`。

- [x] **Step 4: 验证工具列表**

Expected：MCP 客户端只能发现 `search_security_events`、`get_alert_context` 和 `lookup_attack_technique` 三个工具。

- [x] **Step 5: 提交**

```powershell
git add services/backend/src/evidencesoc/tools services/backend/src/evidencesoc/mcp_server services/backend/tests/tools
git commit -m "feat: add restricted mcp investigation tools"
```

**完成标志：** 工具无法执行 Shell、访问任意 URL、扩大时间窗或返回超过上限的数据。

- [x] **收尾补充 1: 接入取证预算与查询去重**

落实第 4.3 节的每轮 3 次、调查累计 6 次逻辑调用限制，种子、知识查询、失败和空结果均计入。规范化工具名与参数生成查询指纹；校验案件/场景范围并记录策略拒绝，缓存命中不重新执行。规则降级、外层回退与重启共享同一调查额度。

- [x] **收尾补充 2: 实现逐次持久化台账与恢复测试**

在 PostgreSQL 持久化原子额度预占、查询状态、物理尝试数和结果引用，所需模型与迁移纳入后续实现提交。覆盖并发预占、调用前中断、调用完成但节点未结束、结果未确认及重试额度用尽。取证预算与审批后验证查询分别审计，完成恢复后再运行现有工具权限测试。

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

**当前状态（2026-10-13）：** 六角色图、审批、规则降级和调查检查点已有实现；取证节点内部的有限自主选择工具、补查及恢复增强已在本机实现并留有验收记录，外层角色顺序保持固定。未提交增强仍须经过 Task 12 的整合及统一版本复验。

**Files:**
- Create: `services/backend/src/evidencesoc/agents/state.py`
- Create: `services/backend/src/evidencesoc/agents/nodes/*.py`
- Create: `services/backend/src/evidencesoc/agents/graph.py`
- Create: `services/backend/src/evidencesoc/agents/fallback.py`
- Create: `services/backend/tests/agents/test_graph.py`
- Modify: `services/backend/src/evidencesoc/agents/services.py`，接入有限取证与 Task 6 调用台账。

**Interfaces:**
- Consumes: 三个 MCP 工具、RAG、领域模型和 PostgreSQL Checkpointer。
- Produces: `run_investigation(incident_id: str)` 异步工作流和节点事件。

- [ ] **Step 1: 为状态转换编写失败测试**

覆盖正常闭环、证据不足回退一次、第二次转人工、模型超时、审批拒绝、恢复检查点和验证失败。

- [ ] **Step 2: 实现 `InvestigationState`**

状态至少包含 incident ID、状态、告警、证据、来源判断、攻击分类、攻击步骤、响应方案、审批结果、验证结果、回退次数和错误。收尾新增取证轮次、逻辑预算消耗、台账引用、停止原因和降级状态；持久化台账作为循环恢复依据，不能只依赖节点结束后的检查点或 AgentRun 展示摘要。

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

- [x] **收尾补充 1: 实现有限自主取证规划器**

首次读取固定告警上下文，后续使用结构化输出选择白名单工具、参数、查询依据或结束；由代码执行案件范围、参数和预算校验。工具错误与空结果返回结构化观察，允许在剩余额度内补查。反复重复、无新增证据、额度耗尽或主动结束均产生明确停止原因；保留已有 Evidence ID 归属与完整性校验。

- [x] **收尾补充 2: 接入逐调用恢复及规则降级**

每次调用均使用 Task 6 台账，不等待整个 `collect` 返回后才保存；第二轮取证继承累计预算并复用已完成查询。模型超时、不可用或结构化重试耗尽时使用受同一范围与预算约束的确定性规则，记录 `fallback_used=true` 与停止原因；不能修改自身代码、提示词或长期知识库。

- [x] **收尾补充 3: 完成兼容性与验收**

运行现有图、工具和 API 测试，并补充预算耗尽、重复查询、跨案件/场景查询、空结果、模型超时及循环内部重启测试。REST、SSE 事件名称、审批机制与六角色顺序保持兼容；AgentRun 输出摘要补充查询依据、预算和降级信息。该增强含联调和测试预计增加 4～7 个工作日，已包含在剩余 5～8 周排期中。

验收记录（2026-10-13）：最终回归中 Agent/工具/持久化/证据及真实服务测试 298 项、评测程序测试 550 项通过；此前完整 API 与六角色验收 101 项也通过。298 项中包含真实 OpenSearch 场景隔离测试；另在完整 999 知识块库上完成了独立进程六角色恢复测试。测试覆盖预算、去重、超时、空结果、跨场景阻断、并发预占及 `collect` 内三个中断点；数据库迁移后原有案件、AgentRun、证据和知识块行数不变，`alembic check` 无待生成操作。现有 OpenSearch `security-events-v1` 索引已补齐 `dataset_id: keyword` 映射，更新前后文档数均为 5。

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

**当前状态（2026-10-11）：** AIT 基础流程已跑通：固定 8 个场景的拆分，完成 Fox、Russellmitchell 及新增 6 个场景的来源处理；新增 8 个开发/内部验证包，并冻结 Shaw、Wilson 测试包 22 个（攻击 11、正常 11），消融子集 22 个。各包重建一致，测试时间窗互不重叠，Agent 输入通过金标隔离审计。48/24 的目标数量因独立攻击阶段不足按实际 `N=22`、`M=22` 报告，不重复切片补足。近期补充集由 Task 12 建设、验收并冻结。

**数据时效性安排：** AIT 继续承担流程验证、开发调优与内部验证，冻结测试保留 Shaw/Wilson 的 22 包。Task 12 接入 DEDALE 作为近期第三方公开补充集，记录日志事件时间、采集时间、发布版本、传感器环境和标签依据。DEDALE 前两周仅用于解析、字段归一和正常背景校准，后两周整体作为冻结外部测试；其中同一 APT campaign 不拆入调优/验证。该协议属于经过正常背景校准的外部测试，不描述为完全未经适配的测试。来源、标签及冻结验收细则见 Task 12 Step 6。

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

- [x] **Step 1: 按完整场景固定调优、内部验证与测试拆分**

```json
{
  "development": ["fox", "harrison", "russellmitchell", "santos", "wheeler"],
  "validation": ["wardbeck"],
  "test": ["shaw", "wilson"]
}
```

5 个场景用于提示词、检索、规则和工具策略调优，1 个场景用于内部验证，2 个场景用于冻结测试。开发与内部验证合计 6/8，即 75%；测试为 2/8，即 25%。比例按场景数计算，不代表日志行或事件包严格符合 80/20，也不进行模型权重训练。

测试必须断言三个集合没有交集，案件、日志查询和事件包不能跨场景。最终测试标签仅供评分，提示词、配置、工具策略、知识库版本、事件包选择规则与评分规则在正式测试前冻结；不得依据最终测试结果重新调优。

- [x] **Step 2: 解析原始日志并保留行号**

每个事件必须保存 `dataset_id`、`relative_log_path`、`line_number`、`host`、`timestamp` 和规范化字段。

- [x] **Step 3: 用联合键连接标签**

联合键固定为 `(dataset_id, relative_log_path, line_number)`；确认标签文件完整且匹配成功后，无攻击标签的日志才记为正常，标签缺失、连接失败或解析异常须记录并排除，不能当作正常样本。评分程序保存原始标签，Agent 输入中删除标签字段。

- [x] **Step 4: 构建攻击来源金标**

评分字段为观察到的源 IP、入口主机、入口服务、首次攻击时间和后续跳转主机。`attacks.log` 与含攻击者标识的配置只进入评分侧；原始日志无法观察的攻击步骤须标记可观察性，不要求系统凭空重构。

- [x] **Step 5: 构建攻击类型字典**

固定标准类型为 `reconnaissance`、`credential_attack`、`webshell_upload`、`remote_command_execution`、`privilege_escalation`、`data_exfiltration`。一个事件包允许多个类型，不能压缩成单分类。

- [x] **Step 6: 核验实际测试规模并冻结 22 个测试包及 22 个消融包**

仅从 `shaw`、`wilson` 构建冻结测试包。原目标为 48 个测试包、24 个消融包；实际合格数量为 `N=M=22`（攻击 11、正常 11），已按计划的数量不足处理规则冻结。每个包保存重建所需 ID、时间范围、场景、选择规则和哈希，不提交大型原始数据。

先核验两个测试场景中合格案例的数量；不足时如实记录主测试包数量 `N` 和消融子集数量 `M`（`M <= N`），不重复填充或把高度重叠窗口当成新增独立案例。各基线使用同一批冻结包，各消融使用同一子集；记录包间关联并分别报告两个场景结果，不把同场景多个窗口视为独立场景。

DEDALE 使用独立 manifest 和案例 ID，不计入上述 AIT 的 22 包。Task 12 验收前完成其来源、时间、标签质量、合格案例数量和防泄漏核验；未完成时 Task 12 不验收、Task 13 不启动，并记录缺口，不宣称已验证近期攻击能力。

- [x] **Step 7: 执行防泄漏测试**

测试 Agent 输入中不存在 `labels`、`rules`、`attacks.log` 内容、`attacker_0` 真值或测试答案。

- [x] **Step 8: 提交**

```powershell
uv run --project services/backend pytest evals/tests/test_ait_ground_truth.py -v
git add evals data/manifests
git commit -m "eval: add isolated ait ground truth pipeline"
```

**完成标志：** 任意测试事件包可由 manifest 重建；评分金标与 Agent 输入完全隔离。

### Task 12: 集成收口与近期补充集准入（Task 13 前置验收）

**本轮执行（2026-10-14）：** Step 1～3 已在 `codex/task12-readiness` 独立集成工作树完成，详见 `docs/acceptance/task12-readiness.md`。原工作区 29 个修改和 31 个未跟踪文件保持不变；来源待核实的评测文件仅保全。Task 10/11 的祖先、唯一迁移 head、真实批准/拒绝两支路及完整 61 项浏览器回归已核对。Step 4～6 仍待验收，本地 `main` 的推进按 Step 6 执行；Task 13 未启动。

**当前状态（2026-10-13）：** 尚未验收。本地 `main` 停在 `1f1dbfa`；Task 10 的 `3d8880f` 与 Task 11 的 `f21dda1` 位于不同分支，Task 6/8 增强及合并迁移仍有未提交文件。AIT 的 22 个测试包在当前路径审计通过，但评分 manifest 含本机绝对路径。DEDALE 已选定并完成公开元数据核验，尚未下载数据归档、实现适配或冻结案例；本次计划修订不代表上述工作已经完成。

**范围边界：** 本任务完成统一版本的集成、Task 1～10 遗留门槛复验、AIT 异路径重建以及近期补充集的来源、标签、拆分和冻结。Task 13 才实现 B0～B3、四项消融、真实模型适配器和最终指标，并在首次正式测试前冻结模型、提示词、各组配置及最终评分规则；这些实现和正式实验结果不得作为 Task 12 的前置条件。Task 14 的完整安全、故障和连续三次 E2E 总验收仍在后续执行。

**Files:**
- Create: `docs/acceptance/task12-readiness.md`，记录每个关口的命令、时间、Git SHA、环境、结果、失败/跳过数与证据位置。
- Modify: `docs/environment-verification.md`、`apps/web/src/features/incidents/AttackGraph.tsx`、`apps/web/e2e/full-flow-live.spec.ts` 及对应前端测试，补齐已发现的历史验收缺口。
- Modify: `evals/datasets/ait_v2/build_manifests.py`、`evals/tests/test_ait_case_manifests.py`、`data/manifests/ait-task11-test-selection.json` 和 `data/manifests/ait-task11-dev-validation-selection.json`，消除路径依赖并重核冻结哈希；Create: `scripts/ait_task12_crosspath_check.py`，执行异路径重建与产物哈希对照。
- Create: `docs/datasets/dedale.md`，记录来源、日期证据、许可、传感器、标签语义、适用范围和完整重建命令。
- Create: `evals/datasets/dedale/parse.py`、`evals/datasets/dedale/join_labels.py`、`evals/datasets/dedale/build_manifests.py`，分别负责字段转换、原始标签连接及确定性案例重建；不得直接把 DEDALE 输入交给写死 AIT 场景的构建器。
- Create: `data/manifests/dedale-sources.json`、`data/manifests/dedale-splits.json`、`data/manifests/dedale-selection.json`、`data/manifests/dedale-label-policy.json`，保存来源、时间拆分、案例/消融选择和标签映射规则；具体逐事件答案保存在隔离的评分侧。
- Create: `evals/tests/test_dedale_parse.py`、`evals/tests/test_dedale_ground_truth.py`、`evals/tests/test_dedale_manifests.py`、`scripts/dedale_task12_audit.py`；原始归档、解压日志和生成包放在忽略提交的本地数据目录。
- Modify: `services/backend/src/evidencesoc/ingestion/normalize.py`、`services/backend/src/evidencesoc/agents/services.py` 及相关接入/工具测试，补齐真实证据字段投影和历史告警时间；维持工具白名单、案件边界与预算。
- Modify: Task 10、Task 6/8 的实际冲突文件、数据库迁移和必要测试；只保留一条可升级的迁移链。

**Interfaces:**
- Consumes: Task 1～10 的系统实现、Task 11 的 AIT 原始来源与冻结选择清单、现有 Task 6/8 工作区增强，以及 DEDALE 官方版本固定的系统日志与标签归档。
- Produces: 一个可从提交复现的本地 `main` 版本、AIT 与 DEDALE 各自独立的 Agent 输入和评分金标、冻结数据清单，以及逐项通过的 Task 12 验收记录。

**证据规则：** 以下六步全部在同一集成提交链上验证。旧日志和本机先前的 298/550/101 项通过记录只作背景；关键用例被跳过、环境权限阻断、真实服务不可用或仅有模拟接口结果，均不能记为通过。验收记录必须写明实际运行数、失败数与跳过数，不以“已有测试文件”代替运行证据。远端仓库公开与发布属于 Task 15，不作为本任务门槛。

- [x] **Step 1: 盘点并保护现有改动**

保存 `git status --porcelain=v1 -uall`、分支图、工作区差异及未跟踪文件清单，核对 29 个已跟踪修改、31 个未跟踪文件的实际最新数量。按 Task 6/8、Task 10 迁移、来源待核实的评测文件和文档分组保全；未经核对不得清理未跟踪文件。明确哪些文件进入 Task 12 集成版本，来源待核实的评测文件另行保留，不纳入本次集成；文件存在不构成 Task 13 已启动或已验收的证据。记录保全位置、哈希及恢复办法后，使用干净的集成工作树，不依赖删除原工作区来取得干净状态。

```powershell
git status --porcelain=v1 -uall
git log --graph --oneline --decorate --all -20
git diff --check
git remote -v
```

Expected：所有当前改动均可追回；验收记录列明来源、去向和重复文件处理结果，`git diff --check` 无错误。

- [x] **Step 2: 整合 Task 10、Task 11 与 Task 6/8 到同一版本**

在保全后的干净工作树建立 `codex/task12-readiness` 集成分支，以 `main` 为基点纳入 `codex/task10-frontend`、`task11-ait` 的已提交成果，再分批纳入 Task 6/8 的代码、测试与迁移。逐个核对 9 个同路径改动和 3 个重复迁移文件，合并数据表、审批字段、调用台账和 OpenSearch `dataset_id: keyword` 映射；不得以一侧文件整体覆盖另一侧。以唯一 Alembic head、既有数据行数及跨场景查询结果确认迁移与索引兼容。各批次验证后提交真实 Git 记录，验收通过时将集成结果纳入本地 `main`。

```powershell
git switch -c codex/task12-readiness main
git merge --no-ff codex/task10-frontend
git merge --no-ff task11-ait
git merge-base --is-ancestor 3d8880f HEAD
git merge-base --is-ancestor f21dda1 HEAD
uv run --project services/backend alembic -c services/backend/alembic.ini heads
git diff --check
```

Expected：两个祖先检查退出码均为 0，Alembic 只有一个最终 head；Task 10 前端和 Task 6/8 取证增强都存在于同一提交链。整合后的数据库升级、OpenSearch 映射与原有记录保持一致。

- [x] **Step 3: 补齐 Task 10 并跑通真实界面闭环**

攻击链 React Flow 节点直接显示阶段、主机、时间和置信度；点击节点可追溯 Evidence ID、来源、查询和哈希。用例从告警列表启动调查，观察六角色状态，查看原始证据；批准后看到模拟处置和验证结论，拒绝后流程停止、记录理由且没有模拟处置。现有 `full-flow-live.spec.ts` 只覆盖批准支路，须为拒绝支路增加独立的真实后端浏览器用例并使用不同的测试告警 ID；仅靠模拟 API 的拒绝测试不算真实闭环。另核对 SSE 断线恢复、刷新、loading/empty/error/retry 状态。浏览器在 1440×900、1920×1080 下无横向溢出或控制台错误。真实闭环在隔离后端和已导入样例告警上运行；`TASK10_LIVE_SEED_ALERT_ID`、`TASK10_LIVE_ISOLATED_BACKEND` 缺失造成的 skip 不算通过。页面代理的 `BACKEND_URL` 必须与测试直连的 `TASK10_LIVE_ISOLATED_BACKEND` 完全一致；验收时禁用 Playwright 复用已有 Web 服务，核对新启动的 Web 进程确实继承该地址，避免页面请求落到另一后端。

```powershell
pnpm --dir apps/web lint
pnpm --dir apps/web typecheck
pnpm --dir apps/web test
if ([string]::IsNullOrWhiteSpace($env:TASK10_LIVE_ISOLATED_BACKEND) -or [string]::IsNullOrWhiteSpace($env:TASK10_LIVE_SEED_ALERT_ID)) { throw "缺少真实闭环环境变量" }
$env:BACKEND_URL = $env:TASK10_LIVE_ISOLATED_BACKEND
$env:CI = "1" # Playwright 不复用已有 Web 服务；运行前确认目标端口空闲
pnpm --dir apps/web exec playwright test
pnpm --dir apps/web exec playwright test e2e/full-flow-live.spec.ts --workers=1
pnpm --dir apps/web build
```

Expected：质量命令全部退出码为 0；批准与拒绝两条真实闭环用例实际通过且关键用例 `skipped=0`，拒绝案件没有后续模拟处置。保存 Playwright 报告、隔离后端及 Web 进程地址、案件/证据/审批 ID 与两个分辨率的核查结果。

- [ ] **Step 4: 在集成版本上补齐 Task 1～9 的遗留验收**

更新环境记录中的当前路径、宿主机 CPU/内存、Docker 资源、工具实际版本与检查日期；在隔离环境验证 PostgreSQL 和 OpenSearch 的健康、版本以及写入标记后重启读回同一值/哈希。迁移的 `upgrade head → downgrade -1 → upgrade head` 仅在可丢弃数据库上运行；已有开发库先备份，再核对升级前后表、行数与 `alembic check`，不在保存业务数据的库中直接降级。重新验证接入幂等、Evidence 原文/哈希、三工具白名单与边界、完整知识库 Recall@8 和引用校验。

真实 PostgreSQL、OpenSearch 与 MCP 环境中，复核每轮 3 次、调查累计 6 次逻辑取证调用，失败、空结果、重复指纹、物理重试、并发预占、跨案件/场景拒绝、规则降级及 `collect` 内三个中断点恢复；重启不得重置额度或重复模拟处置，审批后验证查询单独计数。API 验证 `Last-Event-ID` 恢复、首个 SSE 事件小于 2 秒、普通非模型 API 本机 P95 小于 500 ms 和秘密脱敏；记录测量样本数。运行整合后的后端测试与关键真实服务用例，关键项 `skipped=0`。当前运行环境若阻止 Docker、子进程或临时目录访问，改在可执行的隔离验收环境重跑并留证，不将权限错误写为通过。

```powershell
docker compose ps
uv run --project services/backend pytest services/backend/tests -q -rs
uv run --project services/backend ruff check services/backend
uv run --project services/backend mypy services/backend/src
uv run --project services/backend alembic -c services/backend/alembic.ini heads
uv run --project services/backend alembic -c services/backend/alembic.ini check
$env:RUN_RAG_ACCEPTANCE = "1"
uv run --project services/backend pytest services/backend/tests/rag/test_acceptance.py -q -rs
$env:EVIDENCESOC_TEST_POSTGRES = "1"
$env:EVIDENCESOC_TEST_OPENSEARCH = "1"
uv run --project services/backend pytest services/backend/tests/api/test_live_acceptance.py services/backend/tests/api/test_checkpoint_recovery.py services/backend/tests/persistence/test_event_search_acceptance.py -q -rs
```

Expected：环境、持久化、迁移、安全边界、恢复与性能均有同一 Git 版本的可核对结果；已知缺口逐项关闭。三个显式开启的真实服务测试组必须报告实际通过数，不能只看 pytest 退出码或默认 skip。完整 Task 14 安全总验收继续留在 Task 14。

- [ ] **Step 5: 修复 Task 11 AIT 清单的异路径重建**

将评分 manifest 中的 `build.source_config`、`build.splits` 和 `input_sha256` 文件键改为相对明确数据根的稳定引用；重建时由传入的数据根解析，哈希不包含本机绝对路径。对旧 `D:\传智杯` 清单保留变更原因及旧哈希，重新生成受影响的选择清单。在本步实现可执行的异路径重建入口并记录完整命令：于另一个绝对路径建立干净工作区，按来源清单重新获取或复制同一归档及六类输入并逐一核验原始哈希，使用新入口从该路径重建全部 22 个冻结测试包和选择清单，逐项比较新冻结清单要求的 Agent/评分产物哈希；只在原路径跑审计不足以验收。再次断言 5/1/2 场景无交集、测试 22 包（攻击 11、正常 11）、消融 22 包、时间窗不重叠、标签连接完整及 Agent 无金标。AIT 实际计划为 `4N + 4M = 176` 次，不能为凑原 288 次目标重复切片；这 176 次正式模型运行属于 Task 13。

```powershell
uv run --project services/backend pytest evals/tests -q -rs
uv run --project services/backend python -B scripts/ait_task11_audit.py
```

上述现有命令只核验当前包，不能代替异路径重建。验收记录还须附另一目录的实际重建命令、工作区绝对路径、来源获取/校验日志，以及按案例列出的当前路径与异路径 `agent/manifest.json`、`agent/events.jsonl`、`scoring/manifest.json`、`scoring/gold.jsonl` 的 SHA256 对照。Expected：当前目录和另一绝对路径的全包重建均通过，哈希一致；来源归档哈希、旧/新冻结清单哈希及路径迁移原因写入 Task 12 验收记录。AIT 原始数据不进入 Git，重建所需获取与核验步骤必须可供干净环境执行。

- [ ] **Step 6: 接入、冻结 DEDALE 并签署 Task 12 关口**

本步采用第三方已经采集并公开发布的日志，工作内容是获取、转换、隔离、复核与重建，不要求项目成员再次实施攻击。以下 6.1～6.6 均为 Step 6 的必验子项；数据质量和接入验证在本步完成，正式模型比较与评分公式实现仍属于 Task 13。

**6.1 固定来源、版本、许可与资源预算**

首选来源为 Inria / DGA 研究团队公开的 DEDALE，数据集 DOI `10.57745/Y5JLDG`。截至 2026-10-13，[官方仓库](https://entrepot.recherche.data.gouv.fr/dataset.xhtml?persistentId=doi%3A10.57745%2FY5JLDG)与[官方 API](https://entrepot.recherche.data.gouv.fr/api/datasets/:persistentId/?persistentId=doi:10.57745/Y5JLDG)记录的发布版为 **V2.1，2026-09-25 发布**；冻结时保存该版本的元数据快照，不跟随 `latest` 静默更新。许可按官方记录为 CC BY 4.0，引用数据集 DOI、版本、[下载说明](https://dedale.inria.fr/download.html)及论文 [Get out of DEDALE with RESCOUSSE](https://doi.org/10.1007/978-3-032-16092-8_1)。数据来自实验环境中的 APT 类攻击仿真与正常业务采集，报告中保留这一限定。

本期必需归档及当前官方 MD5 如下；表中仅为元数据核验结果，尚不代表文件已下载或校验通过：

| 归档 | 官方字节数 | 官方 MD5 | 用途 |
|---|---:|---|---|
| `system_logs_auditbeat.zip` | 10,896,385,060 | `d01b50094a93aa5ebc8a46e6150d256b` | Linux/auditd 系统事件 |
| `system_logs_winlogbeat.zip` | 27,123,250,952 | `7af54ba2977f7535d4c07beb6b1ec657` | Windows/Sysmon 系统事件 |
| `system_logs_labels.zip` | 2,669,407 | `455d0a7042531eff74285006f97822e4` | 系统日志金标，仅数据准备和评分侧使用 |

三包合计约 **38.02 GB 压缩数据**，解压、生成包和检索索引还需额外空间。先保存下载 URL、dataFile ID、字节数与校验值；完成一份归档的完整性检查后，只抽取正常时期的小样本测量解析吞吐、解压占用与索引膨胀，记录宿主机/Docker 可用磁盘及预计耗时，再开始全量处理。下载后对照官方 MD5，并自行计算 SHA256；解压须检查 CRC、文件数及失败条目。不能把尚未实测的存储需求写成已具备条件。

Syslog 可在确认对既定可观察阶段有增益时补入；Packetbeat、Zeek、全量 PCAP 和虚拟机镜像不列为本期必需输入。官方 V2.1 元数据列出了部分损坏的 PCAP 归档，需保存该公告；公告不能推导为系统日志归档损坏，也不能代替实际下载校验。必需归档若无法完整获取或标签不能连接，本关口保持未通过并记录原因，不静默更换来源。

**6.2 核验事件日期并按作者时间边界隔离**

“近期”的本项目口径预先固定为：所用日志事件处于 Task 12 数据冻结日前 24 个月内；以事件/采集日期判定，不能用 2026 年发布或下载日期替代。此前方案中的预期事件范围为 2024-12-23～2025-01-19、攻击期为 2025-01-06～01-13；本次可访问的元数据确认了四周和八天攻击长度，但未独立核实这些精确日期。冻结前必须用[官方场景说明](https://dedale.inria.fr/attack_scenario.html)、README 和原始时间戳交叉核对并记录证据、时区及最终 UTC 边界；如不符合 24 个月口径，重新审查“近期”结论，不能只修改日期称谓。

按[作者建议](https://dedale.inria.fr/download.html)，前两周为纯正常活动，只用于解析/字段归一、接入排错和预先列明的正常背景校准；后两周整体冻结为 test，包含从第三周开始的同一个八天 APT campaign 及后续正常活动。内部攻击调优和验证沿用 AIT development/validation，DEDALE 不强行拆成三个均含攻击的集合。

在 `dedale-splits.json` 中明确记录 `purpose=benign_calibration`，与现有运行器兼容时映射为 `split=development`；后两周记录 `purpose=external_test, split=test`。数据准备侧可读取测试期原始数据及标签以构建金标、检查格式和计算覆盖，但不得把测试案例、攻击答案或场景说明用于调整模型、提示词、工具策略和知识库。测试期适配如发现格式错误，单独记录纯机械修复及影响范围，重新冻结数据；不能利用模型输出选择修复或保留哪些案件。

时间区间采用 `[start, end)`，保留原始时间及偏移后统一为 UTC。不能平移历史日志到导入当天；同一事件和 campaign 不得跨校准/测试边界，边界相交窗口按预先规则排除并计数。

**6.3 实现最小接入，并证明证据进入真实取证上下文**

每条规范化事件至少具有稳定 `external_id`、`dataset_id`、原始归档/相对文件路径、行号或记录序号、原文哈希、`source`、`event_type`、`observed_at` 和字符串 `host`。明确 Sysmon 与 Auditbeat 的原始事件 ID、进程、父进程、命令行、用户、网络连接等字段到 Evidence 的映射；实际缺失字段保留缺失，不生成虚构 IP/主机。仅将可观察原文的获准字段加入 Agent 投影，并维持输出长度及敏感字段边界。

当前实现会以告警 `created_at` 为中心取前后各 900 秒，查询锚点固定在初始 `source_ip/host/service`；未显式填写历史时间会落到当前时间。本期沿用该受限能力：告警时间取冻结窗口中心，窗口裁剪和端点规则在构建器、接入、检索与评分侧一致。选择稳定主机锚点，记录最终过滤条件；不得为单个测试答案扩大工具权限或修改窗口。

当前调查检索 scope 为 100 条，底层单次接口最多 200 条，实际仍受每轮 3 次、全案累计 6 次逻辑取证预算限制。每包记录原始窗口总量、导入量、可检索量、投影后有效证据、排序/截断规则和缺失阶段。先用正常时期样本，在真实 PostgreSQL/OpenSearch/MCP 上验证“历史告警 → 非空历史证据 → 原文与哈希可追溯”，验证重复导入幂等、跨案例拒绝及进程/命令行确实出现在允许的上下文中；此处不要求真实模型推理或攻击评分。

全量数据可做隔离的解析/连接审计；冻结 test 不用于调查策略调试。现阶段只承诺**窗口内、锚定实体的可观察阶段评测**。完整八天跨主机攻击链重建标记为本期能力限制，不把窗口级结果宣传为全链还原。

**6.4 冻结标签语义、映射和防泄漏边界**

系统日志标签按[官方说明](https://dedale.inria.fr/download.html)保留 `benign / malicious / malicious-related` 三类原值；系统标签的实际字段/编码须查验归档，不能套用网络流标签的 `0/1/2`。`malicious-related` 不直接归为正常，也不自动等同于直接恶意。保留原始事件身份，以作者文档和实测记录确定连接键，逐项记录匹配、未匹配、重复、冲突及排除计数；不能只凭“未连接到攻击标签”判定正常。

`dedale-label-policy.json` 固定从原始标签到案件攻击判定、项目六类标签及 ATT&CK 版本的映射依据。攻击事实明确但无法映射六类的案例保留为 `out_of_taxonomy`，可参加适用的攻击/正常及证据评测，不伪造第七类或归为正常；缺少可靠判定的记录标记 `unscorable` 并解释原因。所有逐字段的源实体、阶段、技术及可观察性金标保存原始定位、依据和复核记录，具体答案只在评分侧；人工补标与作者原标签分别留存，不表述为官方提供的结论。

Agent 输入仅含允许的原始证据与中性告警：不得出现答案标签、攻击脚本、场景说明、攻击阶段命名的标题/案例 ID/挂载路径，或发布方附加的答案性 ATT&CK 标注。原始日志中真实发生的命令行可以作为证据，标签侧信息不能混入日志。数据准备程序产出互相分离的 `agent/` 和 `scoring/`；泄漏审计同时检查字段、自由文本和可访问文件，不能仅依赖字段黑名单。

接入使用案件独立索引和精确数据集过滤，同一 campaign 的其他窗口也不可检索到。Task 12 验证 Agent 服务的运行目录/挂载不可读评分目录；Task 13 新建的模型适配进程须复验同一隔离，传入一个 `agent_dir` 参数本身不构成文件系统隔离。

**6.5 按可观察阶段选择案例，冻结实际规模与适用范围**

生成正式清单前，登记窗口宽度、主机锚点、去重键、排序、截断、正常窗口抽样及排除规则。按已核实的攻击阶段与输入可观察性生成候选包，保留 `campaign_id`、阶段关联、共享主机/证据和时间关系；为每个有可靠标签且在所选系统日志中可观察的阶段至少保留一个合格窗口，无法覆盖的阶段列明原因。正常窗口按固定种子 42 和冻结抽样规则选取，覆盖攻击期正常背景与后续正常日期/主机；抽样规模与分层规则在模型运行前冻结。

至少包含一个可判定攻击包和一个可靠正常包只是最低可运行条件；验收还要求候选全集的入选/排除记录闭合、阶段覆盖矩阵完整、无无法解释的丢弃案例。不得仅凭这两个包或接口跑通宣称数据充分。记录主测试实际数量 `N_D`、正常/攻击/不可评分数量及原因；本期消融使用同一批合格 test 包，`M_D=N_D`，不预设 32 包，不以重复切片补数量。

同一 campaign 的多个窗口不是多个独立攻击。保存去重与重叠检查结果；确需保留不同主机的关联窗口时公开其共享证据和关联组，不将其作为独立样本计算显著性或宣称跨攻击泛化。DEDALE 的外部测试结果与 AIT 两个历史测试场景分别报告。

**6.6 执行数据审计、异路径重建并冻结交接产物**

测试必须覆盖：原始日期/UTC/端点、规范化主机与证据字段、历史告警查询、稳定 ID 和重复导入、三类标签连接及冲突、不可映射攻击处理、跨案例隔离、标题/文件路径等泄漏、全候选入选/排除闭合及确定性重建。使用正常时期样例验证接入，用独立手工可核对样例验证标签连接；test 仅由隔离数据准备/评分流程做无模型的数据审计。

以下测试与审计入口须在本步实现后运行；不得把命令存在写成已执行。`scripts/dedale_task12_audit.py` 约定接受 `--sources`、`--selection`、`--data-root`、`--cases-root` 四个必需参数，从指定数据根解析来源 manifest 中的相对归档路径，验证冻结归档与案例全部哈希、标签侧文件/可观察性和阶段覆盖，并在任一必验项失败时非零退出。另提供构建器 CLI `python -m evals.datasets.dedale.build_manifests`，支持 `--sources --splits --label-policy --data-root --output-root`；其完整实参及选择清单输出位置记录在 `docs/datasets/dedale.md`。

```powershell
uv run --project services/backend pytest evals/tests/test_dedale_parse.py evals/tests/test_dedale_ground_truth.py evals/tests/test_dedale_manifests.py -q -rs
uv run --project services/backend python -B scripts/dedale_task12_audit.py --sources data/manifests/dedale-sources.json --selection data/manifests/dedale-selection.json --data-root data/dedale/raw --cases-root data/dedale/cases
git diff --check
git status --porcelain=v1 -uall
```

Expected：数据审计、关键真实接入用例实际通过且关键项无跳过；在另一绝对路径按固定来源和规则重建全部入选包，Agent、评分金标及侧文件的内容哈希逐项相同。交接产物包括来源/拆分/选择/标签规则四份 manifest、实际 `N_D=M_D`、原始三类计数、阶段/主机/日期覆盖、逐字段评分适用掩码、未知与排除台账、获取与重建命令、许可引用、资源实测和隔离证据。不得等 Task 13 出分后补选案例或修改适用掩码。

六项证据及验收记录均已提交后，在干净工作树把集成分支快进到本地 `main`，核对 Task 10/11 提交仍为祖先；若不能快进，先解决分支变化并在新最终提交上重跑受影响的验收。

```powershell
git switch main
git merge --ff-only codex/task12-readiness
git merge-base --is-ancestor 3d8880f main
git merge-base --is-ancestor f21dda1 main
git status --porcelain=v1 -uall
```

Task 12 验收记录逐项列出六步的命令、实际结果、提交 SHA、数据 manifest 哈希、审查人和未解决问题；报告仅保存可复核的元数据、哈希与计数，不复制冻结测试答案、密钥或敏感原始日志。在最终接受提交上复跑受改动影响的后端、浏览器及两组数据审计，验收记录指向同一个最终版本。只有六步全部通过、两组数据均冻结、接受版本已纳入本地 `main` 且验收工作树干净，才标记 Task 12 完成并允许开始 Task 13。近期数据缺失、关键测试失败或跳过、AIT 无法异路径重建、存在未归档修改时保持未验收；不得用 Task 13 将来会完成的 B0～B3 输出、消融分数或正式模型结果补作本任务证据。若 Task 13 开发必须改动已冻结的数据或标签，需记录新版本并重新执行 Task 12 相应数据关口。

**完成标志：** `docs/acceptance/task12-readiness.md` 对六个关口均有本轮实测证据；本地 `main` 包含 Task 10、Task 11、Task 6/8 增强与 Task 12 修复；AIT 和 DEDALE 的冻结清单、来源与标签隔离可从不同路径重建。Task 13 在此之后实现基线与消融，并在首次正式测试前冻结最终模型、提示词、工具配置、知识库与评分规则。

**推进判断（2026-10-14）：** 可以按 Step 1 → Step 2 → Step 3/4 → Step 5 → Step 6 开展 Task 12，DEDALE 来源/许可/日期和磁盘核查可并行准备。当前没有 Task 12 全部通过的证据，不能启动 Task 13 正式实现或正式测试。最近的执行重点为保护未提交改动、整合 Task 10/11/6/8、补齐真实 UI 闭环与服务验收，再完成 AIT 可移植性和 DEDALE 准入；无需为了开始这些工作新增任务编号或补做自行攻击采集。

### Task 13: 基线、消融和评分系统

**当前状态：** 基线、消融与正式实验待完成；须先取得 Task 12 的六项验收证据，再用开发/内部验证样例校验评测，最后运行冻结测试。

**Files:**
- Create: `evals/runners/baselines.py`
- Create: `evals/runners/ablations.py`
- Create: `evals/adapters/evidencesoc.py`，实现真实模型与系统调用，逐项执行基线/消融的能力开关。
- Create: `evals/run_formal.ps1`、`docs/evaluations/protocol.md`，固定两组数据各自的 plan → execute → score 命令及评分协议。
- Create: `evals/metrics/classification.py`
- Create: `evals/metrics/evidence.py`
- Create: `evals/metrics/attack_chain.py`
- Create: `evals/run_manifest.schema.json`
- Create: `evals/tests/test_metrics.py`
- Modify: `evals/runners/manifest.py`、`evals/runners/score.py`、`evals/README.md` 及相应测试，接入 DEDALE 的适用掩码、标签映射、阶段实例和隔离要求；已有工作区草稿先核对后补齐，不重复创建。

**Interfaces:**
- Consumes: Task 12 验收的统一系统版本、Task 11 的冻结 AIT 测试包（原目标 48 个，当前 `N=22`）及消融子集（原目标 24 个，当前 `M=22`）。
- Consumes: Task 12 独立冻结的 DEDALE、逐字段适用掩码及其评分金标；两组测试答案仍只供隔离的评分流程读取。
- Produces: B0～B3 和四项消融的真实系统输出、JSON/CSV 实验结果和前端图表数据。

- [ ] **Step 1: 实现四个主基线**

`B0=普通LLM`、`B1=普通RAG`、`B2=单Agent+工具`、`B3=六角色EvidenceSOC`。四者使用相同模型、温度 0 和相同输入案例。

B2 与 B3 使用相同三个工具、查询范围、种子上下文、每轮最多 3 次且调查取证累计最多 6 次的逻辑调用预算，以及相同物理重试上限；都允许在预算内自主选择工具。比较单 Agent 与六角色效果时，不为 B3 额外增加取证额度。各组如有审批后处置验证查询，单独统计其成本。

实现真实适配器 `evals.adapters.evidencesoc:run_case`，输入仅含冻结的 run spec 与该案 `agent/` 目录。逐项验证模型调用、RAG 开关、工具权限和角色流程确实生效；声明 capability 或用 fixture 生成输出不算实现基线。B0/B1 使用与 B2/B3 相同的初始可见日志、字段投影及上下文上限，工具组新增查询产生的证据与成本另记。各组事件引用均需来自可信导入/工具台账，不相信模型自报的 Evidence ID。每案使用隔离索引；模型进程不能读取金标、场景文档、其他窗口或包含答案的文件名/目录，评分另在可读金标的进程运行。

- [ ] **Step 2: 实现四项消融**

在 AIT 的 22 个冻结消融包及 DEDALE 的 `M_D=N_D` 个冻结包上，分别移除证据工具、移除 RAG、混合检索改为纯向量、移除效果验证节点。保留工具的消融组沿用 B3 的取证范围和预算，不因关闭某项能力而增加其他工具额度；记录各组实际可用工具与调用量。

静态日志不能证明封禁或隔离产生真实安全效果。“移除效果验证节点”使用预先登记的模拟成功、失败、无变化等处置后证据，比较误报成功率、失败识别率和新增调用成本；各组审批策略一致，处置后模拟证据与攻击诊断输入隔离。诊断指标取处置前输出，模拟验证单列报告，不把模拟执行成功当成实际阻断效果。

- [ ] **Step 3: 实现指标**

攻击类型使用多标签 Macro F1；来源使用可观察源 IP、入口主机、入口服务准确率；同时计算适用的攻击阶段覆盖 F1、顺序准确率、Evidence Precision@K、引用有效率、ATT&CK F1、Unsupported Claim Rate、延迟、Token 和费用。AIT 保留固定六类的主口径，并公开每类支持数与零支持类处理；DEDALE 依据 Task 12 冻结的映射/适用掩码定义可映射类别指标，另报告全部六类预测及其误报，不能看到结果后删去难类。`out_of_taxonomy` 不进入错误的六类金标分母，其攻击判定与证据指标仍按适用性统计。

在 `docs/evaluations/protocol.md` 冻结 K 值、空预测/零分母规则、金标来源、人工支持性复核规则及分母。无可靠源实体、ATT&CK 或阶段金标的字段记 `N/A`，公开适用覆盖率和缺失原因，不能填零或从场景描述推测不可观察答案。阶段按可区分实例与可比较先后关系评分，处理重复阶段和部分顺序；当前只按唯一阶段名排列的评分器须补齐适用逻辑。DEDALE 完整八天全链指标本期记为不适用，窗口可观察阶段指标单列。

区分三种情况：金标本身不可观察、系统主动 `unknown`/转人工、执行失败/缺失。金标适用掩码在 Task 12 冻结；固定清单内有可评分金标的案例，不能因弃答、失败或缺失而移出主结果。准确率中视为未答对，多标签召回保留漏检；同时报告作答覆盖率、仅已作答的条件准确率、正常包误报及成功/失败/缺失数量，避免单独以条件准确率代表整体效果。

AIT 与 DEDALE 使用相同冻结系统版本，分别报告包数、事件时间、攻击技术、适用指标和失败情况；AIT 另列 Shaw/Wilson，DEDALE 另列 campaign/阶段、主机及窗口关联。DEDALE 的运行次数和费用独立列出，不混入 AIT 的 176 次，也不将分数合并成单一总体结果。其一个 campaign 的多个窗口不能支持跨攻击泛化或包级独立显著性结论。

记录取证逻辑调用、工具物理尝试、模型调用及重试、审批后验证查询、耗时、Token、费用和规则降级比例；实验次数与模型/工具调用次数分开统计。引用有效率仅表示引用存在且归属正确，不能代替证据支持性；Unsupported Claim Rate 由独立金标和人工复核计算，保存复核记录。无法取得的用量/费用及未完成的支持性复核记为缺失，不填零冒充达标。

- [ ] **Step 4: 固定实验清单**

AIT 当前主实验 `22 × 4 = 88` 次、消融 `22 × 4 = 88` 次，合计 **176 次**；48/24 包及 288 次只保留为历史目标，不再作为当前待补数量。DEDALE 按 Task 12 冻结数量计划 `4N_D + 4M_D = 8N_D` 次，并分别列出正常/攻击/不可评分情况。以上均为唯一“案例 × 组别”的计划次数，模拟验证条件、失败尝试和重跑另计，不重复切片扩充。

正式运行前固定仅允许的重跑条件（如基础设施中断、请求传输失败）、次数上限与唯一主结果规则；低分或已完成的 `unknown` 不构成重跑理由。沿用运行器连续 attempt 编号，保留全部尝试并以最后一次获准尝试确定状态，不从历史中挑最高分或成功样本；缺失计划行继续显示 missing。全部失败与重跑的费用计入资源总量。

正式测试前冻结拆分及事件包 manifest、提示词、工具策略与预算、配置、知识库版本和评分规则；每次保存数据版本、模型完整 ID、温度、提示词版本、随机种子 42、锁文件哈希和 Git commit。冻结后不依据最终测试结果修改系统，误差分析用于如实报告与后续工作。

该冻结要求同时适用于 AIT 与 DEDALE；两组最终测试原始案例及答案均不得进入调优或知识库，DEDALE 的允许校准范围仅限 Task 12 指定的前两周正常数据。公开数据可能已被基础模型接触，记录模型信息和这一无法排除的污染风险，不宣称数据绝对未见。

Task 12 已冻结数据来源、拆分、标签和案例清单；本步骤在基线、消融与评分实现经过开发/验证集核验之后，再冻结最终模型、提示词、工具策略、知识库、评分规则和运行清单。Task 13 若修改共用调查运行时、证据边界或审批流程，正式冻结前必须重跑受影响的 Task 12 集成与安全边界用例；若修改已冻结数据或标签，先重新执行 Task 12 相应数据关口。Task 12 的准入记录不能替代本步骤的正式实验版本冻结。

- [ ] **Step 5: 验证指标测试**

使用手工可计算的小样例验证 Precision、Recall、F1、引用率和顺序准确率；不得使用 LLM 作为最终裁判。

补测正常包误报、不可映射攻击、金标不可观察、未知/失败保留分母、阶段重复、空证据、缺失用量及重跑主结果选择。开发/内部验证仅使用 AIT 对应拆分，DEDALE 的纯正常校准不充当攻击类验证；逐项核对实际能力开关、隔离边界、预算台账和评分输入，不能用合成预测代替真实适配器验收。

- [ ] **Step 6: 提交冻结实现，运行两组正式实验并归档**

先提交已通过开发/验证核验的实现和协议，取得真实 Git SHA，再生成运行清单并执行。`evals/run_formal.ps1 -Dataset ait|dedale` 为本步实现的统一重放入口：从各自冻结配置读取完整模型 ID、版本、输入路径与预算，依次调用现有 `evals.runners.cli plan/execute/score`；真实执行使用 `evals.adapters.evidencesoc:run_case` 与显式 `--allow-final-test`，评分阶段才可读金标。入口检查 Task 12 记录及冻结哈希，任何缺项失败退出；保存展开后的实际命令，不以占位模型 ID 运行。

```powershell
uv run --project services/backend pytest evals/tests -v
git add evals docs/evaluations/protocol.md
git commit -m "eval: add reproducible baselines and metrics"
pwsh -File evals/run_formal.ps1 -Dataset ait
pwsh -File evals/run_formal.ps1 -Dataset dedale
```

Expected：两组清单的案例/组别全部有可解释结果或明确失败记录；每次真实模型输出、调用台账、证据注册表、人工复核、失败重跑及成本均可追溯。先生成不可变原始结果及 SHA256，再独立评分并提交不含秘密/测试答案的汇总、误差分析和重放说明；缺少真实运行、所需复核或把 fixture 结果冒充模型结果，均不验收。

**完成标志：** 两组主实验与消融可由统一入口重放，协议、数据、系统、输出与评分版本闭合。Macro F1 ≥ 0.85、引用有效率 ≥ 95%、ATT&CK F1 ≥ 0.80、Unsupported Claim Rate ≤ 5% 为效果目标，按数据集和适用分母分别判定；`N/A` 或覆盖不足不能算达标。工程验收可接受如实记录的未达效果目标，但须公开差距与失败分析，不用最终测试反复调参直至通过。

### Task 14: 安全、故障和性能验收

**当前状态：** 已有安全边界、依赖恢复和性能测试；复用现有测试并补充有限取证的预算、循环内部恢复与完整 E2E 验收。

**实验版本约束：** 若本任务发现的问题需修改模型、提示词、取证行为、字段投影、审批或证据边界，记录影响范围并重新冻结系统，在新版本上重跑受影响的正式实验及安全回归；不得把旧版本实验分数直接贴给修复后的发布版。仅文档或无行为影响的修改，也须记录与实验提交的关系。

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

补充未知工具、非法参数、越界时间范围、跨案件/场景查询、重复查询、空结果与预算耗尽；确认代码约束始终有效，重复结果复用且不会产生无限规划循环，每轮最多 3 次、调查累计最多 6 次取证逻辑调用。

- [ ] **Step 2: 测试依赖故障**

分别停止 PostgreSQL、OpenSearch、MCP 和模型接口。Expected：状态进入明确失败或降级，不产生伪造成功结论。

补测模型超时和结构化输出重试耗尽，规则降级仍使用同一台账与剩余额度；工具失败/空结果消耗逻辑预算，物理尝试不超过上限，降级与停止原因均可审计。

- [ ] **Step 3: 测试审批边界**

覆盖未审批执行、重复审批、审批超时、拒绝、并发调查串线。Expected：全部被正确阻止或隔离。

- [ ] **Step 4: 测试 SSE 与恢复**

断开浏览器、刷新页面和重启后端。Expected：使用 Last-Event-ID 和检查点恢复，不重复模拟处置。

在 `collect` 内部的调用预占后、结果持久化前及节点返回前分别中断后端。Expected：取证预算不重置，已完成查询复用结果，未确认调用在原物理重试额度内恢复或明确转人工；审批后验证查询单独审计，REST/SSE 和审批行为保持兼容。

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

数据集说明链接 `docs/datasets/dedale.md`：列出 AIT/DEDALE 来源、DOI/版本、许可引用、真实事件/采集时间、下载与重建步骤、冻结哈希、作者标签与项目派生标签的区别。区分原始公开数据和本项目的案例选择/适配/评分工作，避免将外部数据采集算作项目独立成果。

- [ ] **Step 2: 完成不超过 30 页的技术文档**

章节固定为项目概述、需求分析、架构设计、AI 技术方案、核心功能、数据与评测、测试部署、创新点、社会与商业价值、局限和展望。

实验部分分别呈现 AIT 两个测试场景的 22 包/176 次计划与 DEDALE 实际包数/运行数，公开日期、阶段覆盖、案例关联、缺失/失败/弃答、标签不可观察性及校准范围。说明 DEDALE 为第三方实验环境采集、仅一个 APT campaign，本期系统评价窗口内可观察能力；不宣称真实企业入侵、完整八天链路还原或真实处置效果。报告效果目标实际达标情况，保留未达标项目。

- [ ] **Step 3: 准备演示视频脚本**

视频 5～8 分钟、MP4、1080p：40 秒痛点，50 秒架构，3 分钟完整闭环，1 分钟证据与安全，1 分钟实验，30 秒价值与展望。

- [ ] **Step 4: 新环境安装验证**

在干净环境依据 README 执行安装、Compose 启动、迁移、样例导入、前后端启动和 E2E。Expected：无需阅读源代码即可完成演示。

- [ ] **Step 5: 秘密和大型文件检查**

确认仓库不存在 `.env`、API Key、Cookie、账号密码、AIT/DEDALE 原始大文件、PCAP、虚拟机镜像或混入 Agent 路径的评分答案。公开元数据、哈希、下载来源、生成代码和脱敏汇总，评分金标按隔离与许可要求单独管理。

- [ ] **Step 6: 最终提交与版本标签**

```powershell
git add README.md docs
git commit -m "docs: add competition delivery materials"
git tag -a v1.0.0-demo -m "EvidenceSOC competition demo"
```

**完成标志：** 仓库、PDF、视频和在线演示指向同一 Git 版本；视频中展示的功能均真实存在。

---

## 6. 前期两周纵向切片日程（历史安排）

本节保留初期安排用于理解已有实现，不作为新的两周待办。Task 1～10 的主要实现已存在，按实际代码与验收证据补缺；下面的 Day 10 演示链路仍用于收尾回归，不能把历史目标当成已通过的验收。

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

## 7. 剩余 5～8 周收尾里程碑

估算基准为一名熟悉项目的开发者每天有效工作 6 小时、每周 5 天；从当时实现进度计算，不重复前期脚手架和六角色基础实现。有限自主取证及联调、测试增加约 4～7 个工作日，已计入原排期。DEDALE 现已选定，仍须按约 38.02 GB 必需压缩归档的实际下载、解压空间、解析吞吐、索引占用、标签连接率与合格案例数重估 Task 12/13；不能把尚未做过的适配视为零工作量。5～8 周为原估算，后续周次以 Task 12 通过和正式实验前冻结条件为先，不为守住周次跳过关口。

| 剩余周次 | 目标 | 退出条件 |
|---|---|---|
| 第 1 周 | AIT 解析、金标隔离与小规模评测 | 5/1/2 场景拆分确定；开发/内部验证包可重建；评分小样例正确 |
| 第 2～3 周（DEDALE 试验后重估） | Task 12 集成与数据准入，通过后开始 Task 13 基线/消融实现 | 统一提交版本与历史验收可复核；AIT 异路径重建、DEDALE 前两周正常校准/后两周测试隔离及金标审计通过；六项 Task 12 关口全部签署，随后才开始正式评测实现与 AIT 开发/验证调优 |
| 第 4 周（以关口通过为前提） | 正式运行与误差分析 | Task 13 在最终系统和评分规则冻结后运行；AIT `N=M=22` 为 176 次，DEDALE `N_D=M_D` 为 `8N_D` 次；分开报告结果、失败重跑与费用 |
| 第 5 周 | 安全、故障、性能和交付联调 | 复用并补充现有测试；完整 E2E 连续三次成功；README、技术文档及视频形成交付版 |
| 第 6～8 周（按需缓冲） | 实验故障修复、干净环境复现和材料定稿 | 失败与重跑有记录；代码、PDF、视频版本一致；仅修复交付阻断问题 |

依赖顺序为“Task 11 AIT 基础数据 → Task 12 统一版本及两组数据准入验收 → Task 13 基线/消融实现与开发集、验证集调优 → 最终系统和评分规则冻结 → 正式实验 → Task 14 安全总验收与 Task 15 比赛材料”。材料整理可以并行，但最终实验图表与结论须以冻结运行结果为准；最终测试不用于继续调优。经验库可选扩展不占本期排期。

---

## 8. 最终验收清单

- [ ] GitHub 或 Gitee 仓库为 Public，完整保留真实提交历史。
- [ ] README 包含项目介绍、架构、安装、测试、团队与安全说明。
- [ ] `.env.example` 完整，但仓库不存在真实秘密。
- [ ] `docker compose up -d` 能启动 PostgreSQL 和 OpenSearch。
- [ ] fixture 模式不依赖云密钥即可演示。
- [ ] 一条告警能走完六角色、审批、模拟处置和验证。
- [ ] 取证能有限自主选择白名单工具和补查，每轮最多 3 次、调查累计最多 6 次逻辑调用（含种子）；失败、空结果、重复查询与物理重试符合第 4.3 节规则。
- [ ] 取证逐调用台账可恢复；回退、规则降级和重启不重置额度，停止原因与降级信息可审计。
- [ ] 取证增强与现有 REST、SSE 和审批兼容，非法工具、越界及跨案件/场景查询被阻止，审批后验证查询单独统计。
- [ ] 每个事实结论可追溯到 Evidence ID。
- [ ] 攻击来源表述为观察到的入口/源实体，不夸大为现实身份归因。
- [ ] 攻击类型支持多标签和攻击阶段顺序。
- [ ] AIT 测试标签与 Agent 输入完全隔离。
- [ ] AIT 使用 5 个调优、`wardbeck` 内部验证、`shaw/wilson` 冻结测试场景；开发与验证合计 75%、测试 25%，系统配置与评分规则在正式测试前冻结。
- [ ] Task 12 六项前置关口均有同一集成版本的实测证据；Task 10/11 与 Task 6/8 已纳入本地 `main`，AIT 可异路径重建，关键真实服务与浏览器用例无跳过。
- [ ] DEDALE 官方版本、许可、归档校验、事件日期及近期口径已核验；前两周仅正常背景校准，后两周冻结测试，单一 campaign 不拆入调优；Agent 与评分文件/进程及各案例索引隔离。
- [ ] DEDALE 历史时间、主机与进程证据真实接入，原始三类标签、六类映射、不可评分项、阶段覆盖、实际数量及案例关联均可追溯，全部入选案例可以异路径重建。
- [ ] AIT 176 次与 DEDALE `4N_D + 4M_D` 次正式实验分别具备数据、模型、提示词、工具策略、知识库、依赖和 Git 版本记录；不重复凑数，固定适用分母与重跑规则，公开失败、缺失、弃答及全部尝试成本。
- [ ] 两组结果分别报告；无法观察的指标为 `N/A` 并公开覆盖率，完整八天攻击链及真实阻断效果不在本期结论范围内。
- [ ] B2/B3 与相关消融的取证范围、逻辑预算和物理重试上限一致；效果、分场景结果、实际调用、耗时、用量和降级比例可复核。
- [ ] 技术 PDF 不超过 30 页。
- [ ] 演示视频为 5～8 分钟、MP4、1080p。
- [ ] 在线演示若启用，只使用预置只读数据，不开放真实处置能力。

## 9. 明确延后内容

**完整交付后可选：人工整理的长期经验库。** 仅在本期代码、安全验收、正式实验及比赛材料全部完成且时间允许时添加，预计另需 4～7 个工作日。复用现有 RAG 的导入与检索链路，经验条目由人工整理审核、保留来源及版本；不读取冻结测试答案，也不允许模型自行改写代码、提示词或已审核知识。该扩展不属于本期 MVP 验收条件，不计入 AIT/DEDALE 本轮冻结实验；添加后使用独立的有/无经验库对照评测，避免与本期冻结结果混用。

**本期不加入：** 全流程自由循环、任意工具调用、自动长期记忆写入与自主改写、模型权重训练；本期保留现有知识 RAG 与调查检查点，检查点用于恢复当前调查，不等同于自主学习。

以下内容不进入 v1.0.0-demo：Wazuh 实时接入、Suricata 独立部署、Nmap/OpenVAS 主动扫描、TheHive 双向同步、图数据库、多模态输入、真实防火墙配置、真实账号禁用和公网自动化测试。只有在全部验收门槛通过并完成单独威胁建模后，才能作为后续里程碑加入。
