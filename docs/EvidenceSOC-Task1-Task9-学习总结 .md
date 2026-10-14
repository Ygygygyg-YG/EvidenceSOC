# EvidenceSOC：Task 1–Task 9 结构化学习总结

> 读者：已经完成 Task 1–9 实操、需要理解代码逻辑与工程价值的软件工程初学者。  
> 初稿日期：2026-09-22；补充核对日期：2026-09-27。  
> 内容依据：`docs/EvidenceSOC-project-preparation.md`、`docs/environment-verification.md`，以及当前仓库的配置、实现、测试和 Git 历史。  
> 本文是学习复盘；安装、初始化、迁移和提交命令用于解释原计划中的步骤，按历史示例保留。本次只更新学习文档，不执行 Git 暂存或提交。

## 阅读说明：如何理解这九个任务

EvidenceSOC 是一个强调“安全结论必须有证据”的智能安全运营中心。Task 1–5 依次建立环境、应用骨架、存储服务、数据契约和日志证据能力；Task 6–9 再把这些基础组织为受限工具、可引用知识、六角色调查，以及可由前端调用的 API 和实时事件流。学习时应沿着“数据从哪里来 → 如何形成证据 → 如何支持判断 → 如何经过审批 → 如何保存与展示结果”理解每一层。

本次范围是 Task 1–9。Task 10 的运营界面、Task 11–13 的数据集与完整实验、Task 14–15 的整体验收与比赛材料属于后续范围；已有结果读取接口不表示完整评测系统已经交付。

### 九个任务的递进关系

| 层次 | 对应任务 | 输入 | 输出 | 为下一层解决的问题 |
|---|---|---|---|---|
| 环境 | Task 1：环境验收与仓库初始化 | 本机 Windows、WSL、Git、Node.js、Docker | 固定工具链、环境记录、Git 仓库、配置规范 | 别人能否在同样条件下复现项目 |
| 骨架 | Task 2：前后端脚手架和质量门禁 | Task 1 的工具链 | Next.js 前端、FastAPI 后端、健康接口、质量检查 | 代码放在哪里、如何启动、如何判断修改合格 |
| 基础设施 | Task 3：PostgreSQL、pgvector 和 OpenSearch | 容器环境与连接配置 | 可连接、可检查健康状态、可持久化的存储服务 | 数据存在哪里、日志如何检索 |
| 数据模型 | Task 4：领域模型、迁移和 OpenAPI 契约 | 数据库与应用骨架 | 领域对象、数据库表、版本化迁移、前端 API 类型 | 大家如何用一致的结构表达事件、证据和调查 |
| 业务能力：事实输入 | Task 5：日志接入和证据链 | JSON/JSONL 日志和前四层基础 | 可去重的事件、可重试的双存储写入、可追溯证据 | 一个安全结论能否回到真实事件及其查询上下文 |
| 业务能力：受限访问 | Task 6：只读 MCP 工具 | 可检索事件、证据服务、调用上下文 | 三个经过参数校验、权限检查和审计的只读工具 | Agent 如何安全地取得事实 |
| 业务能力：知识辅助 | Task 7：ATT&CK 混合检索与引用校验 | 有版本与哈希的知识语料、pgvector | 默认 8 条混合检索结果、知识块 ID、引用校验 | 如何用知识解释事实，同时防止编造引用 |
| 业务能力：流程闭环 | Task 8：六角色 LangGraph 工作流 | 领域状态、MCP 工具、RAG、PostgreSQL 检查点 | 可中断、可恢复、有人工审批的模拟调查流程 | 如何把多个判断组织成有限、可靠的业务过程 |
| 业务能力：对外服务 | Task 9：FastAPI、SSE 和审计 | 调查工作流与持久化状态 | REST API、可重放 SSE、幂等审批和脱敏审计 | 客户端如何启动、观察和恢复调查 |

```text
Task 1 环境可复现
  → Task 2 应用能启动、修改能检查
  → Task 3 数据能保存、能检索
  → Task 4 数据有统一结构、结构变化可管理
  → Task 5 日志能转为可核验的证据
  → Task 6 Agent 能通过受限工具获取证据
  → Task 7 判断能参考可追溯知识，引用可校验
  → Task 8 调查能经过六角色、审批、模拟与验证
  → Task 9 客户端能调用 API，断线后能继续观察流程
```

这里的“工程化”是把偶尔能运行的代码，组织为可以重复安装、测试、修改和交接的项目。每一层都向上一层交付明确的能力，避免上层业务同时承担环境、存储和数据格式的问题。Task 6 的 ATT&CK 查询会使用 Task 7 的知识存储；编号表示学习与交付顺序，不意味着两个任务在实际集成时完全没有相互依赖。

例如，一条 SQL 注入样例先在 Task 5 形成 `SE-<ULID>` 事件，Task 6 检索它并形成 `EV-<ULID>` 证据，Task 7 返回相关 ATT&CK 知识，Task 8 据此生成带证据引用的判断与模拟响应方案，Task 9 把状态变化发给客户端。事件、证据、知识块、调查和响应方案具有不同 ID，因为它们承担不同职责。

### TDD：先说明正确行为，再实现它

TDD（Test-Driven Development，测试驱动开发）的基本循环是：

1. **Red：先写一个表达预期行为的测试，再运行并观察合理失败。** 例如 `/health/live` 还不存在，测试要求它返回 200，因此失败。必须看懂失败原因；路径错误、权限不足、依赖没有安装并不能证明业务测试设计正确。
2. **Green：编写满足该测试的最小实现，再运行同一测试直到通过。** 不通过删除断言、放宽版本要求或跳过失败用例取得表面成功。
3. **Refactor：在测试继续通过的前提下整理结构。** 例如把解析、规范化、存储和证据生成拆成独立模块，改变组织方式而不改变约定行为。

| 任务 | Red 阶段的主要对象 | Green 阶段的主要证据 |
|---|---|---|
| Task 1 | 以工具检查和环境验收为主，不把安装工作硬称为单元测试 TDD | 工具版本、Docker 资源、Git 状态与真实记录符合要求 |
| Task 2 | 健康接口尚未实现 | 相同接口测试通过，六条质量检查命令退出码为 0 |
| Task 3 | 连接、扩展、版本或健康状态尚未满足契约 | 真正连接服务的集成测试通过，重启后仍能读取测试记录 |
| Task 4 | 模型尚不能拒绝非法数据，表或契约缺失 | 边界校验、表结构、迁移验证和 API 类型检查达到要求 |
| Task 5 | 解析、幂等性、内容哈希、双存储及证据追溯行为尚未实现 | 正常路径、异常路径、重试路径和完整证据链均满足断言 |
| Task 6 | 参数越界、无调用上下文、超时或非白名单操作尚未受控 | 工具边界、审计、取消、真实 stdio MCP 验收符合约定 |
| Task 7 | 检索无法融合排序，来源或引用未经校验 | 固定语料检索基线达标，无效引用标记为 `unsupported` |
| Task 8 | 状态转换、回退、审批中断、恢复尚未实现 | 有限闭环与异常分支通过，重启可恢复，模拟动作受白名单约束 |
| Task 9 | 告警重复、SSE 断线、重复审批与错误输出尚未受控 | API 契约、持久化事件重放、幂等、日志脱敏与性能验收通过 |

**“拒绝非法输入”的测试通过，也属于 Green。** 例如测试要求非法日期触发异常，系统确实抛出该异常，说明保护规则正确；不能把业务主动拒绝和测试失败混为一谈。

本文回顾原计划中的 Red / Green 顺序。当前实现已存在，再次运行测试通常是在做回归验证；仅凭当前源码和提交记录，不能补造过去每一次 Red 的终端记录。

### 版本、路径和命令的阅读规则

- 本文中的项目内路径以仓库根目录为基准，保留 `apps/web/`、`services/backend/`、`infra/`、`data/samples/`、`docs/` 等原路径规范。代码包名固定为 `evidencesoc`，项目名为 `EvidenceSOC`。
- 原文操作目录是 `D:\桌面\传智杯`；本次实际工作区是 `D:\传智杯`。历史命令保留原路径，需要在当前工作区复现时明确切换到实际根目录。
- 未特别说明时，命令使用 **PowerShell**，从仓库根目录运行。`uv run --project services/backend` 选择 Python 项目，不等于把所有工具的当前目录都改成后端目录；Alembic 的配置定位在 Task 4 单独解释。
- “原文要求”“当前实现”“完成验证标准”分别表示计划、源码事实和验收条件。源码存在、历史提交存在、当前测试通过是不同层面的证据。
- 命令代码块保留原命令的工具、版本和参数；注释用于解释其作用。标为“节选”的代码不是完整源文件，标为“教学示例”的代码用于解释已有逻辑。

## 原文固定基线与全局约束

### 工具链和硬件基线

以下保留准备书中的精确版本；不是在推荐替换为其他版本。

| 工具或环境 | 原文版本或要求 | 含义 |
|---|---|---|
| Windows | `10.0.26200.9457` | 开发操作系统基线 |
| WSL | `2.7.3.0` | Windows 上运行 Linux 环境的基础 |
| Git | `2.55.0`；当前环境表记为 `2.55.0.windows.2` | 前者是要求，后者包含 Windows 发行后缀 |
| Node.js | `24.15.0` | 前端开发、构建工具的运行环境 |
| npm | `11.12.1` | 保留；项目统一使用 pnpm 管理前端依赖 |
| Corepack | `0.34.6` | 按项目指定版本管理包管理器 |
| pnpm | `11.19.0` | 前端固定包管理器 |
| 系统 Python | `3.13.6` | 保持不变，不作为项目解释器 |
| 项目 Python | `3.12.14` | 由 uv 管理 |
| uv | `0.12.16` | 原环境未安装，Task 1 安装并验证 |
| Docker Engine | `29.7.2` | 运行基础设施容器 |
| Docker Compose | `5.5.0` | 根据 `compose.yaml` 管理多个服务 |
| VS Code | `1.137.0` | 原文保留的开发编辑器版本 |
| 建议硬件 | `8` 核 CPU、`32 GB` 内存、`60 GB` 可用空间 | 原文建议配置 |
| 最低硬件 | `4` 核 CPU、`16 GB` 内存、`40 GB` 空间 | 原文最低配置 |
| OpenSearch 前置参数 | `vm.max_map_count >= 262144` | 不得只检查 Docker 客户端版本就跳过内核参数 |

### 前端固定版本

| 依赖 | 原文精确版本 | 作用 |
|---|---|---|
| `next` | `16.3.5` | 页面、路由与构建框架 |
| `react` / `react-dom` | `19.3.0` | UI 组件与浏览器渲染 |
| `typescript` | `7.0.2` | 静态类型检查 |
| `tailwindcss` | `4.3.3` | 样式工具 |
| `@tanstack/react-query` | `5.103.1` | 管理接口请求数据及其状态 |
| `@xyflow/react` | `12.11.6` | 后续攻击链关系图；原文亦称 React Flow |
| `echarts` | `6.1.0` | 统计图表 |
| `zod` | `4.6.5` | 运行时数据校验 |
| `lucide-react` | `1.47.0` | 图标组件 |
| `vitest` | `5.0.1` | 前端测试工具 |
| `@playwright/test` | `1.63.0` | 浏览器端到端测试工具 |
| `openapi-typescript` | `7.13.0` | 根据 OpenAPI 生成 TypeScript 类型 |

### 后端固定版本

| 依赖 | 原文精确版本 | 作用 |
|---|---|---|
| `fastapi[standard]` | `0.141.1` | API 框架及 standard 可选依赖组 |
| `pydantic` | `2.13.5` | 定义并校验数据模型 |
| `pydantic-settings` | `2.15.0` | 从环境变量等来源读取配置 |
| `langchain` | `1.4.1` | 后续模型与工具调用的组织层 |
| `langgraph` | `1.2.11` | 后续有状态调查工作流 |
| `langchain-openai` | `1.6.2` | 模型接口集成 |
| `langchain-postgres` | `0.0.18` | PostgreSQL 相关集成 |
| `langgraph-checkpoint-postgres` | `3.1.2` | 后续工作流检查点持久化 |
| `langchain-mcp-adapters` | `0.3.2` | MCP 工具适配 |
| `mcp` | `1.30.0` | MCP 协议工具支持 |
| `sqlalchemy` | `2.0.54` | 数据库操作与表映射 |
| `alembic` | `1.20.0` | 管理数据库结构迁移 |
| `psycopg[binary,pool]` | `3.3.5` | PostgreSQL 驱动、二进制包和连接池支持 |
| Python 包 `pgvector` | `0.5.0` | Python 侧向量类型集成；与数据库扩展版本不同 |
| `opensearch-py` | `3.2.0` | OpenSearch Python 客户端 |
| `sse-starlette` | `3.4.11` | 后续服务器事件流支持 |
| `httpx` | `0.28.1` | HTTP 客户端 |
| `structlog` | `26.1.0` | 结构化日志 |
| `pytest` / `pytest-asyncio` | `9.1.1` / `1.4.0` | Python 测试和异步测试支持 |
| `ruff` / `mypy` | `0.16.8` / `2.3.1` | 代码规则检查和静态类型检查 |

### 容器固定版本

| 服务 | 原文镜像或版本 | 在 Task 1–9 中的定位 |
|---|---|---|
| PostgreSQL + pgvector | `pgvector/pgvector:0.8.6-pg17-bookworm` | Task 3 启用；数据库主版本 `17`、vector 扩展 `0.8.6` |
| OpenSearch | `opensearchproject/opensearch:3.8.0` | Task 3 启用 |
| OpenSearch Dashboards | `opensearchproject/opensearch-dashboards:3.8.0` | 仅开发调试，不是 Task 3 的必需启动服务 |
| OWASP Juice Shop | `bkimminich/juice-shop:v20.2.0` | 原文后续隔离靶场预留，保留基线，不表示本阶段已经部署 |
| DVWA | 源码版本 `2.5`，本地构建后记录镜像摘要 | 原文后续隔离靶场预留 |

### 必须贯穿实现的约束

1. **依赖可复现。** 所有直接依赖固定精确版本；间接依赖提交 `pnpm-lock.yaml` 和 `uv.lock`，其中后端实际锁文件路径为 `services/backend/uv.lock`。精确版本描述单个直接依赖，锁文件进一步记录完整依赖树，两者不能互相替代。
2. **保留系统解释器。** 系统 Python `3.13.6` 不变，项目固定使用 uv 管理的 Python `3.12.14`。
3. **Strix 仅作架构参考。** 只参考工具注册、任务编排、权限边界和审计思想；不导入或调用 Strix CLI、内部工具或 Python 模块，依赖清单、运行命令和容器中不得出现 Strix。
4. **控制 MVP 范围。** 不引入 MySQL、Milvus、Neo4j、Redis；不执行真实封禁、账号禁用、主机隔离或公网扫描。Task 8–9 的处置必须先经过人工审批，并仅做安全模拟。
5. **工具能力受限。** Agent 只可调用三个自建只读 MCP 工具：`search_security_events`、`get_alert_context`、`lookup_attack_technique`；不提供任意 Shell、任意文件读取或任意 URL 请求能力。Task 5 的本地导入函数不等于已向 Agent 开放读取任意文件的工具。MCP（Model Context Protocol，模型上下文协议）规定模型应用与外部能力如何交换信息；它本身不保证只读。常见能力包括 Tools（工具）、Resources（资源）和 Prompts（提示模板）。本项目的只读边界由自己的工具白名单与实现保证，既不开放 `rm`、`mv`、`write`，也不开放 `ls`、`cat`、`grep` 等 Shell 命令。
6. **保留工具硬限制。** 事件工具默认 `limit=100`，必须 `limit <= 200`；告警上下文 `before_seconds=900`、`after_seconds=900`，单侧窗口 `<= 900` 秒；ATT&CK 查询默认 `limit=10`、返回 `<= 10` 条；每次调用超时 `10` 秒、最多重试两次。这些是 Task 6 的 MCP 工具边界，不能误当作 Task 5 日志导入服务的自动重试策略。
7. **评测答案与调查输入分离。** 正式评测时 Agent 只能读取原始日志；`labels/`、`attacks.log` 和攻击者真值只能由评分程序读取。`dataset_labels` 只允许评分程序写入，生产调查结果默认空列表。
8. **结论必须引用证据。** 所有安全结论必须引用有效 Evidence ID；证据不足时返回 `unknown`，不得编造来源或攻击类型。来源表述指“观察到的源 IP／入口实体”，不能直接夸大为现实身份归因。
9. **约束流程边界。** Task 8 的六角色是可观察的业务节点，由确定性规则与 LLM 节点混合实现，不启动六个无限自主循环进程；证据不足只允许回到收集节点一次，第二次仍不足进入人工复核。无云模型密钥时，固定样例与规则模式仍需可演示。
10. **保留真实工程记录。** 代码、测试和文档使用真实 Git 提交记录；每个任务完成后先执行对应验证再提交。原文给定的提交信息是预期示例，真实历史以 `git log` 为准。
11. **限制开发服务暴露。** 容器端口仅绑定 `127.0.0.1`；OpenSearch 使用单节点、`1 GB` JVM 堆和 HTTP 健康检查，禁用安全插件仅是开发环境选择。

### 原文与当前仓库的差异处理

| 项目 | 原文要求 | 当前文件事实 | 阅读时如何处理 |
|---|---|---|---|
| 工作区 | `D:\桌面\传智杯` | 当前为 `D:\传智杯` | 保留原路径，运行前确认实际根目录 |
| Python 向量客户端 | `pgvector==0.5.0` | `pyproject.toml` 为 `pgvector==0.3.6` | 不改写原版本；二者差异不改变数据库扩展要求 `0.8.6` |
| TypeScript | `typescript@7.0.2` | `typescript` 为 `npm:@typescript/typescript6@6.0.2`；`@typescript/native` 为 `npm:typescript@7.0.2` | 保留原安装命令；解释包别名，实际编译器以安装解析和运行版本为准 |
| Python 版本声明 | 项目固定 `3.12.14` | `.python-version` 为 `3.12.14`；`requires-python` 为 `>=3.12.14` | 固定解释器由前者体现；后者单独看只是下限 |
| 构建依赖 | 所有直接依赖固定精确版本 | 构建系统 `uv_build>=0.12.16,<0.13.0` 是范围 | 记录现状，不能声称所有声明都已经精确锁定 |
| 前端生成契约 | 应与当前后端 DTO（数据传输对象）一致 | 当前 `generated.ts` 已含 Task 5 追溯字段和 Task 9 的 REST 路径、输入输出模型 | 字段存在是源码事实；后续修改仍应重新生成类型并检查，不能只凭编译通过就断言完全同步 |
| Task 2 检查数量 | 完成标志写“五项” | 原文实际列出六条质量检查命令 | 以六条命令全部成功为准 |

当前前端还固定了 `@tailwindcss/postcss@4.3.3`（CSS 样式处理）、`@types/node@20.19.43`（Node.js 的 TypeScript 类型定义）、`@types/react@19.3.0`、`@types/react-dom@19.3.0`、`eslint@9.39.5`、`eslint-config-next@16.3.5`。这些是当前清单补充，不是替换准备书中的版本。`devDependencies` 表示主要用于开发、测试和构建的依赖分类；包是否进入浏览器产物还取决于导入和构建过程，不能仅凭这个分类判断。后端还新增精确依赖 `fastembed==0.8.1`，用于 Task 7 的本地嵌入模型。

DTO 是在接口或不同层之间传递数据的结构。数据库实体负责表映射，DTO 负责表达输入输出；本项目的 Pydantic DTO 还包含字段校验，所以“没有复杂业务流程”不等于“完全没有代码逻辑”。

---

## Task 1：环境验收与仓库初始化

### 1. 任务目标

Task 1 要建立一个可复现、可追踪的开发起点：确认 Windows、WSL、Docker、Git、Node.js 和包管理工具满足准备书要求；安装指定版本的 uv，由 uv 管理项目 Python；统一编辑格式与忽略规则；建立 Git 主分支，并将检查结果写入 `docs/environment-verification.md`。

本任务的输入是电脑已经安装的工具和 Docker 环境，输出是可查证的工具链记录、基础配置文件以及 Git 初始化提交。它还没有实现业务功能，也没有验证数据库、搜索引擎或 Agent 工作流。

准备书与环境记录采用的历史目录是 `D:\桌面\传智杯`，本次阅读的工作区是 `D:\传智杯`。下文保留原文命令中的历史路径，并明确给出当前目录写法；两者不能被静默视为同一个位置。2026-09-19 的环境记录是历史验收材料，不代表本次重新检查过当前电脑。

### 2. 设计初衷（为什么要做）

**固定工具链是为了解决“同一份代码在不同电脑上表现不同”的问题。** 应用框架、编译器、包管理器和 Python 解释器各自有版本。先记录基线，后续出现错误时才能判断问题来自代码变更、依赖差异还是运行环境差异。完整版本表见本文前面的全局版本基线，本任务重点理解如何检查和保存证据。

**保留系统 Python、单独管理项目 Python，是为了控制项目边界。** 系统 Python 3.13.6 可能被其他程序使用，本项目要求 Python 3.12.14，因此不应通过替换系统解释器来满足项目需要。uv 可以安装和管理项目所需解释器；系统终端执行 `python --version` 与项目环境使用的解释器不是同一个概念。

**Git 与配置文件共同建立协作规则。** Git 保存可追溯的变更历史；`.editorconfig` 约定编码、换行和缩进；`.gitignore` 避免提交依赖目录、缓存及真实环境变量；`.env.example` 提供可公开的变量模板。模板描述“需要配置哪些变量”，真实 `.env` 保存“本机具体填了什么”，二者职责不同。

**Docker 检查要区分客户端、服务端和资源条件。** 能执行 `docker --version` 只能证明命令行客户端存在；`docker info` 成功才说明能连接 Docker Server。OpenSearch 还需要足够的 Linux 内存映射上限，因此必须检查 `vm.max_map_count >= 262144`。准备书建议 8 核 CPU、32 GB 内存、60 GB 可用空间，最低为 4 核、16 GB 内存、40 GB 空间；这些是宿主机资源要求，不能拿 Docker 分配内存直接替代宿主机总内存判断。

本任务采用“先检查、再配置、再复核”的环境验收顺序。它与 TDD 都强调先确定标准，但这里没有先编写失败单元测试、再实现函数，因此不应称为完成了一轮单元测试 TDD。

### 3. 详细执行步骤

1. **确认所在目录并检查现有工具。** 在准备书对应的项目根目录执行版本命令，把实际输出与基线逐项比较。版本一致时保留现有安装，不因为要初始化项目就重新安装全部软件。若命令不存在，应先处理该工具的安装或 PATH 问题，再继续后续依赖步骤。
2. **安装 uv 0.12.16，再安装项目 Python 3.12.14。** 先确认 `uv --version`，再通过 `uv python list` 确认存在 `cpython-3.12.14`。系统 `python --version` 仍应保持 3.13.6。项目解释器固定还需在 Task 2 的项目文件中落实。
3. **启用 Corepack 并固定 pnpm 11.19.0。** Corepack 用于管理受支持的包管理器版本；pnpm 才是实际安装前端依赖的工具。执行激活命令后再次检查版本，不能只依赖“安装命令没有报错”。当前仓库根目录的 `package.json` 也记录了 `packageManager: pnpm@11.19.0`。
4. **验收 Docker Server 和 OpenSearch 前置条件。** 使用 `docker info` 确认可连接服务端，再进入 `docker-desktop` 的 Linux 环境读取 `vm.max_map_count`。本阶段检查前置条件，不等同于 Task 3 已经启动并验收 OpenSearch。
5. **建立基础配置并填写环境记录。** 创建 `.gitignore`、`.editorconfig`、`.env.example`，记录检查日期、实际工具版本、CPU、内存与 Docker 分配资源。原文要求 CPU 和内存信息；现有记录包含 Docker 的 24 个 CPU 和 7.609 GiB 内存，但没有明确给出宿主机 CPU 型号、物理核心情况或总内存，因此不能据此宣称宿主机硬件信息记录完整。
6. **初始化 Git 并提交这一阶段成果。** 新仓库使用 `git init -b main` 建立主分支，明确暂存四个任务文件，提交后检查状态。已经初始化的当前仓库不需要为了阅读总结而重做初始化或制造一条重复提交。提交消息应描述实际完成的工作，不能事后编造历史过程。

### 4. 关键代码/命令示例

#### 4.1 检查原有工具链

以下为准备书原始命令，逐行补充中文注释。第一行保留历史目录；只有在该目录真实存在且是待操作仓库时才使用。

```powershell
Set-Location "D:\桌面\传智杯" # 进入准备书使用的历史项目根目录。
git --version # 检查 Git 版本，准备书记录为 2.55.0.windows.2。
node --version # 检查 Node.js，目标版本为 24.15.0。
npm --version # 检查随工具链保留的 npm，基线为 11.12.1。
corepack --version # 检查 Corepack，基线为 0.34.6。
pnpm --version # 检查前端包管理器，目标版本为 11.19.0。
python --version # 检查系统 Python，要求保留 3.13.6。
docker --version # 检查 Docker 客户端版本，基线为 29.7.2。
docker compose version # 检查 Compose，目标版本为 5.5.0。
wsl --version # 检查 WSL，基线为 2.7.3.0。
```

在本次工作区阅读或复现时，目录切换应明确写为以下形式，然后再执行适用的检查步骤：

```powershell
Set-Location "D:\传智杯" # 本次实际工作区；与历史路径的差异在此明确记录。
```

准备书还列出 Windows 10.0.26200.9457 和 VS Code 1.137.0，但上述原始命令块没有直接检查操作系统与 VS Code 的命令；整理验收记录时仍应把其实际信息补齐，不应把“表格列出过”理解为“这一命令块已经验证过”。

#### 4.2 安装 uv、管理 Python 并固定 pnpm

这些是历史初始化时的安装与激活命令，本文仅说明用途，没有执行安装操作。

```powershell
winget install --id astral-sh.uv --version 0.12.16 -e # 精确匹配 uv 软件包 ID，并安装指定的 0.12.16。
uv --version # 复核当前终端可找到 uv，且版本为 0.12.16。
uv python install 3.12.14 # 由 uv 安装项目解释器，不替换系统 Python 3.13.6。
uv python list # 列出 uv 可识别的 Python，确认 cpython-3.12.14 存在。
corepack enable # 启用由 Corepack 提供的包管理器入口。
corepack prepare pnpm@11.19.0 --activate # 准备并激活项目要求的 pnpm 精确版本。
pnpm --version # 再次确认当前生效的 pnpm 输出 11.19.0。
```

`-e` 是 winget 的精确匹配参数；`@11.19.0` 是包名与版本的组合。版本检查不通过时，应先检查新终端中的 PATH 和工具解析位置，不能直接把不一致的结果填写为通过。

#### 4.3 检查 Docker 并理解基础配置

```powershell
docker info # 请求 Docker Server 信息，确认服务可连接并查看资源配置。
wsl -d docker-desktop sysctl vm.max_map_count # 读取 Docker 所用 Linux 环境的内存映射上限，要求至少 262144。
```

下面是当前 `.editorconfig` 的主要规则，注释说明其用途；配置项与实际文件一致。

```ini
# 当前文件为 EditorConfig 配置链的根，不再向父目录继续查找。
root = true
# 对所有文件应用默认规则。
[*]
# 统一使用 UTF-8，保证中文内容可被一致读取。
charset = utf-8
# 保存时使用 LF 换行，减少跨平台差异。
end_of_line = lf
# 文件末尾保留换行。
insert_final_newline = true
# 默认去掉行尾多余空白。
trim_trailing_whitespace = true
# 使用空格缩进。
indent_style = space
# 默认每级缩进四个空格，适用于 Python 等文件。
indent_size = 4
# 对前端、JSON、YAML、样式与 Markdown 文件覆盖缩进宽度。
[*.{js,jsx,ts,tsx,json,yml,yaml,css,scss,md}]
# .tsx 表示 TypeScript 与 JSX 组合的界面源码。
# .yaml/.yml 表示供程序读取的配置数据，不是直接执行的脚本。
# 上述文件使用两个空格缩进。
indent_size = 2
# Markdown 中行尾空格可能用于表达换行，因此单独设置。
[*.md]
# 保留 Markdown 行尾空白。
trim_trailing_whitespace = false
```

`.gitignore` 中与秘密管理最相关的规则如下。完整文件还忽略 `node_modules/`、`.next/`、虚拟环境、缓存、测试报告、构建产物、编辑器文件及日志。

```gitignore
# 忽略本机真实环境变量文件。
.env
# 忽略按环境拆分的本机环境变量文件。
.env.*
# 重新允许提交只含示例值的公共配置模板。
!.env.example
```

忽略规则只影响未跟踪文件的常规暂存行为，不能自动抹去已经提交到 Git 历史中的秘密。`.env.example` 当前提供数据库和 OpenSearch 连接示例，设置 `LLM_MODE=fixture`，并将模型 API Key 留空；这使后续固定样例模式具备不填写云模型密钥的配置入口。本文没有读取真实 `.env`。

#### 4.4 初始化并提交

```powershell
git init -b main # 仅在新项目初始化时创建 Git 仓库，并指定主分支名为 main。
git add .gitignore .editorconfig .env.example docs/environment-verification.md # 仅暂存本任务要求的四个基础文件。
git commit -m "chore: initialize evidencesoc workspace" # 创建可追溯的环境初始化提交。
git status # 补充验收检查：确认工作区状态，原文完成标志要求状态干净。
```

`git add` 把选定变更加入暂存区，`git commit` 为暂存内容建立历史快照。干净的 `git status` 说明工作区与暂存区没有待提交变更，并不能证明所有业务功能正确。

### 5. 核心文件说明

| 文件 | 作用与阅读重点 |
|---|---|
| `.gitignore` | 明确哪些本机文件不进入版本管理，特别区分真实 `.env` 和可提交的 `.env.example`。 |
| `.editorconfig` | 规定 UTF-8、LF、空格缩进、末尾换行等文本规则，减少与业务无关的格式差异。 |
| `.env.example` | 列出应用环境、日志级别、PostgreSQL、OpenSearch、fixture 模式和模型接入所需变量；示例密码是占位值。 |
| `docs/environment-verification.md` | 保存历史验收证据。当前内容注明 2026-09-19、Windows 10.0.26200.9457 和历史项目目录，各工具版本结果均标记为 Pass。 |
| `package.json` | 当前根配置声明仓库私有并固定 `packageManager` 为 `pnpm@11.19.0`，把包管理器选择写进项目。 |
| `.npmrc` | 当前设置 `save-exact=true`，使新增依赖倾向于记录精确版本，服务于后续可复现安装。 |

历史环境记录写明 Docker Server 可连接，`vm.max_map_count` 为 1048576，超过最低要求 262144；Docker 可见 CPU 数为 24，分配内存为 7.609 GiB。它还强调项目 Python 由 uv 管理，开发端口只绑定 `127.0.0.1`。这些是已有文档中的记录，不是本次执行命令产生的新结果。

### 6. 完成验证标准

- **工具可调用且版本吻合。** 逐项核对全局基线；uv 为 0.12.16，pnpm 为 11.19.0，项目 Python 为 3.12.14，系统 Python 仍为 3.13.6。项目解释器和系统解释器分别验证。
- **Docker Server 可连接。** `docker info` 成功；只看到 Docker 客户端版本不能作为替代证据。
- **内核条件满足。** `vm.max_map_count >= 262144`。已有历史记录为 1048576；迁移电脑或重建环境后仍需重新检查。
- **环境记录能解释复现条件。** 包含检查日期、实际版本、项目路径、CPU、内存及 Docker 资源。现有宿主机硬件信息不完整这一点应保留说明，不能用推测补成事实。
- **四个任务文件进入真实提交。** `.gitignore`、`.editorconfig`、`.env.example`、`docs/environment-verification.md` 内容与提交对应，仓库不提交真实秘密。
- **该任务提交后工作区干净。** 这是原文阶段完成条件；后续任务继续修改仓库后，当前状态不必等同于历史提交时的状态。

本次整理依据文件核对说明验收方法，没有重新执行安装、Docker 检查或 Git 提交，因此不新增“今日全部验证通过”的结论。

### 7. 初学者学习要点

1. **环境本身也是工程成果。** 一份可复现的环境记录，可以减少成员加入、换电脑和排查问题时的重复劳动。
2. **版本要分层理解。** 操作系统、运行时、包管理器、框架和项目依赖不是一回事；“Node 版本正确”不能替代“pnpm 与 Next.js 版本正确”。
3. **项目隔离优先于修改全局环境。** 为项目选定 Python 解释器，可以保留其他程序所依赖的系统 Python。
4. **文件存在与规则生效需要分别确认。** 写了 `.gitignore` 不等于历史中没有秘密，写了版本要求不等于终端正在使用该版本。
5. **验收材料必须区分时间和位置。** 历史目录、当前目录、历史检查结果与本次操作应分别表述；真实而有限的证据比笼统写“全部通过”更有价值。
6. **理解本任务在全局的位置。** 它提供后续脚手架、数据库和证据处理的工具基础，同时承接“不引入 Strix 依赖、开发端口仅本机可见、不执行真实高风险处置”等全局边界。

## Task 2：前后端脚手架和质量门禁

### 1. 任务目标

Task 2 使用 Task 1 已验收的 Node.js、pnpm、uv 和 Python，建立可启动的 Next.js 前端与可测试的 FastAPI 后端，并配置最基础的质量检查链路。

这一阶段的明确接口是 `GET /health/live` 返回 HTTP 200，JSON 内容为 `{"status":"ok"}`。主要产物是 `apps/web/**`、`services/backend/pyproject.toml`、`services/backend/src/evidencesoc/main.py` 和 `services/backend/tests/test_health.py`，以及用于可复现安装的 `pnpm-lock.yaml` 与 `services/backend/uv.lock`。

脚手架是后续业务代码的组织起点。前端能打开、后端健康检查通过，只证明基本应用与请求链路成立，不表示数据库、搜索服务、六角色调查流程或完整页面已经实现。

### 2. 设计初衷（为什么要做）

**先建立一条最短可运行链路，可以尽早暴露工程问题。** 如果直接编写大量业务代码后才第一次启动应用，错误可能来自目录结构、依赖安装、导入路径、框架配置或业务实现。一个只有健康接口的后端能把排查范围控制在项目基础层。

**前后端分目录，是为了分离职责与工具链。** `apps/web` 承担页面、交互和前端类型检查；`services/backend` 承担 API、领域逻辑与数据访问。它们仍位于同一仓库，便于共同管理接口变化、依赖版本和提交记录。

**精确依赖与锁文件解决的问题不同。** `package.json`、`pyproject.toml` 记录项目主动选择的直接依赖，锁文件进一步记录依赖解析结果及间接依赖。两者都需要版本管理，才能尽量复现相同安装结果。当前根 `.npmrc` 的 `save-exact=true` 是对前端精确版本约束的补充。

**质量门禁从不同角度发现错误。** pytest 检查行为；Ruff 检查 Python 代码规则；mypy 检查 Python 静态类型；ESLint 检查前端代码规则；TypeScript 检查前端类型；Next.js build 检查生产构建能否完成。通过其中一项不能代替其余检查。

**本任务开始采用明确的 TDD Red/Green 顺序。** 先用测试定义“请求路径、状态码与响应体”，运行并看到符合预期的失败，即 Red；再补充最小实现，使同一个测试通过，即 Green。若失败原因是 uv 不存在或依赖根本没安装，那是环境故障，不是对健康接口需求的有效失败证明。

### 3. 详细执行步骤

1. **创建 Next.js 前端并锁定依赖。** 使用指定版本的 `create next-app`，选择 TypeScript、Tailwind、ESLint、App Router、`src` 目录及 `@/*` 导入别名；随后分别安装运行依赖和开发依赖。命令在项目根目录执行，`--dir apps/web` 指定后续 pnpm 操作所针对的前端目录。
2. **创建 Python 项目并安装固定依赖。** 通过 `uv init --app --python 3.12.14 services/backend` 初始化后端，再用 `uv add --project services/backend` 写入依赖；测试与静态检查工具放入开发依赖组。`--project` 选择项目配置，不能被理解为所有命令都会自动切换当前终端工作目录。
3. **先编写健康接口测试并观察 Red。** 在 `services/backend/tests/test_health.py` 使用 FastAPI 的 `TestClient` 请求 `/health/live`，断言 HTTP 200 与精确响应体。首次应因应用模块尚不存在或路由尚未注册而失败。此时测试说明了需求缺口，而不只是显示终端中的红色文本。
4. **实现最小 FastAPI 应用并观察 Green。** 创建应用对象，注册 GET 路由并返回固定字典，再运行同一个测试。之后运行完整后端测试，确认这一修改没有破坏已有行为。当前仓库已经存在实现，阅读总结时不需要删除路由或改坏代码来伪造历史 Red 阶段。
5. **执行六条质量检查并验证启动。** 依次检查测试、Python 风格与类型、前端风格与类型、生产构建；所有命令退出码均为 0 才能满足准备书的总体要求。前端还需实际启动并在浏览器打开，后端也应验证 HTTP 返回。命令示例中的启动与请求验证是补充教学步骤，应与原文质量门禁区分。
6. **提交这一阶段成果。** 暂存前后端目录和根锁文件，使用原文提交消息保存阶段快照。当前仓库另有根 `package.json`、`.npmrc` 和 `pnpm-workspace.yaml`，如果在实际初始化中新增或修改了这些文件，也应检查是否纳入相应提交，不能因原始 `git add` 没有列出就漏掉必要配置。

### 4. 关键代码/命令示例

#### 4.1 创建前端并安装精确依赖

下列安装命令保留准备书的原始版本号。它们用于理解当时的初始化计划，不是对当前目录再次执行脚手架的操作要求，也不是已经验证今天仍能安装的声明。

```powershell
pnpm create next-app@16.3.5 apps/web --ts --tailwind --eslint --app --src-dir --import-alias "@/*" --use-pnpm # 创建指定版本的 Next.js 项目，采用 TypeScript、App Router 与 src 目录。
pnpm --dir apps/web add next@16.3.5 react@19.3.0 react-dom@19.3.0 @tanstack/react-query@5.103.1 @xyflow/react@12.11.6 echarts@6.1.0 zod@4.6.5 lucide-react@1.47.0 # 固定框架、请求状态、流程图、图表、校验和图标等运行依赖。
pnpm --dir apps/web add -D typescript@7.0.2 tailwindcss@4.3.3 vitest@5.0.1 @playwright/test@1.63.0 openapi-typescript@7.13.0 # 固定编译、样式、单元测试、浏览器测试和接口类型生成所需开发依赖。
```

`--ts` 启用 TypeScript；`--tailwind` 启用 Tailwind CSS；`--eslint` 配置 ESLint；`--app` 使用 App Router；`--src-dir` 将源码放入 `src`；`--import-alias "@/*"` 建立导入别名；`--use-pnpm` 选择 pnpm；`-D` 表示记录到开发依赖。安装了 Vitest 和 Playwright 并不等于已编写或运行对应测试，原文 Task 2 的质量检查也没有单独运行它们。

#### 4.2 创建后端并安装精确依赖

```powershell
uv init --app --python 3.12.14 services/backend # 初始化 Python 应用项目，并选用 uv 管理的 Python 3.12.14。
uv add --project services/backend "fastapi[standard]==0.141.1" pydantic==2.13.5 pydantic-settings==2.15.0 langchain==1.4.1 langgraph==1.2.11 langchain-openai==1.6.2 langchain-postgres==0.0.18 langgraph-checkpoint-postgres==3.1.2 langchain-mcp-adapters==0.3.2 mcp==1.30.0 sqlalchemy==2.0.54 alembic==1.20.0 "psycopg[binary,pool]==3.3.5" pgvector==0.5.0 opensearch-py==3.2.0 sse-starlette==3.4.11 httpx==0.28.1 structlog==26.1.0 # 按准备书固定 API、模型、工作流、数据库、搜索、通信和日志依赖。
uv add --project services/backend --dev pytest==9.1.1 pytest-asyncio==1.4.0 ruff==0.16.8 mypy==2.3.1 # 将测试、异步测试、代码规则与类型检查工具写入开发依赖组。
```

Python 中 `==` 表示精确版本；`fastapi[standard]` 和 `psycopg[binary,pool]` 中的方括号表示额外依赖集合，不是多个项目名称。LangChain、LangGraph、MCP 等依赖在本阶段先纳入环境，具体业务用途属于后续任务；仅安装它们不能证明 Agent 能力已实现。依赖中不应加入 Strix，也不应在运行命令中调用 Strix。

**当前文件与原始安装计划存在实际差异，应同时记录：**

| 检查项 | 准备书计划 | 当前仓库声明或锁定值 | 学习时如何理解 |
|---|---|---|---|
| Python 的 `pgvector` 包 | `pgvector==0.5.0` | `pyproject.toml` 与 `uv.lock` 为 `0.3.6` | 这是 Python 客户端依赖差异，不是 Task 3 的数据库 vector 扩展 0.8.6 被改为 0.3.6。 |
| 前端 TypeScript | `typescript@7.0.2` | `typescript` 键为 `npm:@typescript/typescript6@6.0.2`；另有 `@typescript/native` 键指向 `npm:typescript@7.0.2` | 当前使用包别名，不能只看依赖键名就宣称 `tsc` 已使用原计划版本；本次未执行版本检查来判断具体命令解析结果。 |
| Python 版本约束 | 项目固定 3.12.14 | `services/backend/.python-version` 为 `3.12.14`；`requires-python` 为 `>=3.12.14` | 前者表达项目解释器选择，后者声明兼容范围；兼容下界不等于只允许一个解释器版本。 |
| 构建后端依赖 | 全局要求直接依赖精确版本 | `[build-system]` 中 `uv_build>=0.12.16,<0.13.0` | 当前构建工具使用版本范围，是需要如实保留的配置差异，不能写成“所有声明均为精确版本”。 |

以上差异可由当前文件直接确认；没有充分材料解释变更原因，因此本总结不推断是兼容性修复或已获批准的版本升级，也不擅自修改现有配置。

#### 4.3 先定义健康接口测试：Red

以下保留准备书测试逻辑，并逐行解释。当前 `test_health.py` 的导入顺序略有不同，但请求与断言相同。

```python
from fastapi.testclient import TestClient  # 导入进程内 HTTP 测试客户端，不必先占用真实监听端口。
from evidencesoc.main import app  # 导入要测试的应用；模块不存在时，这一步会使测试收集失败。

def test_live_health() -> None:  # pytest 根据 test_ 前缀发现测试；函数本身不返回业务数据。
    response = TestClient(app).get("/health/live")  # 对目标应用发出 GET 请求，获得可断言的响应。
    assert response.status_code == 200  # 要求 HTTP 状态为成功，未注册路由时通常不满足此条件。
    assert response.json() == {"status": "ok"}  # 要求响应体精确符合约定，不能只检查“有返回值”。
```

```powershell
uv run --project services/backend pytest services/backend/tests/test_health.py -v # 用后端项目环境详细运行健康接口测试，首次应暴露缺少模块或路由的问题。
```

`-v` 提供更详细的测试名称与结果。Red 阶段要读懂失败原因：缺少目标模块或路由符合此处教学顺序；语法写错、解释器错误、包安装失败则需要先修复测试环境，不能把这些偶然失败当作需求被正确检测的证明。

#### 4.4 实现最小健康接口：Green

以下是准备书中的**历史最小实现**，用于说明测试如何驱动代码，不是要求覆盖当前已扩展的 `main.py`。

```python
from fastapi import FastAPI  # 导入 Web 应用框架。

app = FastAPI(title="EvidenceSOC API", version="0.1.0")  # 创建应用对象并声明接口文档中的名称与版本。

@app.get("/health/live")  # 把下一行函数注册为 GET /health/live 的处理函数。
async def live_health() -> dict[str, str]:  # 声明异步路由，并给返回字典的键和值添加字符串类型提示。
    return {"status": "ok"}  # FastAPI 将字典序列化为 JSON，默认成功状态为 200。
```

补充实现后，再运行上一条健康测试命令。同一测试由预期失败变为通过，才构成这一轮 Green。若需要重构代码，应保持接口约定不变，并在重构后再次测试。

当前实际 `main.py` 通过 `create_app()` 创建 `EvidenceSOCApp`，除健康路由外还注册了 Task 9 的业务路由、生命周期管理与请求审计；`/health/live` 仍保持上述行为。`EvidenceSOCApp` 继承 FastAPI，扩展 `openapi()`，将十个核心领域模型及相关定义加入 OpenAPI 的 `components.schemas` 并缓存结果。这是为了后续 Task 4 的契约与前端类型生成；不要把当前导入领域模型的扩展版本误称为 Task 2 最初的最小实现。

#### 4.5 运行六条质量门禁命令

```powershell
uv run --project services/backend pytest -q # 运行后端测试；-q 精简输出，验证实际行为。
uv run --project services/backend ruff check services/backend # 检查后端代码中的规则问题与常见错误。
uv run --project services/backend mypy services/backend/src # 检查后端源码的静态类型一致性。
pnpm --dir apps/web lint # 调用前端 package.json 中的 lint 脚本，当前脚本为 eslint。
pnpm --dir apps/web exec tsc --noEmit # 运行 TypeScript 类型检查，不生成 JavaScript 输出文件。
pnpm --dir apps/web build # 调用 next build，检查生产构建是否能完成。
```

**原文完成标志写“五项质量检查”，但前面的命令块实际包含六条命令，应按六项理解和核对。** 成功标准是六条命令全部退出码为 0。后续仓库增加集成测试后，`pytest -q` 的执行范围可能涉及基础设施，不能把当前完整测试运行条件简单等同于最初只有健康测试的阶段。

#### 4.6 补充启动验证与原文提交命令

原文要求“前端可启动”，但未列启动命令。下面根据当前前端脚本和 FastAPI 应用入口补充一组教学示例。前后端开发服务器分别运行在两个终端，服务启动后再在另一终端发送 HTTP 请求；这些命令本次未执行。

```powershell
pnpm --dir apps/web dev --hostname 127.0.0.1 # 补充示例：启动前端开发服务器，并限制为本机访问。
uv run --project services/backend uvicorn evidencesoc.main:app --app-dir services/backend/src --host 127.0.0.1 --port 8000 # 补充示例：从项目根目录启动后端，并显式指定 src 导入路径与本机监听地址。
Invoke-RestMethod -Uri "http://127.0.0.1:8000/health/live" -Method Get # 补充示例：在服务启动后发出真实 HTTP 请求，检查响应中的 status 为 ok。
```

前端地址以启动日志实际显示的本机 URL 为准，在浏览器打开并确认页面渲染；当前 `apps/web/src/app/page.tsx` 仍是 Next.js 起始页面，因此此处验收的是脚手架页面。进程内 TestClient 与真实 HTTP 启动验证互相补充：前者适合快速回归，后者可以发现监听地址、端口与导入配置等启动问题。

```powershell
git add apps services pnpm-lock.yaml # 原文命令：暂存前后端目录及根 pnpm 锁文件；services 目录包含后端 uv.lock。
git commit -m "chore: scaffold web and backend applications" # 原文命令：记录前后端脚手架和基础质量门禁成果。
```

### 5. 核心文件说明

| 文件或目录 | 作用与阅读重点 |
|---|---|
| `apps/web/package.json` | 声明前端依赖与 `dev`、`build`、`start`、`lint` 脚本。当前没有 `test` 脚本，不能把已安装 Vitest 等同于可执行 `pnpm test`。 |
| `apps/web/src/app/page.tsx` | 前端首页入口，当前还是脚手架起始页面；它证明了页面结构的起点，不代表 SOC 界面完成。 |
| `apps/web/src/app/layout.tsx` | App Router 的根布局文件，为页面提供公共结构。 |
| `apps/web/tsconfig.json` | 当前启用严格类型检查，使用 `@/*` 映射到 `./src/*`，并设置 `noEmit` 等编译选项。 |
| `apps/web/eslint.config.mjs` | 前端代码规则配置，是 `lint` 命令的规则来源。 |
| `pnpm-workspace.yaml` | 当前将 `apps/*` 纳入 pnpm 工作区，使多个前端项目能够统一管理；还记录依赖构建脚本的允许规则。 |
| `pnpm-lock.yaml` | 保存前端完整依赖解析结果，与清单配合复现安装。 |
| `services/backend/pyproject.toml` | 保存项目元数据、Python 兼容约束、运行依赖、开发依赖和构建后端配置；本项目采用 `src` 包目录。 |
| `services/backend/.python-version` | 记录项目选用 Python 3.12.14，帮助 uv 选择解释器。 |
| `services/backend/uv.lock` | 保存 Python 依赖解析结果。当前 `pgvector` 锁定为 0.3.6，与准备书计划不同。 |
| `services/backend/src/evidencesoc/main.py` | 通过 `create_app()` 组织应用、健康路由、业务路由、依赖恢复和请求审计；这些是在最小脚手架上逐步扩展的能力。 |
| `services/backend/src/evidencesoc/openapi.py` | 当前实现 OpenAPI 领域模型注册，属于后续契约工作的扩展，不属于最初最小健康代码必需内容。 |
| `services/backend/tests/test_health.py` | 用状态码与精确 JSON 断言固化健康接口的外部行为，作为后续修改的回归保护。 |

### 6. 完成验证标准

- **前端可启动并显示页面。** 开发命令保持运行，浏览器能够打开实际本机地址，页面成功渲染；生产构建检查也应通过。
- **健康接口符合契约。** `GET /health/live` 返回 HTTP 200 与 `{"status":"ok"}`，健康测试通过。`/health/live` 是进程存活检查，不证明数据库与 OpenSearch 已就绪，也不能替代之后的 `/health/ready`。
- **TDD 顺序有真实依据。** 按原计划开发时，应先观察针对缺失模块或路由的失败，再补实现并通过测试；没有历史运行输出时只能说明计划顺序，不能补写虚构的 Red/Green 执行记录。
- **六项质量门禁通过。** pytest、Ruff、mypy、ESLint、TypeScript 与 Next.js build 全部退出码为 0。某项失败时保留输出并修复原因，不能把“应用能启动”作为忽略失败的理由。
- **依赖与解释器约束可追溯。** 清单、锁文件与 `.python-version` 纳入版本管理；TypeScript、Python `pgvector` 及构建依赖范围的计划差异应被明确记录，不能笼统宣称完全一致。
- **提交完整且不混入本机产物。** 应用源码、测试、必要配置和锁文件保留，虚拟环境、`node_modules/`、构建缓存与真实 `.env` 按规则排除。

本次通过读取代码与配置确认文件和约定的存在，没有启动服务或重新运行质量门禁，因此此处列出的是完成标准与现有证据边界，不是本次测试通过报告。

### 7. 初学者学习要点

1. **把接口当作可以测试的约定。** 路径、请求方法、状态码和响应体都属于约定。测试写清楚这些内容后，内部实现可以逐步扩展而不随意破坏调用方。
2. **掌握 Red、Green、Refactor 的区别。** Red 说明测试检测到未实现的需求；Green 说明最小实现满足测试；Refactor 在保持行为的前提下改进结构。并非所有报错都算 Red，也并非先写完代码再写测试就等于按 TDD 开发。
3. **理解运行依赖与开发依赖。** 前者支持应用功能，后者支持构建、测试和代码检查。开发依赖并不意味着可以不固定版本，运行依赖也不意味着已经被业务调用。
4. **区分运行时验证与静态验证。** 类型检查不执行完整业务请求，测试也无法覆盖所有可能路径；多种检查组合能从不同角度降低错误概率。
5. **区分存活与就绪。** 最简单健康接口用于判断应用能否响应；真正接收业务请求前，还需确认依赖、配置和数据条件已经准备好。
6. **学会阅读清单与锁文件中的真实差异。** 包别名、版本范围、客户端库版本和数据库扩展版本表达不同含义，不能因为名字相似就合并成同一个版本结论。
7. **从最小闭环稳步扩展。** 本任务获得的能力是搭建前后端、使用固定工具环境、编写 API 测试和运行质量检查；Task 3 在此基础上连接存储，Task 4 建立领域与契约，Task 5 才把日志变为可追溯证据。

## Task 3：PostgreSQL、pgvector 和 OpenSearch

### 1. 任务目标

Task 3 交付可连接、可检查健康状态并可持久化数据的 PostgreSQL、pgvector 和 OpenSearch，为模型迁移、日志接入及知识检索提供存储基础。

输入是 Task 1 准备的 Docker 环境和 `.env.example` 中的配置；输出是 PostgreSQL 连接地址（DSN，即数据库连接字符串）、OpenSearch 服务地址以及两个容器的健康检查结果。

| 组成部分 | 原计划固定要求 | 本任务承担的职责 |
|---|---|---|
| PostgreSQL | 主版本 17；镜像 `pgvector/pgvector:0.8.6-pg17-bookworm` | 保存结构化业务数据，为事务、关系查询和后续迁移提供基础。 |
| PostgreSQL 的 `vector` 扩展 | `0.8.6` | 让 PostgreSQL 能存储和检索向量，为后续知识检索预留能力。 |
| OpenSearch | 镜像 `opensearchproject/opensearch:3.8.0` | 为规范化日志提供字段筛选、全文检索等能力。 |
| Docker Compose | `5.5.0` | 通过仓库根目录的 `compose.yaml` 统一定义、启动和检查依赖服务。 |

原计划的完成标志是“一条 Compose 命令可启动基础设施，重启不丢数据”。这既要求配置文件存在，也要求真实服务连接、版本、健康状态以及重启后的记录读取均得到验证。本章根据仓库源码说明实施方法；本次文档整理没有启动 Docker、写入数据库或执行重启，因此不把下面的验收要求写成已经发生的运行结果。

### 2. 设计初衷（为什么要做）

**让不同工具承担适合自己的工作。** PostgreSQL 是关系数据库，适合保存告警、事件、证据、审批记录等有明确结构和关联的数据；OpenSearch 是搜索引擎，适合对大量日志按时间、IP、关键词等条件进行检索。两者不是互相替代的关系。Task 3 先准备可用服务，业务表和数据库迁移放在 Task 4，日志向两个存储写入及一致性处理放在 Task 5。

**区分同名的 pgvector 服务端扩展与 Python 包。** 镜像中的 pgvector 提供 PostgreSQL 服务端扩展，启用后的扩展名称是 `vector`，本项目要求其版本为 `0.8.6`。Python 依赖中的 `pgvector` 是 Python 与向量数据交互的客户端适配包。原准备文档要求 Python 包为 `pgvector==0.5.0`，当前 `services/backend/pyproject.toml` 实际固定为 `pgvector==0.3.6`。这是计划与实现的差异，不能改写成二者完全一致；客户端版本也不需要与服务端扩展版本写成同一个数字。只安装 Python 包不会在数据库里自动创建 `vector` 扩展。

**通过容器与精确版本减少环境差异。** Compose 文件集中描述镜像、端口、配置、数据卷和健康检查，便于其他开发者重建依赖。这里 PostgreSQL 固定的是主版本 17，并不是某个精确的 `17.x` 补丁版本；pgvector 和 OpenSearch 则使用计划中的明确版本标签。直接 Python 依赖仍须固定版本，间接依赖通过 `uv.lock` 保留解析结果，不应为了启动服务临时引入未登记的替代依赖。

**把本地依赖限制在本机开发范围。** `127.0.0.1` 是回环地址。端口映射中的 `127.0.0.1:5432:5432` 表示宿主机只在本机地址上提供 PostgreSQL 入口；OpenSearch 同样只绑定本机。当前 OpenSearch 关闭安全插件，仅适用于计划中的本地开发方式。它不等于已经配置生产身份认证，也不应通过把监听地址改为 `0.0.0.0` 来处理连接问题。项目继续遵守全局约束：MVP 不增加 MySQL、Milvus、Neo4j、Redis，不把 Strix 放进依赖、启动命令或容器，不执行真实封禁、账号禁用、主机隔离或公网扫描。

**分别处理“进程启动”“可以使用”和“数据保留”。** 容器运行不代表数据库已经接受连接；健康检查用于判断服务是否就绪。容器文件层也不是业务数据持久化方案，所以 PostgreSQL 和 OpenSearch 使用各自的命名数据卷。健康状态、真实请求和重启读取记录分别回答不同的问题，不能互相替代。

### 3. 详细执行步骤

**步骤一：确认 Task 1、Task 2 的前置条件和配置。**

原计划的环境基线为 Windows `10.0.26200.9457`、WSL `2.7.3.0`、Docker Engine `29.7.2`、Docker Compose `5.5.0`；项目使用 uv `0.12.16` 管理 Python `3.12.14`，保留系统 Python `3.13.6`。OpenSearch 的前置检查要求 `vm.max_map_count >= 262144`。这些条件来自前面的环境验收，不需要在每次写文档时重新安装工具。

命令默认从当前仓库根目录 `D:\传智杯` 执行。原准备文档 Task 1 中的 `D:\桌面\传智杯` 是原工作路径，应与当前实际位置区分。检查公开的 `.env.example`，确保数据库名称、用户、端口和 URL 对应：

```dotenv
# 数据库名称：创建的数据库与连接地址末尾的数据库名应一致。
POSTGRES_DB=evidencesoc
# 数据库用户：需要与连接地址中的用户名一致。
POSTGRES_USER=evidencesoc
# 公开样例占位密码；这里只展示 .env.example 的内容。
POSTGRES_PASSWORD=change-me-local-only
# SQLAlchemy 使用的 PostgreSQL 连接地址，并指定 psycopg 驱动。
DATABASE_URL=postgresql+psycopg://evidencesoc:change-me-local-only@127.0.0.1:5432/evidencesoc
# OpenSearch 映射到宿主机的端口，Compose 从这个变量读取端口号。
OPENSEARCH_PORT=9200
# 后端与测试从宿主机访问 OpenSearch 的地址。
OPENSEARCH_URL=http://127.0.0.1:9200
```

`DATABASE_URL` 可理解为“协议和驱动 + 用户凭据 + 主机和端口 + 数据库名”。如果修改本地用户名、密码或端口，应同时更新对应的连接地址。尤其是 `OPENSEARCH_PORT` 和 `OPENSEARCH_URL` 是两个不同变量，修改前者不会自动改写后者。真实 `.env` 属于本地配置，不应复制到学习文档或提交到仓库；本章也未读取其内容。

**步骤二：先编写连接测试，确认 TDD 的 Red 阶段。**

在 `services/backend/tests/integration/test_dependencies.py` 中直接访问真实依赖，先验证 PostgreSQL 的 `SELECT 1`、服务器版本与 `vector` 扩展版本，再验证 OpenSearch 根接口的版本和 `/_cluster/health`。当前实现还增加了第三个测试，检查名为 `security-events` 的索引模板是否已安装。

TDD 的 Red 阶段是先运行测试，观察“尚未满足约定”造成的预期失败，例如目标服务还没有启动、扩展未启用或模板不存在。需要确认失败原因与本任务有关，不能把 Python 导入路径写错或测试语法错误当作有效的 Red 证据。这里的 Red 是原实施流程说明，本次整理不通过停止现有服务来人为制造失败。

**步骤三：定义容器、健康检查与持久化。**

在根目录 `compose.yaml` 中定义 `postgres` 和 `opensearch`，使用上述固定镜像。PostgreSQL 挂载初始化脚本，使用 `pg_isready` 检查连接就绪；OpenSearch 使用 `discovery.type=single-node` 运行单节点，使用 `-Xms1g -Xmx1g` 将 JVM 初始堆和最大堆都设置为 1 GB。1 GB 只是 Java 堆大小，不是整个容器的内存上限，Docker 仍需为运行时和其他服务提供足够内存。

`infra/postgres/init.sql` 执行 `CREATE EXTENSION IF NOT EXISTS vector;`。此脚本通过 `/docker-entrypoint-initdb.d/001-init.sql` 挂载，按 PostgreSQL 镜像的初始化机制在新数据库目录首次初始化时执行；已有数据卷不会因为修改 SQL 文件就自动重新执行初始化。`IF NOT EXISTS` 只用于避免重复创建扩展，也不负责把已有扩展升级到指定版本。因此必须查询数据库里的实际扩展版本。

PostgreSQL 的 `postgres_data` 挂载到 `/var/lib/postgresql/data`，OpenSearch 的 `opensearch_data` 挂载到 `/usr/share/opensearch/data`。它们是命名卷，重启容器时数据仍由卷保存。不要用会删除数据卷的命令替代原计划的重启验证。

**步骤四：启动服务，等待健康检查通过，再安装索引模板。**

原计划依次执行 `docker compose config`、`docker compose up -d postgres opensearch` 和 `docker compose ps`。第一条检查 Compose 展开后的配置；第二条在后台启动两个依赖；第三条查看运行和健康状态。OpenSearch 初始化通常比 PostgreSQL 慢，应以状态与请求结果为准，不能把出现 `running` 直接当成 `healthy`。

当前 `compose.yaml` 没有挂载或上传 `infra/opensearch/security-events-template.json` 的逻辑。文件存在于仓库不意味着模板已经存在于 OpenSearch，必须通过 `PUT /_index_template/security-events` 安装。本章的模板安装命令是根据当前配置和第三个集成测试补充的可执行说明，并非原计划中已经列出的命令。

索引模板是“以后创建符合命名规则的索引时采用的字段与设置规则”。`security-events-*` 匹配应用默认索引 `security-events-v1`。应先安装模板，再让 Task 5 创建事件索引；更新模板不会自动改写已有索引的字段映射。当前模板安装测试仅检查模板名称存在，还不能证明服务器端的模板内容与仓库 JSON 完全一致。

**步骤五：执行真实集成测试，完成 Green 阶段。**

按原命令运行 `uv run --project services/backend pytest services/backend/tests/integration/test_dependencies.py -v`。Green 阶段要求前面定义的断言实际通过。当前文件包含三个测试函数，未设置 `skip`、`skipif` 或依赖不可达时自动跳过的逻辑；因此不能把“跳过了依赖测试的其他测试集通过”写成 Task 3 已验收。

测试读取配置的顺序是进程环境变量、仓库根目录 `.env`、仓库根目录 `.env.example`。`postgres_dsn()` 会把 SQLAlchemy 风格的 `postgresql+psycopg://` 转为 psycopg 直接连接所需的 `postgresql://`。模板安装命令与测试必须指向同一个 OpenSearch 实例。

**步骤六：按原计划验证重启后记录仍存在。**

先向服务写入专用验证记录并确认读回，再执行原命令 `docker compose restart`，等待两个容器重新就绪，随后使用相同标识再次读取。为了覆盖本任务的两个持久化卷，可分别验证 PostgreSQL 测试表中的一行和 OpenSearch 测试索引中的一个文档。该补充检查比只观察卷定义更能证明持久化链路有效。

当前 `test_dependencies.py` 没有写入记录、重启容器再读取的自动化测试；代码中配置了命名卷也不能替代这一运行证据。应保存执行日期、命令、记录标识与重启后结果，作为独立验收记录。

**步骤七：验证通过后提交基础设施变更。**

保留原计划中的暂存路径和提交信息，便于理解任务如何形成真实 Git 历史。对于已经完成的历史任务，无需为了复习再次提交相同内容，更不能制造“重新完成”的提交记录。

### 4. 关键代码/命令示例

**示例一：PostgreSQL 容器配置与扩展初始化。** 下列 YAML 节选自实际 `compose.yaml`，增加中文注释；仍需放在原文件的 `services` 层级下。省略的内容以原文件为准。

```yaml
postgres: # Compose 服务名称，供 up、exec 等命令定位服务。
  image: pgvector/pgvector:0.8.6-pg17-bookworm # PostgreSQL 17 与 pgvector 0.8.6 镜像。
  environment: # 传入数据库初始化所需环境变量。
    POSTGRES_DB: ${POSTGRES_DB:-evidencesoc} # 未设置变量时采用样例数据库名。
    POSTGRES_USER: ${POSTGRES_USER:-evidencesoc} # 未设置变量时采用样例用户名。
    POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:-change-me-local-only} # 本地样例默认密码。
  ports: # 格式为宿主机地址、宿主机端口、容器端口。
    - "127.0.0.1:5432:5432" # 只通过本机地址访问 PostgreSQL。
  volumes: # 同时挂载持久化数据目录和只读初始化脚本。
    - postgres_data:/var/lib/postgresql/data # 使用命名卷保存数据库文件。
    - ./infra/postgres/init.sql:/docker-entrypoint-initdb.d/001-init.sql:ro # ro 表示只读。
  healthcheck: # Docker 根据此命令的退出状态判断是否就绪。
    test:  # 配置数据库健康检查命令。
      [
        "CMD-SHELL", # 在容器内通过 Shell 执行下一项。
        "pg_isready -U \"$${POSTGRES_USER}\" -d \"$${POSTGRES_DB}\"" # $$ 保留给容器内变量展开。
      ]
    interval: 5s # 每隔 5 秒检查一次。
    timeout: 5s # 单次检查最多等待 5 秒。
    retries: 12 # 连续失败达到阈值后标记为不健康。
    start_period: 10s # 为启动初始化预留宽限时间。
```

```sql
-- infra/postgres/init.sql：在当前初始化数据库中启用服务端 vector 扩展。
CREATE EXTENSION IF NOT EXISTS vector;  -- 扩展已存在时不重复创建；这启用数据库服务端向量能力。
```

`pg_isready` 说明服务器已经接受连接；是否能执行查询、是否运行目标版本以及扩展是否存在，仍要由下面的集成测试确认。

**示例二：OpenSearch 的单节点、内存与 HTTP 健康检查。** 以下是实际文件的关键配置节选，中文注释仅用于学习。

```yaml
opensearch: # OpenSearch 的 Compose 服务名称。
  image: opensearchproject/opensearch:3.8.0 # 固定服务器版本标签。
  environment: # 传入 OpenSearch 启动设置。
    - cluster.name=evidencesoc # 设置集群名称。
    - node.name=opensearch # 设置当前节点名称。
    - discovery.type=single-node # 本地只启动一个节点。
    - bootstrap.memory_lock=true # 请求锁定进程内存，配合下方 memlock 限制。
    - OPENSEARCH_JAVA_OPTS=-Xms1g -Xmx1g # JVM 初始堆和最大堆均为 1 GB。
    - DISABLE_INSTALL_DEMO_CONFIG=true # 不安装镜像自带的演示安全配置。
    - DISABLE_SECURITY_PLUGIN=true # 按本地开发配置禁用安全插件。
  ports:  # 限定宿主机可访问的端口映射。
    - "127.0.0.1:${OPENSEARCH_PORT:-9200}:9200" # 宿主机默认 9200，容器端口固定 9200。
  volumes:  # 挂载保存索引文件的命名卷。
    - opensearch_data:/usr/share/opensearch/data # 使用命名卷保存索引数据。
  ulimits: # 调整容器进程可使用的资源限制。
    memlock:  # 设置内存锁定限制。
      soft: -1 # 内存锁定软限制不设上限。
      hard: -1 # 内存锁定硬限制不设上限。
    nofile:  # 设置打开文件数量限制。
      soft: 65536 # 可打开文件描述符的软限制。
      hard: 65536 # 可打开文件描述符的硬限制。
  healthcheck:  # 定义容器就绪检查。
    test:  # 指定健康探针执行命令。
      [
        "CMD-SHELL", # 通过容器内 Shell 发起健康检查。
        "curl --fail --silent 'http://localhost:9200/_cluster/health?wait_for_status=yellow&timeout=5s' >/dev/null || exit 1" # 请求集群至少达到 yellow 状态。
      ]
    interval: 10s # 每隔 10 秒检查一次。
    timeout: 10s # 单次 Docker 检查的超时时间。
    retries: 18 # 连续失败达到阈值后标记为不健康。
    start_period: 60s # 为 OpenSearch 启动预留较长宽限时间。
```

健康检查中的 `localhost` 指 OpenSearch 容器自身；配置中的 `127.0.0.1` URL 供在宿主机上运行的后端和测试使用。`yellow` 表示主分片可用但部分副本未分配，`green` 表示主分片和副本全部分配；单节点环境可能出现 `yellow`，所以当前测试接受二者。HTTP 健康检查主要依赖请求退出状态，集成测试还会明确读取 JSON 中的 `status` 字段。

**示例三：索引模板核心内容。** 下列保留真实 JSON 的关键层级和字段，并以 JSONC（带注释的 JSON 展示形式）逐行解释；它用于学习，不是完整模板的替代文件。JSON 本身不支持注释，安装时必须读取仓库里的完整 `.json` 文件，不能把这个带注释片段直接作为 HTTP 请求体。

```jsonc
{ // 模板对象开始。
  "index_patterns": ["security-events-*"], // 适用于以后新建的 security-events-* 索引。
  "priority": 100, // 多个模板匹配时用于选择优先级。
  "version": 1, // 模板版本为 1，与 OpenSearch 3.8.0 的软件版本不同。
  "template": { // 定义索引设置与字段映射。
    "settings": { // 定义分片等运行设置。
      "number_of_shards": 1, // 单节点示例使用一个主分片。
      "number_of_replicas": 0 // 本地不配置副本。
    }, // 结束当前层级。
    "mappings": { // 定义字段如何被搜索引擎保存和检索。
      "dynamic": false, // 不自动为未知字段建立映射。
      "_source": {"enabled": true}, // 保留写入的原始文档以便回读。
      "properties": { // 列出可检索字段；HTTP 内部也有自己的 properties。
        "event_id": {"type": "keyword"}, // 事件 ID 使用 keyword 进行精确匹配。
        "observed_at": {"type": "date"}, // 观察时间使用 date 支持范围查询。
        "source_ip": {"type": "ip"}, // 源地址使用 ip 类型。
        "source_port": {"type": "integer"}, // 源端口使用整数类型。
        "message": { // 消息同时支持全文检索与精确匹配。
          "type": "text", // text 表示对消息进行全文分词。
          "fields": { // 为同一消息建立附加的精确匹配子字段。
            "keyword": {"type": "keyword", "ignore_above": 256} // 超过 256 的值不进入这个子字段索引，原文仍保留。
          } // 结束当前层级。
        }, // 结束当前层级。
        "http": { // 分组保存 HTTP 请求的检索字段。
          "properties": { // 列出可检索字段；HTTP 内部也有自己的 properties。
            "method": {"type": "keyword"}, // HTTP 方法使用精确字符串匹配。
            "path": {"type": "wildcard"}, // HTTP 路径支持通配条件。
            "status_code": {"type": "integer"} // HTTP 状态码保存为整数。
          } // 结束当前层级。
        }, // 结束当前层级。
        "raw_event": {"type": "object", "enabled": false} // 保留原始对象但不为它的任意内部字段创建索引。
      } // 结束当前层级。
    } // 结束当前层级。
  } // 结束当前层级。
} // 结束当前层级。
```

| 字段或设置 | 初学者需要理解的含义 |
|---|---|
| `index_patterns` | 将模板应用于随后创建的 `security-events-*` 索引。 |
| `priority`、`version` | 分别表示模板匹配优先级和模板自身版本；`version: 1` 不是 OpenSearch 版本。 |
| `number_of_shards: 1` | 一个主分片，降低本地单节点示例的复杂度。 |
| `number_of_replicas: 0` | 不配置副本；符合本地单节点方案，但不提供跨节点副本保障。 |
| `dynamic: false` | 不为未知字段自动新增映射；它不等于拒绝含未知字段的整条日志。 |
| `_source.enabled: true` | 保存提交的原始文档内容，便于按 ID 回读与追溯。 |
| `keyword` | 适合事件 ID、来源、严重性、主机、哈希、标签等精确筛选字段，不按全文分词。 |
| `date`、`ip`、`integer` | 分别为时间范围、IP 地址和整数数值提供明确类型。 |
| `message.type: text` | 支持消息全文检索；其 `keyword` 子字段提供另一种精确匹配方式。 |
| `ignore_above: 256` | 超过阈值的消息不进入该 `keyword` 子字段索引，不表示 `_source` 内容被截断。 |
| `http.method`、`http.path`、`http.status_code` | 分别使用精确字符串、通配检索字段和整数描述 HTTP 请求信息。 |
| `raw_event.enabled: false` | 保留原始事件对象，但不解析其内部字段建立索引，避免任意原始结构不断扩张映射。 |

完整文件还声明 `external_id`、`source`、`event_type`、`severity`、`ingested_at`、`destination_ip`、`destination_port`、`host`、`service`、`content_sha256`、`tags` 等字段，并使用 `_meta.schema_version: 1` 记录应用模式版本。

**示例四：原计划启动命令与补充的模板安装步骤。** 下列命令是执行说明，本次整理未运行。原计划中的四条启动/测试命令保留不变；模板安装插在容器就绪与运行测试之间。

```powershell
# 检查 Compose 语法、变量替换和最终服务配置；不要公开含真实配置的输出。
docker compose config
# 在后台启动本任务的两个服务。
docker compose up -d postgres opensearch
# 查看状态，等待两个服务显示 healthy。
docker compose ps

# 补充步骤：以下地址使用 .env.example 的本地默认值；若本地修改端口，应同步修改此值。
$task3OpenSearchUrl = "http://127.0.0.1:9200"
# 读取仓库中完整的模板文件，明确按 UTF-8 解码。
$task3Template = Get-Content -LiteralPath "infra/opensearch/security-events-template.json" -Raw -Encoding UTF8
# 安装名为 security-events 的索引模板，供后续新建事件索引使用。
Invoke-RestMethod -Method Put -Uri "$task3OpenSearchUrl/_index_template/security-events" -ContentType "application/json" -Body $task3Template
# 回读已安装模板；可进一步核对其映射与设置是否和仓库文件相同。
Invoke-RestMethod -Method Get -Uri "$task3OpenSearchUrl/_index_template/security-events"

# 执行原计划指定的真实依赖集成测试。
uv run --project services/backend pytest services/backend/tests/integration/test_dependencies.py -v
```

**示例五：真实测试中的关键断言。** 以下代码节选自当前 `services/backend/tests/integration/test_dependencies.py`，仅增加中文注释；`postgres_dsn()` 与 `opensearch_url()` 为同文件已有的配置辅助函数。

```python
def test_postgres_and_pgvector_versions() -> None:  # 定义真实数据库与 vector 扩展版本验收。
    with (  # 用上下文管理器确保连接与游标用完关闭。
        psycopg.connect(  # 创建 psycopg 数据库连接。
            postgres_dsn(),  # 读取配置，并转换为 psycopg 支持的 PostgreSQL DSN。
            connect_timeout=5,  # 连接最多等待 5 秒，避免无限等待服务。
        ) as connection,  # 将打开的连接绑定到 connection。
        connection.cursor() as cursor,  # 创建游标以执行 SQL。
    ):
        cursor.execute("SELECT 1")  # 用最小 SQL 验证真实数据库请求。
        assert cursor.fetchone() == (1,)  # 查询结果是一行元组，必须等于 (1,)。

        cursor.execute("SHOW server_version")  # 读取实际服务器版本。
        server_version = cursor.fetchone()  # 获取返回的一行。
        assert server_version is not None  # 确认数据库确实返回版本。
        assert server_version[0].startswith("17.")  # 只约束主版本为 17，不锁定补丁版本。

        cursor.execute(  # 查询已经安装的向量扩展版本。
            "SELECT extversion "  # 查询已安装扩展的版本列。
            "FROM pg_extension "  # PostgreSQL 系统目录保存已安装扩展信息。
            "WHERE extname = 'vector'"  # 服务端扩展名称是 vector。
        )
        assert cursor.fetchone() == ("0.8.6",)  # 必须已启用且精确匹配 0.8.6。

def test_opensearch_version_and_health() -> None:  # 定义 OpenSearch 版本与健康状态验收。
    root_response = httpx.get(opensearch_url(), timeout=10)  # 访问真实 OpenSearch 根接口。
    root_response.raise_for_status()  # HTTP 错误立即使测试失败。
    assert root_response.json()["version"]["number"] == "3.8.0"  # 精确核对服务器版本。

    health_response = httpx.get(  # 发送集群健康请求并限制等待时间。
        f"{opensearch_url()}/_cluster/health",  # 读取集群健康信息。
        timeout=10,  # 最多等待 10 秒。
    )
    health_response.raise_for_status()  # 先确认请求本身成功。
    assert health_response.json()["status"] in {"yellow", "green"}  # 不接受 red。

def test_security_events_template_is_installed() -> None:  # 定义索引模板安装验收。
    response = httpx.get(  # 读取 security-events 模板。
        f"{opensearch_url()}/_index_template/security-events",  # 查询目标模板。
        timeout=10,  # 避免模板查询无限等待。
    )
    response.raise_for_status()  # 模板不存在等 HTTP 错误会导致失败。

    template_names = {  # 从响应中提取服务器实际保存的模板名称。
        item["name"] for item in response.json()["index_templates"]  # 提取返回的模板名称。
    }
    assert "security-events" in template_names  # 当前只验证名称存在，不比较完整内容。
```

**示例六：补充的重启持久化验证命令。** 这部分是便于学习的操作示例，不属于原仓库现成的自动化测试。数据库名和用户采用 `.env.example` 默认值；如本地配置不同，应先调整。SQL 使用专用探针表，OpenSearch 使用专用探针索引，避免混入业务数据。

```powershell
# 在 PostgreSQL 写入固定标识的验证记录；-T 便于从管道传入 SQL。
# CREATE TABLE 建立专用探针表；INSERT 在重复执行时保留同一条记录；SELECT 确认写入结果。
@'
CREATE TABLE IF NOT EXISTS task3_persistence_probe (id text PRIMARY KEY, note text NOT NULL); -- 创建独立探针表，避免干扰业务表。
INSERT INTO task3_persistence_probe (id, note) VALUES ('task3-check', 'before-restart') ON CONFLICT (id) DO NOTHING; -- 相同探针重复执行不会重复插入。
SELECT id, note FROM task3_persistence_probe WHERE id = 'task3-check'; -- 重启前先确认记录确实存在。
'@ | docker compose exec -T postgres psql -U evidencesoc -d evidencesoc -v ON_ERROR_STOP=1

# 向专用 OpenSearch 索引写入固定 ID 文档，索引名称可匹配已安装的模板。
Invoke-RestMethod -Method Put -Uri "$task3OpenSearchUrl/security-events-task3-probe/_doc/task3-check?refresh=true" -ContentType "application/json" -Body '{"event_id":"task3-check","message":"before-restart"}'
# 重启前先回读，证明验证记录确实已写入目标服务。
Invoke-RestMethod -Method Get -Uri "$task3OpenSearchUrl/security-events-task3-probe/_doc/task3-check"

# 原计划的重启命令：对当前 Compose 项目执行重启。
docker compose restart
# 等待 PostgreSQL 和 OpenSearch 重新显示 healthy 后再继续读取。
docker compose ps
# 重启后使用同一个主键查询 PostgreSQL，预期仍得到原记录。
"SELECT id, note FROM task3_persistence_probe WHERE id = 'task3-check';" | docker compose exec -T postgres psql -U evidencesoc -d evidencesoc -v ON_ERROR_STOP=1
# 重启后使用同一个文档 ID 查询 OpenSearch，预期 found 为 true 且 _source 内容一致。
Invoke-RestMethod -Method Get -Uri "$task3OpenSearchUrl/security-events-task3-probe/_doc/task3-check"
```

**示例七：原计划的历史提交步骤。** 只在任务首次实施、验证通过并确认暂存范围后执行；已完成的历史提交无需重做。

```powershell
# 暂存 Compose、基础设施文件和集成测试目录。
git add compose.yaml infra services/backend/tests/integration
# 使用原计划约定的提交说明记录真实完成状态。
git commit -m "infra: add postgres pgvector and opensearch"
```

### 5. 核心文件说明

本章路径均相对于仓库根目录 `D:\传智杯`。原计划中的测试路径包含 `services/backend/` 前缀，不是根目录下的 `tests/integration/test_dependencies.py`。

| 文件 | 作用 | 阅读时应关注的内容 |
|---|---|---|
| `compose.yaml` | 声明两个容器、端口、环境变量、健康检查和命名数据卷。 | 固定镜像、本机绑定、1 GB 堆、卷路径、检查间隔；其中没有自动安装索引模板的步骤。 |
| `infra/postgres/init.sql` | 在新数据库首次初始化时启用 `vector` 扩展。 | `CREATE EXTENSION IF NOT EXISTS vector;` 不负责业务建表，也不负责已有扩展升级。 |
| `infra/opensearch/security-events-template.json` | 规定新事件索引的分片、副本和字段映射。 | 模板名由安装接口确定；索引匹配规则为 `security-events-*`。 |
| `services/backend/tests/integration/test_dependencies.py` | 对真实 PostgreSQL 和 OpenSearch 执行连接、版本、健康和模板检查。 | 当前三个测试没有跳过分支；没有重启持久化测试，也没有模板内容完整比较。 |
| `.env.example` | 提供可公开的连接配置样例。 | 数据库凭据和 DSN 要一致；OpenSearch 端口与 URL 要一致。 |
| `services/backend/src/evidencesoc/config.py` | 为后端应用定义数据库、搜索地址及默认索引。 | 默认索引为 `security-events-v1`；应用的 Settings 与依赖测试各有自己的配置读取实现。 |
| `services/backend/pyproject.toml`、`services/backend/uv.lock` | 声明 Python 直接依赖并记录锁定结果。 | Python `pgvector` 包与服务器 `vector` 扩展版本不能混淆；当前客户端声明与原计划存在差异。 |
| `docs/EvidenceSOC-project-preparation.md` | 原始实施计划与验收依据。 | Task 3 的五个原始步骤、固定版本、重启读取要求及提交信息。 |

### 6. 完成验证标准

应分别记录“计划要求”“源码具备的检查”与“本次是否实际执行”，避免把代码审阅当作运行验收。

| 验证项目 | 原计划或合理补充的通过标准 | 当前源码能证明什么 |
|---|---|---|
| Compose 配置 | `docker compose config` 成功，两个服务端口均只绑定 `127.0.0.1`。 | YAML 中已声明本机绑定及固定镜像；仍需实际配置检查结果。 |
| 容器就绪 | `docker compose ps` 中 PostgreSQL 与 OpenSearch 均为 `healthy`。 | 已定义两套健康检查，不能据此推断当前容器状态。 |
| PostgreSQL 连接和版本 | `SELECT 1` 返回 `(1,)`，服务器主版本为 17。 | 测试断言使用 `startswith("17.")`，不验证具体补丁号。 |
| pgvector 扩展 | 数据库已安装 `vector`，实际扩展版本为 `0.8.6`。 | 测试精确断言 `("0.8.6",)`；与 Python 包版本无关。 |
| OpenSearch 连接和版本 | 根接口版本为 `3.8.0`，集群状态为 `yellow` 或 `green`。 | 测试分别检查版本与健康 JSON。 |
| 事件索引模板 | `security-events` 模板存在，内容符合仓库模板，新索引采用相应字段映射。 | 当前测试只确认名称存在；模板内容及新索引映射需另行核对。 |
| 集成测试执行 | 直接运行指定文件，三个测试实际执行并通过。 | 文件没有 `skip` 或 `skipif`；被跳过、被排除或没有运行均不能算通过。 |
| 重启持久化 | 重启前后的验证记录标识及内容相同，两个持久化卷均得到覆盖。 | 已声明命名卷；当前依赖测试不覆盖真实重启过程。 |
| 版本计划一致性 | 服务端满足 Task 3 固定版本；依赖差异有真实记录和处理依据。 | Python 客户端原计划 `0.5.0`、当前声明 `0.3.6`，不能报告“所有依赖完全符合原计划”。 |
| 交付记录 | 验证结果与真实 Git 提交对应。 | 原计划提供了提交命令；仅有命令文本不能证明提交或验证发生。 |

本次整理完成的是文件与断言核对，没有运行上述容器、连接测试或持久化写入。因此，这里不报告“3 passed”，也不宣称数据库或搜索服务当前已经健康。后续验收应保留实际测试输出；如果某次更大范围的测试报告出现 skipped，还必须说明跳过的是哪些测试，不能将其计入本任务成功证据。

### 7. 初学者学习要点

1. **先理解服务分工。** PostgreSQL 管结构化业务记录，OpenSearch 管日志检索；向量扩展是在 PostgreSQL 内增加一种数据与检索能力，不是又启动了一个独立数据库服务。
2. **区分四类版本。** PostgreSQL 服务器版本、`vector` 扩展版本、Python `pgvector` 包版本和 OpenSearch 版本分别验证。模板的 `version: 1` 又属于应用模板自身版本，不能混在一起比较。
3. **把连接地址拆开阅读。** 先看协议与驱动，再看主机和端口，最后看数据库名；用户名、密码或端口变化时，检查所有相关配置是否同步更新。
4. **分清地址所在的运行环境。** 宿主机上的 `127.0.0.1` 指宿主机，容器健康检查里的 `localhost` 指当前容器；将来若后端也进入容器，不能直接假设宿主机连接地址仍然适用。
5. **理解 Red 和 Green 的证据意义。** Red 要证明测试能发现缺失能力，Green 要证明实现满足同一个约定；普通单元测试通过不能替代真实数据库和搜索服务的集成测试。
6. **不要把健康、版本和持久化混为一谈。** 服务能响应不一定版本正确；容器健康不代表模板已安装；挂载卷不等于已验证重启后数据还在。每项验收都要有对应证据。
7. **理解初始化和迁移的区别。** `init.sql` 为新数据库启用扩展，Task 4 的 Alembic 负责业务结构演进。修改初始化文件不会自动更新已有数据库。
8. **理解“文件存在”和“服务已配置”的区别。** OpenSearch 模板 JSON 必须通过接口安装才会生效，并且主要影响后来创建的索引。当前测试检查模板名称存在，只覆盖了这一链路的一部分。
9. **按真实进度记录完成情况。** 版本差异、未执行的运行验证和历史命令都应明确标注；学习总结的作用是帮助理解并复现，不是补写没有发生过的测试结果。

## Task 4：领域模型、迁移和 OpenAPI 契约

### 1. 任务目标

Task 4 交付领域模型、初始 12 张业务表、版本化迁移和前端 API 类型，使告警、调查、证据与审批拥有一致的数据契约。

输入是 Task 3 提供的 PostgreSQL DSN（数据库连接字符串），输出供后续日志接入、工具调用和调查工作流复用。

原文要求产出的 10 个核心模型必须保留完整名称：`SecurityEvent`、`Alert`、`Incident`、`EvidenceItem`、`AttackOrigin`、`AttackClassification`、`AgentRun`、`ResponsePlan`、`ApprovalRecord`、`ValidationResult`。

| 模型 | 初学者可以怎样理解 | 主要数据 |
|---|---|---|
| `SecurityEvent` | 一条经过规范化的原始安全事件 | 来源、原始内容、时间、严重性、内容哈希；当前还包含去重键和索引状态 |
| `Alert` | 值得调查的告警 | 告警标题、严重性、关联事件 ID |
| `Incident` | 跟踪一次调查的业务对象 | 告警 ID、调查状态、创建时间 |
| `EvidenceItem` | 可以追溯和核验的一项证据 | Evidence ID、来源、查询、观察时间、摘要、SHA-256；当前还包含事件 ID |
| `AttackOrigin` | 对攻击来源的判断 | 观察到的源 IP、入口主机、入口服务、来源范围、置信度、证据引用 |
| `AttackClassification` | 对攻击类型的判断 | 主类型、多标签攻击类型、阶段、ATT&CK 技术 ID、置信度、证据引用 |
| `AgentRun` | 一个 Agent 节点的一次运行记录 | 调查 ID、节点名称、状态、开始和结束时间 |
| `ResponsePlan` | 等待人工审批的模拟处置方案 | 动作、方案摘要、证据引用、必须审批标记 |
| `ApprovalRecord` | 人的审批决定 | 批准或拒绝、理由、审批人、时间 |
| `ValidationResult` | 模拟处置后的验证结论 | 成功、失败或证据不足，以及相应证据 |

原文的最终完成标志是：**空库可完整迁移；前端生成类型无 `any` 替代核心 DTO**。DTO 即“数据传输对象”，可以理解为不同模块交换数据时共同遵守的表单格式。

本任务直接相关的原定版本为 Python `3.12.14`、uv `0.12.16`、FastAPI `0.141.1`、Pydantic `2.13.5`、SQLAlchemy `2.0.54`、Alembic `1.20.0`、`psycopg[binary,pool]` `3.3.5`、Python `pgvector` `0.5.0`、PostgreSQL `17`、数据库 pgvector 扩展 `0.8.6`、`openapi-typescript` `7.13.0`、TypeScript `7.0.2`、pytest `9.1.1`。当前版本差异见第 6 模块，不能把原计划版本和当前安装声明混为一谈。

### 2. 设计初衷（为什么要做）

如果各模块只传递随意拼装的字典，前端可能把严重性写成 `urgent`，后端却只认识 `high`；一个 Agent 可能输出 `confidence=1.1`；审批页面可能传入空理由。只有程序运行到很后面时才发现问题，既难定位，也可能把错误数据长期留在数据库中。

这个任务建立了四层相互衔接的约定：

| 层次 | 本项目工具 | 解决的问题 | 不自动解决的问题 |
|---|---|---|---|
| 领域模型 | Pydantic | Python 对象的字段类型、枚举、范围和业务校验 | 不会自动创建数据库表，也不证明 Evidence ID 在数据库中存在 |
| 持久化映射 | SQLAlchemy ORM | Python 类与数据库表、列、外键和约束的对应关系 | 修改类后，已有数据库不会自动更新 |
| 结构迁移 | Alembic | 按版本执行建表、加列、回填和回退 | 自动生成的脚本仍需人工审阅，尤其要考虑已有数据 |
| 跨端契约 | OpenAPI → `openapi-typescript` → TypeScript | 把接口数据形状传递给前端，减少手写类型漂移 | TypeScript 编译通过不等于运行时数据合法，也不代表接口已实现 |

例如，`confidence` 在 Python 中是限制为 `0 <= confidence <= 1` 的浮点数，生成到前端后是 `number`。前端知道它是数字，但普通 TypeScript 类型不会自动禁止 `1.1`，因此运行时仍要由后端校验。数据库约束则防止绕过 Python 模型的写入破坏关键规则。

证据约束服务于项目的核心原则：所有安全结论必须引用有效 Evidence ID；证据不足时返回 `unknown`，不得编造来源或攻击类型。`source_scope="unknown"` 表示“尚无法确定来源范围”，不代表可以删除证据出处；当前 `AttackOrigin` 即使为 `unknown` 也要求非空 `evidence_ids`。

`dataset_labels` 只允许评分程序写入，生产调查结果默认保持空列表。它是评测真值，不是 Agent 从原始日志推导出的结论。正式评测时，Agent 只能读取原始日志，`labels/`、`attacks.log` 和攻击者真值只能由评分程序读取，否则相当于“拿着标准答案参加考试”。基础领域模型只设置空列表默认值；当前 Task 8 的 `AnalysisOutput` 另有校验器，会拒绝调查输出中的非空 `dataset_labels`。模型默认值、调查边界校验和评分侧的完整权限隔离仍应分别理解和验证。

### 3. 详细执行步骤

**第 1 步：先把错误输入写成测试，建立 TDD 的 Red 阶段。**

原文要求覆盖五类错误：非法严重性、置信度越界、缺失证据 ID、无效时间顺序、空审批理由。测试先描述“什么应该被拒绝”，实现尚未存在时应失败；随后实现最小必要逻辑，让测试通过，进入 Green 阶段。重构时继续运行这些测试，防止把原来拒绝的非法数据又放进来。

实际文件 `services/backend/tests/domain/test_models.py` 用 `import_module()` 动态加载模型。模型文件或模型类尚未实现时，测试会给出明确的失败提示，便于按步骤推进。当前测试还覆盖 `unknown` 来源、多标签攻击类型、完整调查状态、缺失 Evidence ID、错误 SHA-256、空告警事件列表、空处置动作、禁止关闭审批，以及验证结果枚举。

这里要区分“测试文件体现了 Red/Green 的设计方式”和“本次实际重演了历史 Red/Green”：本学习总结依据现有代码解释流程，没有删除模型制造失败，也没有声称已经重新执行历史测试过程。

**第 2 步：实现 Pydantic 模型、枚举和边界校验。**

在 `services/backend/src/evidencesoc/domain/models.py` 中定义模型，重点先固定以下规则：

| 约束对象 | 当前规则 |
|---|---|
| `Severity` | 只允许 `info`、`low`、`medium`、`high`、`critical` |
| `IncidentStatus` | 原文十个状态为 `received`、`triaged`、`collecting`、`analyzing`、`reconstructing`、`awaiting_approval`、`simulating`、`validating`、`completed`、`failed`；当前 Task 8 增加 `manual_review`（人工复核）和 `rejected`（审批拒绝） |
| `Incident.status` | 默认是 `IncidentStatus.RECEIVED`，调查状态必须来自该枚举 |
| `AttackOrigin.source_scope` | 只允许 `external`、`internal`、`unknown` |
| 两类攻击判断的 `confidence` | `Field(ge=0, le=1)`，上下界都包含 |
| `AttackClassification.attack_types` | `list[str]` 且至少 1 项，允许多个攻击标签 |
| `AttackClassification.dataset_labels` | `Field(default_factory=list)`，每个对象有独立的空列表默认值 |
| `AttackOrigin`、`AttackClassification`、`ResponsePlan`、`ValidationResult` 的 `evidence_ids` | 至少 1 项；这还不是对引用目标存在性的校验 |
| `AgentRun.finished_at` | 可以为空；不为空时必须大于或等于 `started_at` |
| `ApprovalDecision` | 只允许 `approved`、`rejected` |
| `ApprovalRecord.reason` | 去除首尾空白后不能为空，并返回清理后的理由 |
| `EvidenceItem.evidence_id` | 符合 `^EV-[0-9A-HJKMNP-TV-Z]{26}$`，即 `EV-<ULID>` 形状 |
| `content_sha256` | 符合 `^[0-9a-f]{64}$`，即 64 位小写十六进制字符串 |
| `Alert.event_ids` 与 `ResponsePlan.actions` | 不能为空列表 |
| `ResponsePlan.requires_approval` | `Literal[True] = True`，不能传入 `False` |
| `ValidationOutcome` | `success`、`failure`、`insufficient_evidence` |

不要把所有“未知”都统一成一个字符串。攻击来源范围使用 `unknown`，验证结果使用 `insufficient_evidence`；`primary_type`、`entry_host` 等允许 `None` 的字段表达“没有确定值”。这些含义不同，前后端必须保持一致。

当前 `SecurityEvent` 已包含 Task 5 增补的 `deduplication_key`、`index_status`、`indexed_at` 和 `index_error`，`EvidenceItem` 已包含 `event_id`。读当前代码时要知道它是在 Task 4 基础上继续演进的版本，不能把这些字段都说成最初公共契约已有。

**第 3 步：建立 12 张固定业务表和数据库约束。**

在 `services/backend/src/evidencesoc/persistence/tables.py` 中，通过 `Base(DeclarativeBase)` 收集表结构。`Mapped[...]` 描述 Python 属性类型，`mapped_column(...)` 描述数据库列，`ForeignKey(...)` 维护对象之间的引用关系。

| 固定表名 | 主要用途和关系 |
|---|---|
| `security_events` | 保存规范化事件；当前以 `(source, deduplication_key)` 保证去重唯一性 |
| `alerts` | 保存告警及关联事件 ID 列表 |
| `incidents` | 保存调查；`alert_id` 外键指向 `alerts.alert_id` |
| `evidence_items` | 保存证据；关联调查，当前还通过 `event_id` 外键关联原始事件 |
| `attack_steps` | 保存攻击链步骤；同一调查的 `sequence` 不重复 |
| `agent_runs` | 保存调查中每次 Agent 运行 |
| `tool_calls` | 保存工具名、参数、结果、成功状态、错误和时间；关联 Agent 运行 |
| `response_plans` | 保存模拟处置方案；数据库要求 `requires_approval = true` |
| `approvals` | 保存审批；限定决定值并禁止空白理由 |
| `validation_results` | 保存验证结果；关联处置方案 |
| `knowledge_chunks` | 保存知识内容、元数据和 `Vector()` 向量列 |
| `evaluation_runs` | 保存数据集名称、配置、指标及评测运行状态 |

数据库中的 `JSONB` 用来保存有结构但字段可变化的内容，例如原始事件、工具参数和 Evidence ID 列表。`DateTime(timezone=True)` 声明带时区时间列。知识表的 Python 属性叫 `chunk_metadata`，映射到的数据库列仍叫 `metadata`，避免与 ORM 自身的 `metadata` 属性混淆。

数据库检查约束与模型规则相互配合。例如，严重性枚举、调查状态、运行时间顺序、审批理由和必须审批标记都建立了相应 SQL 约束。当前 `evidence_ids` 是 JSONB 列表，并没有为其中每一个字符串建立数据库外键；这也是后续证据引用验证需要承担的职责。

`database.py` 负责创建数据库引擎和独立会话工厂。创建引擎并不立即连接数据库；会话工厂也不代表已执行 SQL。实际读写发生在业务代码使用会话执行语句和提交事务的时候。

**第 4 步：创建、审阅并验证 Alembic 迁移。**

`services/backend/alembic.ini` 指定 `script_location = %(here)s/migrations` 和 `prepend_sys_path = %(here)s/src`。这里的 `%(here)s` 指配置文件所在目录，使脚本路径跟配置文件绑定。

`services/backend/migrations/env.py` 在 Task 4 将 `Base.metadata` 交给 Alembic；当前已使用 `[Base.metadata, ApiBase.metadata]`，同时管理领域表和 Task 9 的 API 协调表。LangGraph 检查点管理表由 Checkpointer 管理，在迁移自动比较时予以排除，避免 Alembic 误把它们当作多余表删除。数据库连接读取顺序是环境变量 `DATABASE_URL`，然后仓库根目录 `.env`，再然后 `.env.example`。如果全部缺失则报错，不会自行猜测地址。示例 DSN 为 `postgresql+psycopg://evidencesoc:change-me-local-only@127.0.0.1:5432/evidencesoc`，其中 `change-me-local-only` 是本地示例占位密码。

Task 4–5 最初形成两个迁移版本，当前 Task 1–9 代码已扩展为以下四个连续版本：

1. `fbc66d4e9111_create_evidence_soc_schema.py`：`revision="fbc66d4e9111"`，`down_revision=None`，创建 Task 4 的 12 张表；回退时按依赖顺序删除这些表。
2. `f311d6238878_add_ingestion_trace_fields.py`：`revision="f311d6238878"`，`down_revision="fbc66d4e9111"`，是 Task 5 对去重、索引状态和证据关联的增量修改。
3. `a8f02c68d901_add_investigation_terminal_states.py`：`revision="a8f02c68d901"`，`down_revision="f311d6238878"`，加入 Task 8 的 `manual_review`、`rejected` 状态。
4. `b6d091c3e217_add_durable_api_coordination.py`：`revision="b6d091c3e217"`，`down_revision="a8f02c68d901"`，加入 Task 9 的四张 API 协调表，保存告警载荷哈希、幂等键、调查元数据和可重放事件。

第二个迁移展示了重要的已有数据处理方式：先新增可空列，回填旧记录，再设置非空和外键。证据关联先尝试查询参数中的 `matched_event_id` / `event_id`，再尝试来源、观察时间和哈希的唯一匹配；仍无法确定关联时明确报错，不能随意选一条事件。历史无 external ID 的重复事件通过 `ROW_NUMBER() OVER` 和 `:legacy:` 后缀保留，避免直接建立唯一约束时冲突。

原文要求执行“升级 → 回退一个版本 → 再升级”。在 Task 5 结束时从 `head` 回退 `-1` 会回到 Task 4 初始结构；当前四个版本下，从 `head` 回退 `-1` 会撤销 Task 9 的 API 协调表，回到 `a8f02c68d901`；不能据此声称重新验证了从空库创建全部表。空库验证应单独使用可重建的测试数据库。`knowledge_chunks.embedding` 使用 vector 类型，还需要 Task 3 的 `infra/postgres/init.sql` 已执行 `CREATE EXTENSION IF NOT EXISTS vector;`；初始业务迁移本身没有创建该扩展。

**第 5 步：导出 OpenAPI，并生成前端 TypeScript 类型。**

FastAPI 通常从实际路由使用的模型生成 OpenAPI。Task 4 时许多业务路由尚未建立，为提前交付类型契约，`openapi.py` 定义 `EvidenceSOCApp(FastAPI)`，把 10 个核心模型及其枚举合并到 `components.schemas`。`main.py` 使用这个应用类，接口文档可以在 `/openapi.json` 输出这些定义。

随后用原定 `openapi-typescript` 命令生成 `apps/web/src/lib/api/generated.ts`，再用 `tsc --noEmit` 检查类型。生成文件顶部明确写着不要直接手工修改；模型变化后的正确流程是更新源模型、重新导出并生成类型、审阅差异、再次编译。

原准备书的公共 REST 契约如下。Task 4 时这张表还是目标接口清单；当前 Task 9 已注册相应业务路由及 `/health/ready`。原约定中的 `{id}` 在实际代码中展开为 `{incident_id}`、`{investigation_id}`、`{plan_id}`、`{evaluation_id}`，含义一致。结果读取接口存在不等于已经完成后续全部实验。

| 原文方法与路径 | 原文用途 |
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

公共契约还固定了 9 种 SSE 事件：`investigation.started`、`agent.started`、`evidence.added`、`agent.completed`、`approval.required`、`decision.recorded`、`validation.completed`、`investigation.failed`、`investigation.completed`。这些在 Task 4 是工作流约定，在 Task 8–9 才通过节点事件、持久化与流接口落实。

后续只读 MCP 工具约定为 `search_security_events(time_from, time_to, filters, limit=100)`、`get_alert_context(alert_id, before_seconds=900, after_seconds=900)`、`lookup_attack_technique(query, limit=10)`。硬限制仍是事件返回 `limit <= 200`、告警上下文单侧窗口 `<= 900` 秒、ATT&CK 返回 `<= 10` 条、每次调用超时 10 秒且最多重试两次。Task 4 提供它们将使用的类型基础，不等于已经实现这些工具。

**第 6 步：验证结果后提交。**

原文提交命令是 `git add services/backend apps/web/src/lib/api/generated.ts` 和 `git commit -m "feat: add domain models and database schema"`。真实仓库已有 `1cc8e31 feat: add evidence SOC data model and migrations` 与 `40ac226 feat: complete task 4 OpenAPI contract` 等相关提交；应以真实记录为准，不要把准备书中的建议提交消息改写成历史事实。

### 4. 关键代码/命令示例

以下代码以现有实现的核心片段为依据，省略处会注明；学习示例中的注释用于解释关键行，不要求复制回业务文件。

**示例 A：攻击来源和多标签分类如何表达“可验证的判断”。**

```python
from datetime import datetime  # 表达观察时间，不把时间当任意字符串处理。
from typing import Literal  # 用有限字面值约束来源范围。
from pydantic import BaseModel, Field  # BaseModel 提供校验；Field 补充范围和长度约束。

class AttackOrigin(BaseModel):  # 描述来源判断，而不是数据库表。
    observed_source_ip: str | None  # 无法确定观察到的源 IP 时允许传 None。
    entry_host: str | None  # 无法确认入口主机时不强行编造值。
    entry_service: str | None  # 无法确认入口服务时允许 None。
    first_seen_at: datetime | None  # 首次观察时间可以暂时未知。
    source_scope: Literal["external", "internal", "unknown"]  # unknown 是合法状态。
    confidence: float = Field(ge=0, le=1)  # 置信度必须在闭区间 [0, 1]。
    evidence_ids: list[str] = Field(min_length=1)  # 至少引用一项证据。

class AttackClassification(BaseModel):  # 一次判断可以同时包含多个攻击标签。
    primary_type: str | None  # 主类型可以未知，但不是替代全部标签的单一枚举。
    attack_types: list[str] = Field(min_length=1)  # 多标签列表且至少有一项。
    dataset_labels: list[str] = Field(default_factory=list)  # 默认空；仅评分程序应写入。
    attack_phase: str | None  # 当前攻击阶段可以尚未确认。
    technique_ids: list[str] = Field(default_factory=list)  # ATT&CK 技术 ID 可以暂为空。
    confidence: float = Field(ge=0, le=1)  # 分类置信度同样限制为 0 到 1。
    evidence_ids: list[str] = Field(min_length=1)  # 分类必须带证据出处。
```

`str | None` 表示值允许为 `None`，并不自动表示创建对象时可以省略该字段；是否可以省略还要看有没有默认值。上述 `entry_host` 允许传 `None`，但未设置默认值，构造对象时仍应明确提供。

**示例 B：对多个字段一起校验，与对单个字段校验。**

```python
# 以下是 AgentRun 类中的实际校验方法，需放在相应类内部。
@model_validator(mode="after")  # 所有字段解析完成后，比较两个时间字段。
def validate_time_order(self) -> Self:  # 校验成功后返回当前模型对象。
    if self.finished_at is not None and self.finished_at < self.started_at:  # 仅当已经结束时比较结束时间与开始时间。
        raise ValueError("finished_at must be greater than or equal to started_at")  # 拒绝倒序。
    return self  # 允许未结束的运行，以及结束时间等于开始时间的情况。

# 以下是 ApprovalRecord 类中的实际校验方法，需放在相应类内部。
@field_validator("reason")  # 此规则只针对审批理由字段。
@classmethod  # Pydantic 字段校验器使用类方法形式。
def validate_reason(cls, value: str) -> str:  # 接收并规范化审批理由。
    cleaned_value = value.strip()  # 清理两端空白。
    if not cleaned_value:  # 清理后为空说明没有提供有效理由。
        raise ValueError("approval reason must not be blank")  # 空字符串和全空白都拒绝。
    return cleaned_value  # 模型中保留清理后的审批理由。
```

片段依赖 `models.py` 已导入的 `Self`、`field_validator` 和 `model_validator`，它们不是可单独运行的完整文件。

**示例 C：失败测试必须确认失败发生在正确字段。**

```python
import pytest  # 提供异常断言能力。
from pydantic import ValidationError  # Pydantic 用此异常报告输入不合法。
from evidencesoc.domain.models import AttackOrigin  # 测试实际领域模型。

def test_confidence_rejects_above_one() -> None:  # 定义超出置信度上界时的拒绝行为。
    with pytest.raises(ValidationError) as exc_info:  # 预期构造对象时拒绝输入。
        AttackOrigin(  # 使用其余合法字段构造待验证对象。
            observed_source_ip=None,  # 其余字段都提供合法值，避免其他错误干扰测试。
            entry_host=None,  # 没有确定入口主机是合法情况。
            entry_service=None,  # 没有确定入口服务是合法情况。
            first_seen_at=None,  # 首次观察时间允许未知。
            source_scope="unknown",  # unknown 本身合法。
            confidence=1.1,  # 这是本测试唯一故意设置的错误。
            evidence_ids=["EV-01ARZ3NDEKTSV4RRFFQ69G5FAV"],  # 满足非空证据列表要求。
        )
    assert any(error["loc"] == ("confidence",) for error in exc_info.value.errors())  # 确认拒绝原因。
```

这是参考现有测试写法整理的学习示例，未写入测试文件。相比只检查“有异常”，检查 `error["loc"]` 可以避免测试因为无关字段缺失而误通过。当前非法严重性测试没有提供后来新增的必填 `deduplication_key`，又只断言有 `ValidationError`，因此仅凭它通过，不能单独证明严重性校验有效。

**示例 D：ORM、数据库检查约束和会话工厂。**

```python
# 摘自 ResponsePlanTable 的相关定义；其余列省略。
__tablename__ = "response_plans"  # 这是 PostgreSQL 实际表名。
__table_args__ = (  # 集中声明这张表的数据库约束。
    CheckConstraint(  # 让真实数据库也检查必须审批这一规则。
        "requires_approval = true",  # 即使绕过 Pydantic，数据库也拒绝关闭审批。
        name="ck_response_plans_requires_approval",  # 给约束命名，便于定位与迁移维护。
    ),  # 结束这个命名检查约束的定义。
)
requires_approval: Mapped[bool] = mapped_column(Boolean, default=True)  # ORM 写入时默认需要审批。

# 摘自 database.py；完整文件已导入 SQLAlchemy 所需类型。
def create_database_engine(url: str) -> Engine:  # 教学简化：创建引擎，省略当前文件中的有界连接与语句超时钩子。
    if not url.strip():  # 在尝试使用数据库之前拒绝空连接字符串。
        raise ValueError("database URL must not be blank")  # 对空配置尽早报错，避免延迟到连接阶段。
    return create_engine(url, pool_pre_ping=True)  # 取连接时先检查连通性，创建引擎本身不连接。

def create_session_factory(engine: Engine) -> sessionmaker[Session]:  # 建立可为不同请求独立创建会话的工厂。
    return sessionmaker(  # 配置 SQLAlchemy 会话的连接与对象生命周期。
        bind=engine,  # 会话使用此引擎连接数据库。
        autoflush=False,  # 避免某些查询前自动 flush；提交时仍会 flush 待写数据。
        expire_on_commit=False,  # 提交后保留已加载属性，减少隐式重新查询。
    )
```

`default=True` 是 ORM 默认值，不等于给数据库设置了 `server_default`。数据库检查约束只能保证传入值符合规则；直接 SQL 插入时仍需考虑列是否提供默认值及是否允许空值。

**示例 E：迁移脚本把 Python 定义变成真实数据库变更。**

```python
# 初始迁移 fbc66d4e9111 的版本关系。
revision: str = "fbc66d4e9111"  # 当前迁移的唯一版本号。
down_revision = None  # 没有前一个业务版本，是迁移链起点。

# 摘自初始迁移 upgrade() 的 alerts 建表操作；使用脚本现有 sa、op、postgresql 导入。
op.create_table(  # 执行真实建表操作；这里是初始迁移的节选。
    "alerts",  # 创建真实表，不只是声明一个 Python 类。
    sa.Column("alert_id", sa.String(length=64), nullable=False),  # 告警 ID 不能为空。
    sa.Column("title", sa.Text(), nullable=False),  # 告警标题。
    sa.Column("severity", sa.String(length=16), nullable=False),  # 保存严重性字符串。
    sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),  # 带时区创建时间。
    sa.Column("event_ids", postgresql.JSONB(astext_type=sa.Text()), nullable=False),  # 关联事件列表。
    sa.CheckConstraint(  # 定义 PostgreSQL 对严重性取值的检查约束。
        "severity IN ('info', 'low', 'medium', 'high', 'critical')",  # 数据库重复守住枚举规则。
        name="ck_alerts_severity",  # 明确约束名称。
    ),  # 结束严重性约束的定义。
    sa.PrimaryKeyConstraint("alert_id"),  # 主键保证告警 ID 唯一且不可为空。
)
```

迁移命令必须保留原文，便于对照准备书：

```powershell
# 原文 Step 4：升级到最新迁移。
uv run --project services/backend alembic upgrade head
# 原文 Step 4：回退一个版本，会撤销相应结构变更。
uv run --project services/backend alembic downgrade -1
# 原文 Step 4：重新升级到最新迁移。
uv run --project services/backend alembic upgrade head
```

但 `uv run --project services/backend` 选择的是 Python 项目，不应依赖它替 Alembic 查找任意目录下的配置。当前仓库配置在 `services/backend/alembic.ini`，从 `D:\传智杯` 根目录执行时，准确的变体如下。它们是复现命令示例，本次编写总结没有执行任何升级或回退；回退含删列或删表操作，只适合本任务的可重建测试数据库。

```powershell
Set-Location "D:\传智杯"  # 当前实际仓库根目录；准备书早期环境路径为 D:\桌面\传智杯。
uv run --project services/backend alembic -c services/backend/alembic.ini upgrade head  # 明确配置位置。
uv run --project services/backend alembic -c services/backend/alembic.ini downgrade -1  # 只回退一个版本。
uv run --project services/backend alembic -c services/backend/alembic.ini upgrade head  # 再次恢复最新结构。
```

**示例 F：显式发布核心 schema，再生成 TypeScript。**

```python
# 摘自 EvidenceSOCApp.openapi()；前面已通过 get_openapi(..., routes=self.routes) 得到 schema。
model_inputs = [(model, "validation") for model in DOMAIN_MODELS]  # 把 10 个领域模型作为输入校验契约。
_, bundled_schema = models_json_schema(  # 把领域模型汇总为相互引用的 JSON Schema。
    model_inputs,  # 生成模型以及它们引用的枚举定义。
    ref_template="#/components/schemas/{model}",  # 让引用指向 OpenAPI components 位置。
)
definitions = bundled_schema.get("$defs", {})  # 取出 Pydantic 汇总的模型定义。
components = schema.setdefault("components", {})  # 兼容还没有 components 的基础文档。
schemas = components.setdefault("schemas", {})  # 取得所有可复用 schema 的容器。
schemas.update(definitions)  # 合并数据结构，不会因此创建业务路由。
self.openapi_schema = schema  # 缓存文档，避免每次请求都重新生成。
return schema  # 返回可由 /openapi.json 获取的契约。
```

```powershell
# 补充前置操作：在一个终端启动后端，让本机 8000 端口能提供 OpenAPI JSON。
uv run --project services/backend uvicorn evidencesoc.main:app --host 127.0.0.1 --port 8000

# 原文 Step 5：在另一个终端，从服务导出类型，路径相对于 apps/web。
pnpm --dir apps/web exec openapi-typescript http://127.0.0.1:8000/openapi.json -o src/lib/api/generated.ts
# 原文 Step 5：只做类型检查，不输出 JavaScript 文件。
pnpm --dir apps/web exec tsc --noEmit
```

当前生成文件里的代表性类型如下；这里添加了解释注释，文件本身应继续由工具维护：

```typescript
// 以下字段摘自 generated.ts 的 components.schemas.AttackOrigin。
source_scope: "external" | "internal" | "unknown"; // 后端 Literal 转成前端联合类型。
confidence: number; // Python float 对应 number；[0,1] 的运行时范围仍需后端校验。
evidence_ids: string[]; // 前端知道这是字符串数组，但不会自动查询每项证据是否存在。

// 以下字段摘自 generated.ts 的 components.schemas.AttackClassification。
attack_types: string[]; // 保留多标签结构，不退化成单一字符串。
dataset_labels?: string[]; // 可省略时由后端提供空列表；类型本身不控制谁有权写入。

// 以下字段摘自 generated.ts 的 components.schemas.ResponsePlan。
requires_approval: true; // Literal[True] 生成常量类型，不能赋值 false。

// 前端使用示例：取出已经生成的 DTO 类型，而不是手写另一个同名接口。
type IncidentDTO = components["schemas"]["Incident"]; // 示例应在已导入 components 的文件中使用。
```

`query`、`raw`、`actions` 内部开放字典在生成文件中使用 `[key: string]: unknown`。`unknown` 表示使用值之前要缩小类型范围，不能把它和任意操作都放行的 `any` 混淆。

**示例 G：模型和元数据验证，以及原文提交命令。**

```powershell
Set-Location "D:\传智杯"  # 以下测试路径都以仓库根目录为基准。
# 补充验证：检查领域模型、ORM 元数据和 OpenAPI 的核心 schema。
uv run --project services/backend pytest services/backend/tests/domain/test_models.py services/backend/tests/persistence/test_tables.py services/backend/tests/test_openapi_contract.py -v
# 补充验证：Task 5 的迁移脚本顺序测试使用记录操作对象，不会连接真实数据库。
uv run --project services/backend pytest services/backend/tests/persistence/test_ingestion_migration.py -v
# 原文 Step 6：暂存后端和生成的前端类型；实际提交前应审阅暂存差异。
git add services/backend apps/web/src/lib/api/generated.ts
# 原文 Step 6：示范提交信息；不代表真实仓库历史一定使用该消息。
git commit -m "feat: add domain models and database schema"
```

### 5. 核心文件说明

以下路径均以 `D:\传智杯` 为根目录，保留准备书约定的路径，方便查找原实现。

| 文件或目录 | 核心职责 | 阅读时关注什么 |
|---|---|---|
| `docs/EvidenceSOC-project-preparation.md` | Task 4 与公共契约的原始要求 | 区分原计划、当前实现和后续任务 |
| `services/backend/src/evidencesoc/domain/models.py` | Pydantic DTO 与状态枚举 | `Field`、字段校验器、模型校验器、默认值 |
| `services/backend/src/evidencesoc/persistence/tables.py` | 12 张业务表的 ORM 映射 | 表名、列、外键、唯一约束、检查约束、JSONB 和向量类型 |
| `services/backend/src/evidencesoc/persistence/database.py` | 引擎与会话工厂 | 连接创建时机、事务会话配置 |
| `services/backend/alembic.ini` | Alembic 配置入口 | `script_location`、`prepend_sys_path` 和配置位置 |
| `services/backend/migrations/**` | 原计划的迁移目录路径规范，包含运行环境、模板与各版本脚本 | `**` 表示该目录及其子目录，下面逐项列出当前关键文件 |
| `services/backend/migrations/env.py` | 连接配置与迁移运行环境 | `DATABASE_URL` 读取顺序、`target_metadata`、在线与离线模式 |
| `services/backend/migrations/versions/fbc66d4e9111_create_evidence_soc_schema.py` | 初始业务表迁移 | `upgrade()` 创建结构，`downgrade()` 反向撤销 |
| `services/backend/migrations/versions/f311d6238878_add_ingestion_trace_fields.py` | Task 5 增量迁移 | 先回填再收紧约束，不能把旧数据关联到猜测的事件 |
| `services/backend/migrations/script.py.mako` | 新迁移脚本模板 | 模板与实际已执行迁移文件不是一回事 |
| `services/backend/tests/domain/test_models.py` | 验证 DTO 和业务边界 | 错误输入是否因预期原因被拒绝，正常边界是否接受 |
| `services/backend/tests/persistence/test_tables.py` | 检查表、列、外键和约束名称 | 验证的是 `Base.metadata`，不是实时数据库 |
| `services/backend/tests/persistence/test_ingestion_migration.py` | 检查增量迁移顺序和回填 SQL | 使用 `RecordingOperations`，不证明 SQL 已在 PostgreSQL 成功运行 |
| `services/backend/tests/persistence/test_event_repository.py` | Task 5 仓储层单元测试 | 使用记录会话检查 SQL、提交和幂等逻辑 |
| `services/backend/tests/persistence/test_event_search.py` | Task 5 搜索层单元测试 | 使用模拟客户端验证文档序列化和请求参数 |
| `services/backend/src/evidencesoc/openapi.py` | 显式将领域模型放入 OpenAPI | `DOMAIN_MODELS`、模型引用路径和缓存 |
| `services/backend/src/evidencesoc/main.py` | 创建 FastAPI 应用并挂载路由 | 当前已有健康、业务路由、调查恢复和审计；Task 2 时先建立最小健康接口 |
| `services/backend/tests/test_openapi_contract.py` | 确认 10 个核心 DTO，并核对 Task 9 的结果、错误和 SSE 契约 | 静态契约检查不代替每个字段的业务校验、真实服务调用或生成文件同步检查 |
| `apps/web/src/lib/api/generated.ts` | 从 OpenAPI 生成的前端类型 | 不手工修改；模型变化后需重新生成 |

### 6. 完成验证标准

**原文要求的验收标准应完整保留：**

1. 五类非法输入测试通过：非法严重性、置信度越界、缺失证据 ID、无效时间顺序、空审批理由。
2. 所有调查状态来自 `IncidentStatus`；来源支持 `unknown`；攻击类型支持多标签。
3. 12 张指定业务表及其关系可从空库建立。
4. 原文升级、回退、再升级三条命令成功，最终所有业务表存在。
5. OpenAPI 可用于生成前端类型，`tsc --noEmit` 成功，核心 DTO 没有被 `any` 替代。
6. 验证后提交真实代码变更，保留可追踪历史。

**截至本次静态核查，以下差异或证据边界必须明确：**

| 核查项 | 当前代码事实 | 对学习和验收的影响 |
|---|---|---|
| 核心模型和业务表 | 10 个核心 Pydantic 模型、初始 12 张领域业务表均有定义，Task 9 另有四张 API 协调表 | 领域表、API 协调表、LangGraph 检查点表与 `alembic_version` 管理表职责不同；存在定义不等于真实库已迁移 |
| OpenAPI schema | `DOMAIN_MODELS` 明确加入核心 DTO；当前契约测试还检查 Task 9 的响应模型、统一错误体及 SSE 内容类型 | 契约测试保护结构，业务流程与真实网络行为仍需单独测试 |
| REST 路由 | 当前应用和生成文件的 `paths` 已包含 Task 9 的告警、事件、调查、审批、结果读取、SSE 与健康接口 | Task 4 先定义约定，Task 9 再提供行为；Task 10 的页面建设仍是另一层交付 |
| 前端类型同步 | 当前 `generated.ts` 已含 `EvidenceItem.event_id`，以及 `SecurityEvent.deduplication_key`、`index_status`、`indexed_at`、`index_error` | 旧版缺字段的问题已不适用于当前文件；以后修改仍需重新生成并审阅差异 |
| `dataset_labels` 权限 | 基础领域模型允许传入非空列表；Task 8 的 `AnalysisOutput` 拒绝调查输出中的非空列表 | 领域默认值、调查边界校验、完整评测真值隔离是不同保障，不能互相替代 |
| Evidence ID 的有效性 | 基础模型校验 ID 形状和非空列表；Task 7–8 增加当前授权证据与允许知识块的引用核对 | 合法 ID 形状不证明证据存在；存在的引用也不自动证明语义上支持该结论 |
| 非法严重性测试 | 当前测试缺少后来新增的必填 `deduplication_key`，只断言发生 `ValidationError` | 可能被无关缺字段错误掩盖，应检查错误字段；本次只记录，不修改业务或测试 |
| 置信度测试覆盖 | 现有测试显式检查大于 1 的输入，模型本身同时声明下界 0 | 不能把已有用例描述成已经全面覆盖负值及恰好 0、1 等边界 |
| 迁移回退范围 | 当前迁移链有四个版本，最新为 `b6d091c3e217` | `downgrade -1` 撤销 API 协调表，不能替代独立空库验收，并会影响已保存的调查与 SSE 数据 |
| vector 扩展 | 由 Task 3 初始化 SQL 创建，初始业务迁移直接使用 vector 列类型 | “空库可迁移”需明确基础扩展已经可用这一前置条件 |
| 持久化测试 | 元数据、记录会话、模拟客户端和记录迁移操作均可离线验证 | 单元测试通过不证明数据库和 OpenSearch 上的真实往返成功 |
| Python `pgvector` 版本 | 准备书固定 `0.5.0`，当前 `pyproject.toml` 为 `0.3.6` | 与 PostgreSQL 扩展 `0.8.6` 属于不同版本体系，应分别说明 |
| TypeScript 版本 | 原计划 `typescript@7.0.2`；当前 `typescript` 为 `npm:@typescript/typescript6@6.0.2`，另有 `@typescript/native` 为 `npm:typescript@7.0.2` | 不应把原文 `tsc --noEmit` 自动解释为调用原生 7.0.2；实际命令解析及版本需结合环境核实 |

本模块完成的是源码、测试和迁移脚本的阅读核对。本次没有启动服务重新生成前端类型，没有执行数据库升降级，也没有把测试文件存在或历史提交存在写成“本次运行全部通过”。验收时应分别记录命令、执行目录、使用的数据库、输出结果和日期。

### 7. 初学者学习要点

1. **先分清四层职责。** Pydantic 检查数据对象，ORM 描述数据库映射，Alembic 改变实际数据库，OpenAPI/TypeScript 传递前后端契约。遇到错误时先判断它发生在哪一层。
2. **测试不仅要报错，还要因正确原因报错。** 让无关字段都合法，并检查异常定位字段，可以避免“测试绿了但功能没有被测到”。
3. **未知是合法的业务状态。** `unknown`、`None` 和 `insufficient_evidence` 分别用于明确的字段和语境；保留证据出处比勉强填一个结论更可靠。
4. **多标签和主标签可以共存。** `primary_type` 提供主要概括，`attack_types` 保留完整类型组合，不要为了显示方便把列表压成唯一分类。
5. **默认值不等于权限。** `dataset_labels=[]` 不会自动限制评分程序以外的写入；字段声明、权限检查和数据源隔离是不同层面的工作。
6. **约束需要理解其强度。** `min_length=1` 只保证列表非空，正则只保证字符串形状，外键才约束数据库引用目标。不同机制不能相互代替。
7. **迁移必须考虑已经存在的数据。** 加非空列通常需要先允许为空、回填、验证、再收紧约束；遇到无法可靠关联的数据应明确失败。
8. **生成文件会落后。** 后端修改后需要重新生成前端类型。`tsc --noEmit` 检查当前文件能否编译，却不会自动发现服务器契约已经变化。
9. **schema 不是路由。** 在 `/openapi.json` 看到 `ResponsePlan` 并不意味着审批接口可调用；要分别查看 `components.schemas` 和 `paths`。
10. **记录实际版本和验证证据。** 原准备书、依赖声明、当前安装、迁移文件、数据库实际状态是不同证据来源。清楚区分它们，才能准确复现已完成任务。

## Task 5：日志接入和证据链

### 1. 任务目标

Task 5 交付可幂等导入、可恢复双存储写入、可由 `EvidenceItem` 回溯原始 `SecurityEvent` 的日志证据链。

原文接口约定如下：

- **输入：** JSON 或 JSONL 日志；JSONL 是“一行一个 JSON 对象”的日志格式。
- **输出：** `SecurityEvent` 与 `EvidenceItem`。
- **证据编号：** `EV-<ULID>`，即 `EV-` 加 26 位 ULID；当前事件编号相应使用 `SE-<ULID>`。
- **幂等键：** 有外部 ID 时使用 `(source, external_id)` 的业务含义；当前实现把第二部分编码为 `deduplication_key="id:<external_id>"`，数据库唯一约束实际落在 `(source, deduplication_key)`。没有 external ID 时，去重键为 `sha256:<规范化事件内容哈希>`。
- **双存储：** OpenSearch 索引固定为 `security-events-v1`；PostgreSQL 保存业务 ID、状态、来源、哈希及可追溯字段，OpenSearch 保存原始内容和检索字段。

任务完成后，任意 Evidence ID 都应能定位到对应事件、来源、查询参数、观察时间、摘要与内容哈希。这里的“可定位”不只是页面上显示一段模型生成文字，而是程序能沿 `evidence_id → event_id → PostgreSQL/OpenSearch 事件` 回溯，并重新校验内容。

### 2. 设计初衷（为什么要做）

**日志先规范化，是为了让不同来源可以进入同一套业务流程。** WAF、Nginx 和应用程序可能使用不同大小写、字段顺序和时间写法。如果调查逻辑直接依赖每一种原始格式，新增一个数据源就要修改全部上层功能。规范化层把来源和事件类型整理为小写，把带时区时间转换为 UTC，同时保留原始对象，供后续检索与审计。

**幂等导入，是为了让安全系统可以放心重试。** 日志采集、网络连接和外部服务都可能失败。如果同一文件重放一次就多出一批事件，告警数量、攻击时间线和统计指标都会被放大。幂等性表示同一个逻辑请求执行一次或多次，最终业务效果一致。当前实现遇到完全相同的事件时返回已有 `event_id`；如果相同来源和 external ID 对应的内容变了，则抛出冲突，而不是把修改过的内容悄悄当成同一事件。

**PostgreSQL 与 OpenSearch 分工，兼顾业务一致性和日志检索。** PostgreSQL 适合保存事件身份、状态、关系和证据记录；OpenSearch 适合按 IP、主机、服务、消息、标签和 HTTP 字段搜索。两边都保留内容哈希，使证据生成时可以核对“业务库中的事件”和“搜索索引中的文档”是否仍是同一份内容。

**双存储不是一笔跨系统原子事务。** 当前流程先在 PostgreSQL 注册事件，再向 OpenSearch 建索引。OpenSearch 失败时，PostgreSQL 中的事件仍然存在，并被标记为 `failed`；`retry_pending_events()` 后续重试同一个 `event_id`。这是一种可恢复的一致性设计：允许短暂不同步，但明确记录状态并提供补偿路径。若不记录失败状态，系统可能把“数据库写入成功”误报为“日志已经可以搜索”。

**哈希建立的是内容完整性线索，不是来源真实性证明。** SHA-256 可以发现内容变化；它不能单独证明日志一定来自可信设备，也不能证明采集前没有被修改。可信时间源、传输认证、访问控制和不可篡改归档仍需由更完整的安全设计承担。

**证据对象保存查询上下文，是为了支持复核。** `EvidenceItem` 顶层保存 `event_id`、`query`、`observed_at`、`source`、摘要和 `content_sha256`；`matched_event_id` 是 `query` 内部的附加键，不是顶层字段。这样审阅者能够回答“这条证据是通过什么条件找到的、命中了哪条事件、当时看到的内容是否和现在一致”。这正是 EvidenceSOC 中“结论必须引用有效 Evidence ID”的基础。

如果不完成这一任务，后续 Agent 可能读取重复、格式不一或已被修改的数据；OpenSearch 与业务数据库也可能彼此指向不同内容。最严重的结果是系统给出看似完整的攻击判断，却没有可复查的事实链。

### 3. 详细执行步骤

1. **Red：先写解析、去重与哈希的失败测试。** 测试先描述行为：合法 JSON/JSONL 能解析并保留来源文件与行号；空文件、非法 JSON、重复键、非对象记录、非 UTF-8 内容和不支持的扩展名必须拒绝；字段顺序不应改变规范哈希，内容变化必须改变哈希；来源为空或时间无效必须拒绝；同一文件重复导入只保留一个事件。此时缺少实现，测试应因目标模块、函数或行为不存在而失败。只有这种“失败原因正好对应未实现需求”的结果才是有效 Red。
2. **Green：实现严格的 JSON/JSONL 解析。** `parse_log_file()` 根据扩展名选择 JSON 或 JSONL；使用 `utf-8-sig` 兼容 UTF-8 BOM；JSONL 跳过空白行但保留真实行号；解码阶段主动拒绝重复键和 `NaN`、`Infinity` 等非有限数。错误对象包含稳定的错误码、文件路径和行号，方便排查坏数据。
3. **Green：规范化字段并计算稳定 SHA-256。** `canonical_json()` 对键排序、使用紧凑分隔符、保留 Unicode，并禁止非有限数，再编码为 UTF-8 字节。相同逻辑对象即使字段顺序不同，也得到相同哈希。`normalize_record()` 清理 `source`、`external_id`、`event_type`，要求 `observed_at` 和 `ingested_at` 带时区并统一到 UTC，同时保留 `raw`。
4. **Green：生成带类型前缀的 ULID。** `new_event_id()` 生成 `SE-<ULID>`，`new_evidence_id()` 生成 `EV-<ULID>`。ULID 将毫秒时间放在高位，因此通常可按生成时间排序；随机部分降低同一毫秒冲突概率。格式测试、唯一性测试和时间排序测试共同验证这一约定。
5. **Green：在 PostgreSQL 实现数据库级幂等。** `EventRepository.register()` 使用 PostgreSQL `INSERT ... ON CONFLICT DO NOTHING` 和命名唯一约束 `uq_security_events_source_deduplication_key`。若已有内容哈希相同，复用已有事件；若相同去重键对应不同哈希，抛出 `EventContentConflictError`。数据库约束是并发条件下的最终防线，不能只在 Python 中“先查后写”。
6. **Green：将可检索文档写入 OpenSearch。** 文档 ID 固定使用 `event_id`；文档同时保留 `raw_event` 和规范字段，并展开常用检索字段：`source_ip`、`destination_ip`、`source_port`、`destination_port`、`host`、`service`、`message`、`tags`、`http`。目标索引由配置 `opensearch_index="security-events-v1"` 指定。
7. **Green：记录索引状态并提供重试。** 新事件默认 `pending`；OpenSearch 写入成功后标为 `indexed` 并写入 `indexed_at`；外部依赖异常时标为 `failed` 并保存 `index_error`，继续处理后续事件。`retry_pending_events(limit=100)` 读取 `pending` 和 `failed` 事件，以原 `event_id` 重试，避免补偿过程制造新身份。
8. **Green：实现证据生成前的双端核验。** `EvidenceService` 先分别读取 PostgreSQL 事件与 OpenSearch 文档；核对请求的 `event_id`、两端原始内容的重新计算哈希、两端保存的哈希，以及来源、external ID、去重键、观察时间、严重性和事件类型。整批事件全部验证后才写入证据，避免一批证据写到一半才发现后面有篡改。
9. **补充迁移，使数据库承载追溯字段。** Task 5 增加迁移 `f311d6238878_add_ingestion_trace_fields.py`：为事件表增加 `deduplication_key`、`index_status`、`indexed_at`、`index_error`，为证据表增加非空 `event_id` 外键；迁移先回填旧数据，再增加非空和唯一约束，避免旧行直接违反新结构。
10. **用样例和测试完成验证，再记录真实提交。** `data/samples/sql-injection.jsonl` 与 `data/samples/benign-web.jsonl` 提供可公开演示数据。先运行原计划的 ingestion 测试，再运行证据、持久化和真实双存储集成测试；确认结果后再提交。当前 Git 历史中对应提交为 `4fcd47a feat: add auditable event ingestion`，这是真实历史事实；原计划的提交命令仍保留在下一模块中用于说明预期操作。

### 4. 关键代码/命令示例

#### 4.1 Red：用测试先表达规范哈希和幂等行为

下面节选自当前测试，注释解释每个关键断言。编写这些测试时应先运行并确认它们因实现缺失而失败，再进入 Green。

```python
def test_content_change_changes_hash() -> None:  # 定义“内容变化必须改变哈希”的测试。
    module = normalize_module()  # 加载待实现的规范化模块。
    calculate_hash = module.calculate_content_sha256  # 取得实际哈希函数。

    first = {"source": "nginx", "status": 200}  # 构造第一份原始事件。
    second = {"source": "nginx", "status": 500}  # 只修改一个有业务意义的字段。

    assert calculate_hash(first) != calculate_hash(second)  # 内容不同必须得到不同摘要。
```

```python
first_report = service.import_file(log_path)  # 第一次导入，预期创建并索引事件。
duplicate_report = service.import_file(log_path)  # 重复导入同一个文件。

assert first_report.inserted == 1  # 第一次只新增一条事件。
assert duplicate_report.inserted == 0  # 第二次不得再新增事件。
assert duplicate_report.duplicated == 1  # 报告应明确说明识别到重复事件。
assert duplicate_report.event_ids == [EVENT_ID_1]  # 重复导入复用首次持久化的 ID。
```

#### 4.2 Green：解析文件并保留定位信息

```python
@dataclass(frozen=True, slots=True)  # 不可变且节省实例内存的解析结果。
class ParsedLogRecord:  # 定义日志解析结果的容器。
    raw: dict[str, Any]  # 保留原始 JSON 对象，避免丢失审计信息。
    source_path: str  # 记录来自哪个文件。
    line_number: int  # 记录位于哪一行，错误可精确定位。


def parse_log_file(path: Path) -> list[ParsedLogRecord]:  # 解析指定日志文件并返回带定位信息的记录。
    suffix = path.suffix.casefold()  # 扩展名转小写，统一处理 .JSONL 等写法。
    if suffix not in {".json", ".jsonl"}:  # 只接受原计划允许的两种格式。
        raise LogParseError(...)  # 使用结构化错误拒绝不支持的格式。

    text = path.read_text(encoding="utf-8-sig")  # 按 UTF-8 读取并兼容文件头 BOM。
    if not text.strip():  # 空文件和只有空白的文件都没有有效事件。
        raise EmptyLogFileError(path)  # 明确拒绝，避免把“零记录”误当作导入成功。

    if suffix == ".json":  # 普通 JSON 可为一个对象或对象数组。
        return _parse_json_document(text, path)  # 交给 JSON 文档解析器。
    return _parse_jsonl(text, path)  # JSONL 按非空行逐条解析并保留行号。
```

省略的 `_decode_json()` 还使用 `object_pairs_hook` 检测重复字段，并通过 `parse_constant` 拒绝 `NaN`、`Infinity`、`-Infinity`。这是必要的，因为不同解析器对这些非标准值和重复键可能给出不同结果，进而破坏稳定哈希。

#### 4.3 Green：生成规范内容哈希与去重键

```python
def canonical_json(value: Mapping[str, Any]) -> bytes:  # 把同一个逻辑 JSON 对象转换成稳定字节序列。
    serialized = json.dumps(  # 开始使用固定参数序列化原始内容。
        value,  # 对完整原始事件进行序列化。
        sort_keys=True,  # 固定对象键顺序，避免字段排列影响哈希。
        separators=(",", ":"),  # 去掉无意义空格，形成稳定紧凑表示。
        ensure_ascii=False,  # 保留中文等 Unicode 字符，而不是转成转义序列。
        allow_nan=False,  # 拒绝 JSON 标准之外的非有限浮点数。
    )
    return serialized.encode("utf-8")  # 哈希函数处理字节，因此明确使用 UTF-8。


def calculate_content_sha256(value: Mapping[str, Any]) -> str:  # 生成可比较的 SHA-256 内容摘要。
    return hashlib.sha256(canonical_json(value)).hexdigest()  # 返回 64 位小写十六进制摘要。


def build_deduplication_key(external_id: str | None, content_sha256: str) -> str:  # 按是否有外部事件 ID 选择去重策略。
    if external_id is not None:  # 数据源提供稳定业务 ID 时优先使用它。
        return f"id:{external_id}"  # 前缀区分 ID 键和哈希键，避免类型碰撞。
    return f"sha256:{content_sha256}"  # 没有外部 ID 时，以规范内容哈希识别重复。
```

这里应注意：哈希输入是完整 `raw`，不是清理后的少数字段；`ingested_at` 和新生成的 `event_id` 不在 `raw` 中，因此重放相同日志不会仅因导入时间改变而变成新内容。

#### 4.4 Green：用数据库唯一约束处理并发去重

```python
statement = (  # 组装数据库插入语句，不在这里进行先查后写。
    insert(SecurityEventTable)  # 使用 PostgreSQL 方言的 INSERT。
    .values(**_event_values(event))  # 将领域事件转换为表字段。
    .on_conflict_do_nothing(  # 让数据库原子处理唯一键冲突。
        constraint="uq_security_events_source_deduplication_key"  # 以命名唯一约束判断冲突。
    )
    .returning(SecurityEventTable.event_id)  # 插入成功时返回真正落库的事件 ID。
)
inserted_event_id = self._session.execute(statement).scalar_one_or_none()  # 执行并读取结果。

if inserted_event_id is not None:  # 非空表示本次确实创建了新行。
    self._session.commit()  # 提交 PostgreSQL 事务。
    return PersistResult(event=event, created=True)  # 向上层报告“已创建”。

existing = self._session.execute(  # 冲突时查回数据库中已有事件。
    select(SecurityEventTable).where(  # 按来源与去重键定位冲突对应的已有行。
        SecurityEventTable.source == event.source,  # 来源必须相同。
        SecurityEventTable.deduplication_key == event.deduplication_key,  # 去重键必须相同。
    )
).scalar_one_or_none()  # 要求查询结果最多一条，没查到则返回 None。

if existing.content_sha256 != event.content_sha256:  # 同一业务键却出现不同内容。
    raise EventContentConflictError(...)  # 明确报冲突，禁止静默覆盖审计事实。
```

#### 4.5 Green：建立可恢复的双存储写入

```python
def _index_event(self, event: SecurityEvent) -> bool:  # 尝试把已注册事件同步到搜索索引。
    try:  # 为外部搜索服务调用建立失败处理边界。
        self._search_store.index_event(event)  # 将同一事件写入 OpenSearch。
    except Exception as exc:  # 外部客户端或传输错误都进入统一失败路径。
        error = str(exc).strip() or type(exc).__name__  # 保存可诊断的错误文本。
        self._repository.mark_index_failed(event.event_id, error)  # PostgreSQL 记录 failed。
        return False  # 调用者统计失败，但可以继续处理后续事件。

    self._repository.mark_indexed(  # 只有索引成功之后才更新业务库中的索引状态。
        event.event_id,  # 更新的仍是原事件，不能生成新的事件 ID。
        indexed_at=self._clock(),  # 记录实际索引成功时间。
    )
    return True  # 向导入报告计入一次成功索引。
```

OpenSearch 文档使用事件 ID 作为文档 ID：

```python
self._client.index(  # 调用 OpenSearch 写入文档接口。
    index=self._index_name,  # 默认配置为 security-events-v1。
    id=event.event_id,  # 使用稳定业务 ID，重复写入定位到同一文档。
    body=build_event_document(event),  # 写入原始内容、哈希及展开的检索字段。
)
```

#### 4.6 Green：生成证据前校验双端内容

```python
event = self._event_repository.get(event_id)  # 从 PostgreSQL 取得业务事件。
document = self._search_store.get_document(event_id)  # 用同一 ID 从 OpenSearch 取得文档。

postgres_hash = calculate_content_sha256(event.raw)  # 重新计算 PostgreSQL 原始内容哈希。
opensearch_hash = calculate_content_sha256(raw_document)  # 重新计算搜索文档原始内容哈希。
opensearch_stored_hash = document.get("content_sha256")  # 读取索引中保存的摘要。

hashes = (  # 收集两端保存值与重新计算值，供统一比较。
    postgres_hash,  # PostgreSQL 当前内容的重新计算值。
    opensearch_hash,  # OpenSearch 当前内容的重新计算值。
    event.content_sha256,  # PostgreSQL 保存的摘要。
    opensearch_stored_hash,  # OpenSearch 保存的摘要。
)
if not all(isinstance(value, str) and value == postgres_hash for value in hashes):  # 所有摘要都必须是字符串且与重新计算的内容一致。
    raise EvidenceIntegrityError(...)  # 任意一项不一致都拒绝生成证据。
```

通过核验后，证据还会保存查询上下文并加入命中的事件 ID：

```python
EvidenceItem(  # 只有完成完整性核验后才构造证据对象。
    evidence_id=self._evidence_id_factory(),  # 生成 EV-<ULID>。
    event_id=event.event_id,  # 建立证据到原始事件的直接关系。
    source=event.source,  # 保存数据来源。
    observed_at=event.observed_at,  # 保存事件实际观察时间。
    query={**deepcopy(query_template), "matched_event_id": event.event_id},  # 保存查询和命中 ID。
    summary=_summary(event),  # 摘要来自已验证事件的确定字段。
    content_sha256=event.content_sha256,  # 保存创建证据时对应的内容摘要。
)
```

#### 4.7 验证和历史提交命令

原计划给出的验证与提交命令必须保留：

```powershell
uv run --project services/backend pytest services/backend/tests/ingestion -v # 运行解析、规范化、幂等和双存储单元测试。
git add services/backend/src/evidencesoc/ingestion services/backend/src/evidencesoc/evidence services/backend/tests/ingestion data/samples # 暂存原计划列出的实现、测试与样例。
git commit -m "feat: add auditable event ingestion" # 用原计划提交信息记录通过验证的成果。
```

当前实现还包含持久化代码、ID 生成器、Task 5 迁移和额外测试。验收当前仓库时，应扩大范围：

```powershell
uv run --project services/backend pytest services/backend/tests/ingestion services/backend/tests/evidence services/backend/tests/persistence -v # 验证解析、服务、证据与存储适配层。
uv run --project services/backend pytest services/backend/tests/integration/test_ingestion_pipeline.py -v # 连接真实 PostgreSQL 和 OpenSearch，验证端到端追溯。
uv run --project services/backend ruff check services/backend # 检查后端代码规则与常见错误。
uv run --project services/backend mypy services/backend/src # 检查生产代码的静态类型。
```

第二条是真实依赖集成测试，运行前必须先按 Task 3 启动健康的 PostgreSQL 与 OpenSearch，并按 Task 4 将数据库升级到最新迁移。它会创建唯一测试索引与测试行，并在 `finally` 中清理；即使如此，也只能在明确的开发测试环境运行。

### 5. 核心文件说明

| 文件 | 职责 |
|---|---|
| `services/backend/src/evidencesoc/ingestion/jsonl.py` | 读取 JSON/JSONL，保留文件路径和行号，拒绝空文件、非法编码、重复键、非对象记录和非有限数。 |
| `services/backend/src/evidencesoc/ingestion/normalize.py` | 清理字段、统一带时区时间、生成规范 JSON、SHA-256 和去重键，构造 `SecurityEvent`。 |
| `services/backend/src/evidencesoc/ingestion/service.py` | 编排“解析 → 规范化 → PostgreSQL 注册 → OpenSearch 索引”，生成导入报告并处理失败重试。 |
| `services/backend/src/evidencesoc/ids.py` | 生成 ULID、`SE-<ULID>` 和 `EV-<ULID>`。 |
| `services/backend/src/evidencesoc/evidence/service.py` | 在证据落库前核验 PostgreSQL 与 OpenSearch 的内容、哈希和规范字段，保存查询上下文。 |
| `services/backend/src/evidencesoc/persistence/event_repository.py` | 实现事件的数据库级幂等、索引状态更新，以及证据的批量写入和读取。 |
| `services/backend/src/evidencesoc/persistence/event_search.py` | 构造 OpenSearch 文档，以 `event_id` 写入和读取搜索索引。 |
| `services/backend/src/evidencesoc/domain/models.py` | 定义 `SecurityEvent`、`EvidenceItem`、`EventIndexStatus` 等经过校验的领域结构。 |
| `services/backend/src/evidencesoc/persistence/tables.py` | 定义事件去重约束、索引状态字段和证据到事件的外键。 |
| `services/backend/migrations/versions/f311d6238878_add_ingestion_trace_fields.py` | 将已有 Task 4 数据库结构升级为支持去重、索引恢复和直接事件追溯的结构。 |
| `services/backend/src/evidencesoc/config.py` | 将默认 OpenSearch 索引固定为 `security-events-v1`，并读取连接配置。 |
| `services/backend/tests/ingestion/test_jsonl.py` | 验证 JSON/JSONL 输入格式、错误定位、编码和边界条件。 |
| `services/backend/tests/ingestion/test_normalize.py` | 验证字段清理、时区、哈希稳定性、内容变化和去重键。 |
| `services/backend/tests/ingestion/test_service.py` | 验证新导入、重复导入、冲突和预处理顺序。 |
| `services/backend/tests/ingestion/test_dual_store.py` | 验证 OpenSearch 失败不会阻塞后续事件，并能使用原事件 ID 重试。 |
| `services/backend/tests/ingestion/test_ids.py` | 验证 ID 格式、唯一性、排序和带时区要求。 |
| `services/backend/tests/evidence/test_service.py` | 验证证据生成、查询复制、缺失来源和两端内容/元数据篡改检测。 |
| `services/backend/tests/persistence/test_event_repository.py` | 验证命名唯一约束、冲突行为、状态更新及证据持久化。 |
| `services/backend/tests/persistence/test_event_search.py` | 验证 OpenSearch 文档结构、文档 ID、读取和异常传播。 |
| `services/backend/tests/integration/test_ingestion_pipeline.py` | 使用真实 PostgreSQL 与 OpenSearch 验证重复导入、双端读取和 Evidence ID 追溯。 |
| `data/samples/sql-injection.jsonl` | SQL 注入演示链路的公开样例事件；生产调查不得混入评分标签或攻击者真值。 |
| `data/samples/benign-web.jsonl` | 正常 Web 流量样例，用来检验系统能同时处理攻击与非攻击事件。 |

原计划只列出部分创建文件；上表按当前实现补充了真正参与完整链路的模块。`labels/`、`attacks.log` 和攻击者真值不属于这些样例的可见输入，也不能为了让演示结果“更准确”而混入 `raw`。

### 6. 完成验证标准

#### 6.1 原计划最低标准

- `uv run --project services/backend pytest services/backend/tests/ingestion -v` 成功；重复导入、内容篡改、空文件和非法 JSON 测试全部通过。
- 同一文件重复导入只产生一个持久化事件，第二次报告 `duplicated=1` 并返回已有 `event_id`。
- 原始内容的业务字段发生变化后，规范 SHA-256 随之变化；只调整 JSON 对象的键顺序时，哈希保持不变。
- 缺失或空白 `source`、非法或不带时区的时间、非法严重性和非法事件类型被明确拒绝。
- OpenSearch 的目标索引为 `security-events-v1`；PostgreSQL 与 OpenSearch 保存的内容和哈希能够互相核验。
- 任意 `EV-<ULID>` 都能定位到原始事件和生成该证据时的查询。

#### 6.2 当前实现应追加的标准

- JSON/JSONL 的重复键、非有限数、非对象项、错误 UTF-8 和不支持扩展名均产生带错误码、文件和行号的异常。
- `(source, deduplication_key)` 由数据库唯一约束保护；相同键、相同内容复用事件，相同键、不同内容明确报冲突。
- OpenSearch 单条索引失败时，该事件进入 `failed`，后续事件仍可继续；依赖恢复后使用相同 `event_id` 重试并进入 `indexed`。
- 证据生成前核对两端重新计算哈希、两端保存哈希、事件 ID 和规范元数据；任何不一致都不得落库证据。
- 批量证据必须“先全部验证，再统一写入”，不能因中途错误留下半批结果。
- Task 5 迁移升级成功，旧数据可回填；`evidence_items.event_id` 最终为非空外键，`security_events.index_status` 只允许 `pending`、`indexed`、`failed`。
- 真实集成测试在健康的 PostgreSQL 17、pgvector 0.8.6 与 OpenSearch 3.8.0 上通过，并完成临时数据清理。
- 样例输入不存在 `labels`、`attacks.log` 内容或攻击者真值；生成的业务结论引用有效 Evidence ID，证据不足时返回 `unknown`。

#### 6.3 验证证据的边界

单元测试可以使用内存仓库和记录型假对象验证业务分支，但它不能证明真实数据库、网络和索引模板配置可用。`test_ingestion_pipeline.py` 才跨越真实服务边界。反过来，一次集成测试通过也不能证明 SHA-256 具有来源认证能力，或证明双存储拥有跨系统原子事务。

2026-09-22 的原总结记录：整理时曾尝试在受限执行环境运行相关测试，结果为 90 个用例通过、30 个依赖 pytest `tmp_path` 的用例因临时目录 `PermissionError: [WinError 5]` 在 setup 阶段报错；更换到另一个受限目录后仍发生同类权限错误。因此这个结果说明已执行的 90 个测试通过，也说明测试沙箱无法创建临时目录；这段是历史记录，不能被写成 2026-09-27 的新测试结果，也不能写成“Task 5 全套测试当前全部通过”。在正常可写的本地开发环境中，仍应按本节命令重新运行并以新鲜输出作为验收证据。

### 7. 初学者学习要点

1. **解析、规范化、持久化和证据生成是四个不同职责。** 拆开后，每一层都能独立测试，错误也更容易定位。
2. **原始数据与规范字段应同时保留。** 规范字段便于查询，原始对象便于审计；只保存其中一个都会损失能力。
3. **规范化是稳定哈希的前提。** JSON 对象字段无顺序含义，哈希前必须确定编码、键顺序、空白和非法数值策略。
4. **业务幂等键与内容哈希用途不同。** external ID 表达“数据源认为这是同一事件”，内容哈希表达“内容是否相同”；二者结合才能识别正常重放与可疑冲突。
5. **唯一性最终要由数据库保证。** 仅靠应用先查询再插入会留下并发竞态，数据库唯一约束配合冲突处理更可靠。
6. **双写系统要设计失败状态和补偿。** PostgreSQL 成功、OpenSearch 失败并不罕见；记录 `pending/failed/indexed` 并重试，比假装一次函数调用能跨两个系统原子提交更诚实。
7. **Evidence ID 是引用，不是证据本体。** 真正有价值的是它指向的事件、查询、时间、来源和内容哈希，以及核验这些信息的过程。
8. **哈希回答“内容是否变化”，不回答“来源是否可信”。** 身份认证、权限控制和可信采集仍是独立问题。
9. **测试失败要先分类。** Red 阶段的预期业务失败、程序缺陷、外部服务未启动和临时目录权限错误含义不同。只有先确认失败原因，TDD 才不会退化为“看到红色就随便改代码”。
10. **Task 5 是从工程底座走向业务能力的转折点。** 前四个任务准备环境、骨架、服务和模型；本任务第一次把真实日志转换为可搜索、可恢复、可审计的业务事实，为后续 MCP 工具、RAG、Agent 调查和人工审批提供可信输入。

---

## Task 6：只读 MCP 工具

### 1. 任务目标

把日志、告警上下文和 ATT&CK 知识封装为三个有权限边界、资源上限、超时和审计的自建只读 MCP 工具，让 Agent 能取得可追溯的调查材料。

### 2. 设计初衷（为什么要做）

MCP（Model Context Protocol）是客户端发现工具、提交参数、取得结构化结果的一种协议。它本身不会自动保证工具安全：如果服务器公开了任意 Shell、文件读取或 URL 请求，Agent 仍可能越过调查范围。因此，本任务先确定“可以做什么”，再实现业务查询，而不是让模型自由连接数据库和操作系统。

项目只允许 `search_security_events`、`get_alert_context`、`lookup_attack_technique` 三个工具。MCP 服务器不向 Agent 提供任意 Shell、任意文件读取、任意 URL 请求，Agent 也不执行真实封禁、账号禁用、主机隔离或公网扫描。Strix 只提供架构参考，不作为依赖导入或运行。

三个工具解决三个不同问题：事件搜索回答“指定时间和条件下发生了什么”；告警上下文回答“当前调查关联的告警有哪些允许查看的事件”；ATT&CK 查询回答“这些行为可能对应哪些已知攻击技术”。不做封装，业务节点就要各自处理连接、参数、证据转换和异常，容易出现权限检查遗漏、输出格式不一致和无法复盘的问题。

“只读”主要指读取安全事件与知识，不改变被调查系统。**真实实现仍会在 EvidenceSOC 自己的数据库中创建证据、写入 `tool_calls` 审计记录。** 所以不能把一次工具调用理解为“对任何数据库都完全没有写入”。证据保存和审计是为了让人能追溯 Agent 看过哪些材料、为何拒绝某次调用；它们不等于执行安全处置。

### 3. 详细执行步骤

1. **先确认依赖和接口，再写边界测试。** 本任务接续 Task 5 的日志与证据服务，消费 OpenSearch、PostgreSQL 和本地 ATT&CK 知识。原计划使用 Python `3.12.14`、uv `0.12.16`、MCP Python SDK `mcp==1.30.0`、`langchain-mcp-adapters==0.3.2`、`opensearch-py==3.2.0`、SQLAlchemy `2.0.54` 和 `psycopg[binary,pool]==3.3.5`。实际入口使用 MCP SDK 的 `FastMCP`、`ClientSession` 和 stdio；已安装适配器依赖不意味着这里的客户端由 LangChain 适配器实现。`services/backend/README.md` 当前是空文件，具体操作依据源码、配置和测试，不能声称 README 已提供运行教程。

2. **用失败案例界定权限。** 原计划要求覆盖事件数量 `201`、单侧告警窗口 `901` 秒、负窗口、未知工具、空 Alert ID、超时和 OpenSearch 失败。真实测试还覆盖额外参数、错误参数类型、后台超量结果、调查上下文不匹配、重复审计和取消后的写入边界。这些测试的目的，是证明拒绝发生在存储调用之前，而不只是最后返回一句错误。

3. **实现不访问外部资源的策略函数。** `tools/policy.py` 保存工具允许列表和告警、ATT&CK 参数规则；事件规则实际定义在 `domain/event_search_policy.py`，再从 `tools/policy.py` 导出。事件 `limit` 默认 `100`，必须为 `1～200`；起止时间必须带时区，且起点早于终点；筛选字段仅允许 `source`、`event_type`、`severity`、`source_ip`、`destination_ip`、`host`、`service`，值必须为非空字符串。告警窗口前后默认各 `900` 秒，每侧都在 `0～900` 秒；ATT&CK 默认 `10` 条，允许 `1～10` 条，查询不能为空。注意：单侧 `900` 秒是 `get_alert_context` 的限制，源码没有为 `search_security_events` 规定同样的最大时间跨度，不能把这两种接口混写。

4. **把调查身份放在可信上下文中。** `RunContext` 保存 `run_id`、`incident_id`、`trace_id`，客户端通过 `EVIDENCESOC_RUN_ID`、`EVIDENCESOC_INCIDENT_ID`、`EVIDENCESOC_TRACE_ID` 传给本地子进程。服务器启动时查询 `agent_runs`，验证运行记录存在且确实属于该事件。工具 schema 不公开这三个参数，模型不能在每次请求中自行换一个事件 ID。`get_alert_context` 进一步要求告警属于当前事件，再从该告警 `event_ids` 允许列表与时间窗的交集中取事件；它不是搜索告警周围所有任意日志。

5. **按“校验 → 查询 → 证据转换 → 结果校验 → 审计”的顺序执行。** `SecurityEventTools` 和 `AlertContextTools` 通过 `run_audited_tool` 先校验，再在线程中执行同步存储工作。事件工作先在 OpenSearch 中找事件 ID，再由 `EvidenceService.create_for_events` 核验原始材料并创建 `EvidenceItem`；告警工作先在 PostgreSQL 中找允许的事件 ID，再走同一证据链。即使输入没有越界，也要校验后台返回的类型和数量，避免存储层故障绕过上限。

6. **区分可以重试的读与不能盲目重试的写。** 原计划“每次调用超时 `10` 秒、最多重试两次”，实现中的 `range(3)` 表示首次尝试加两次重试，合计最多三次；这些尝试共享剩余时间，不是每次各有十秒。事件 ID 查询对特定连接、超时与 `502/503/504` 错误重试；告警和 ATT&CK 数据库查询对 `OperationalError` 重试。SDK 自带的 OpenSearch 重试被禁用，避免叠加重试。证据创建和审计提交均不重试，因为“提交超时”可能表示数据已写入但客户端没有收到确认，再写一次会让结果不明确。

7. **让十秒预算贯穿业务与审计。** `RestrictedFastMCP` 设置整次调用截止时间；`run_audited_tool` 的默认预算也是 `10.0` 秒，并在默认情况下给审计预留最多 `1` 秒。`ExecutionBudget` 通过上下文传播到同步工作线程，SQL 查询设置 `statement_timeout`，OpenSearch 使用剩余时间作为请求超时，取消后还检查是否允许进入证据保存。`asyncio` 超时本身不会强行杀死同步线程，因此这些协作式检查有实际意义。审计失败不能被假装成一次完整成功调用。

8. **注册、发现并检查错误协议。** `mcp_server/main.py` 只注册三个工具，`restricted.py` 在 MCP 边界检查名称、必需参数、额外参数和类型。拒绝写入审计，并返回包含 `code`、公开 `message`、`trace_id` 的错误对象。错误码固定为 `POLICY_DENIED`、`NOT_FOUND`、`DEPENDENCY_TIMEOUT`、`DEPENDENCY_UNAVAILABLE`。内部异常不直接暴露给调用者。边界拒绝与业务失败分别审计，避免同一次失败被记录两遍。

9. **核对计划与真实返回契约。** 原计划 Task 6 写“所有结果先转换成 `EvidenceItem`”，但同一计划第 4.3 节已把 ATT&CK 工具定义为 `list[dict[str, str]]`。真实实现按后者处理：前两个工具返回 `EvidenceItem`，ATT&CK 返回六字段知识字典，字段为 `knowledge_chunk_id`、`technique_id`、`title`、`summary`、`source_uri`、`version`。日志证据 ID 与知识块 ID 属于不同命名空间，不能把 ATT&CK 知识说成现场日志证据。当前生产构造器已接入 Task 7 的混合 ATT&CK 检索；`attack_work.py` 中仍保留旧的关键词仓库类，读到它不代表生产入口仍只用 `ILIKE`。

### 4. 关键代码/命令示例

**源码节选，加逐行教学注释：告警窗口校验。** 下例取自 `tools/policy.py`，保持校验逻辑，省略文件里的其他函数；模块中可以直接定义这些导入、常量和函数。

```python
from evidencesoc.domain.event_search_policy import PolicyDeniedError  # 复用项目统一的策略拒绝异常。
MAX_CONTEXT_SECONDS = 900  # 每一侧窗口最多十五分钟，不能用大窗口扩大读取范围。
def validate_alert_context(  # 定义纯校验函数；这里不连接数据库。
    alert_id: str,  # 调用者必须给出告警标识。
    before_seconds: int = 900,  # 默认读取告警之前十五分钟的允许事件。
    after_seconds: int = 900,  # 默认读取告警之后十五分钟的允许事件。
) -> None:  # 合法时正常返回；非法时抛异常阻止后续工作。
    if not alert_id.strip():  # 空串或仅空格都不是有效告警 ID。
        raise PolicyDeniedError("alert_id must not be blank")  # 拒绝请求而不是尝试全表查询。
    if not 0 <= before_seconds <= MAX_CONTEXT_SECONDS:  # 检查前侧窗口，零秒合法。
        raise PolicyDeniedError("before_seconds must be between 0 and 900")  # 超限与负数都拒绝。
    if not 0 <= after_seconds <= MAX_CONTEXT_SECONDS:  # 后侧独立检查，不能靠总窗口替代。
        raise PolicyDeniedError("after_seconds must be between 0 and 900")  # 两侧都合法后才可访问存储。
```

**教学示例：验证边界，不访问服务。** 这是调用真实校验器的最小程序，不是新增项目测试文件。

```python
from evidencesoc.tools.policy import PolicyDeniedError, validate_alert_context  # 导入实际项目接口。
validate_alert_context("AL-example", before_seconds=900, after_seconds=900)  # 合法边界应正常返回。
try:  # 演示超限输入的结果。
    validate_alert_context("AL-example", before_seconds=901, after_seconds=900)  # 一侧多一秒也拒绝。
except PolicyDeniedError as error:  # 捕获项目的权限异常。
    print(error.code)  # 输出 POLICY_DENIED；这个例子没有调用存储层。
```

**JSONC 教学示例：MCP 调用参数和失败结果。** 注释仅用于阅读；正式 JSON 请求必须去掉注释。`name` 与 `arguments` 是教学展示的调用封装，对应 `session.call_tool(name, arguments)`，不是任意扩展的业务参数。

```jsonc
{ // 展示一个工具调用的名称和参数。
  "name": "get_alert_context", // 使用三个允许工具之一。
  "arguments": { // 这里只传 schema 允许的业务参数。
    "alert_id": "AL-example", // 服务器还会验证它是否属于当前事件。
    "before_seconds": 901, // 故意超出前侧 900 秒上限。
    "after_seconds": 900 // 后侧合法也不能抵消前侧越界。
  } // 当前 run_id、incident_id、trace_id 来自受信任上下文。
} // 实际调用应得到错误结果而非日志列表。
```

```jsonc
{ // 对应失败结果的 structuredContent；SDK 外层还会标记 isError=true。
  "error": { // 项目统一的错误对象。
    "code": "POLICY_DENIED", // 客户端用错误码区分权限拒绝和依赖故障。
    "message": "request denied", // 公开提示不暴露内部数据库细节。
    "trace_id": "TRACE-example" // 此值来自可信运行上下文，便于查审计记录。
  } // POLICY_DENIED 不等于数据源暂时不可用。
} // 不应把错误对象当成空检索结果。
```

**验证命令说明：在仓库根目录运行。** 下列命令供读者使用，本次文档整理没有执行这些测试或工具调用。`tests/tools` 中的 stdio 测试会创建临时 SQLite 数据库和本地 MCP 子进程；它们验证协议和边界，不证明真实 OpenSearch 现场查询已经验收。

```powershell
Set-Location 'D:\传智杯' # 使用当前工作区；原计划早期环境示例中的 D:\桌面\传智杯 是历史路径。
uv run --project services/backend pytest services/backend/tests/tools/test_policy.py -v # 先检查纯策略规则，不需要业务服务。
uv run --project services/backend pytest services/backend/tests/tools/test_mcp_server.py services/backend/tests/tools/test_mcp_client.py -v # 验证允许列表、结构化失败和本地 stdio 会话。
uv run --project services/backend pytest services/backend/tests/tools -v # 检查结果类型、重试、取消、审计和证据写入边界的完整工具测试。
```

原计划的 Git 命令作为历史学习材料保留；本次文档更新不执行暂存或提交：

```powershell
git add services/backend/src/evidencesoc/tools services/backend/src/evidencesoc/mcp_server services/backend/tests/tools # 原计划：暂存工具实现、MCP 入口和工具测试。
git commit -m "feat: add restricted mcp investigation tools" # 原计划：为经过验证的工具交付建立历史快照。
```

### 5. 核心文件说明

以下均为从仓库根目录出发的真实路径；学习时建议按“策略 → 工具 → 工作实现 → MCP 边界”的顺序阅读。

| 文件或目录 | 职责及阅读重点 |
|---|---|
| `services/backend/src/evidencesoc/domain/event_search_policy.py` | 事件上限、允许筛选字段、带时区且递增的时间范围；这是事件校验的真实定义位置。 |
| `services/backend/src/evidencesoc/tools/policy.py` | 三个工具允许列表、单侧 900 秒、ATT&CK 最多 10 条；原计划核心文件。 |
| `services/backend/src/evidencesoc/tools/security_events.py` | 事件工具包装，把可信 `incident_id` 交给业务工作，并校验 `EvidenceItem` 返回值。 |
| `services/backend/src/evidencesoc/tools/alert_context.py`、`alert_work.py` | 校验告警参数，限定当前事件关联告警与事件允许列表；最多返回 200 项。 |
| `services/backend/src/evidencesoc/tools/event_work.py` | 重试只读 OpenSearch ID 查询，再调用证据服务；证据保存不重试。 |
| `services/backend/src/evidencesoc/tools/attack.py`、`attack_work.py` | ATT&CK 六字段返回校验、最多两次只读重试，以及接入混合检索的生产构造器。 |
| `services/backend/src/evidencesoc/tools/runtime.py`、`services/backend/src/evidencesoc/execution.py` | 十秒总期限、线程工作预算、结果校验、取消和审计；理解超时不能只写在最外层。 |
| `services/backend/src/evidencesoc/tools/audit.py`、`audit_sql.py`、`errors.py` | 定义审计记录、写入 `tool_calls`、生成 `TC-` ID、统一公开错误码。 |
| `services/backend/src/evidencesoc/mcp_server/main.py` | 验证 AgentRun 与事件关系、构造服务、只注册三个异步工具，并使用 `transport="stdio"`。 |
| `services/backend/src/evidencesoc/mcp_server/restricted.py` | 请求名称、参数集合和参数类型检查；未知工具和多余参数也要拒绝并审计。 |
| `services/backend/src/evidencesoc/mcp_server/context.py`、`client.py` | 从环境读取可信上下文，启动本地子进程并在整个 AgentRun 中保持一个会话。 |
| `services/backend/src/evidencesoc/config.py`、`.env.example` | `DATABASE_URL`、`OPENSEARCH_URL`、默认索引 `security-events-v1`、`RAG_DATA_DIRECTORY`；相对知识目录按仓库根目录解析。 |
| `services/backend/tests/tools/` | `test_policy.py` 是计划指定测试；其余测试覆盖真实实现的协议、业务、审计和取消路径。当前仓库没有单独的 `tests/mcp/`，MCP 测试实际是本目录下的 `test_mcp_server.py`、`test_mcp_client.py`。 |

### 6. 完成验证标准

应分别验证接口、越界、异常和追溯，不能只看“服务器能启动”。本节列的是验收要求与已有测试依据，不代表本次文档整理重新执行了验收。

- **发现范围正确：** `list_tools()` 只能返回三个固定名称；工具输入 schema 不公开可信运行身份；错误的 AgentRun/事件绑定不能初始化服务。
- **输入拒绝早于存储：** `limit=201`、前/后侧 `901` 秒或负数、空告警 ID、未知工具、额外参数、错误类型、非法事件筛选字段均被拒绝；测试中的 work spy 证明业务未调用。
- **输出也有上限：** 事件搜索不超过请求 `limit` 且绝不超过 200；告警上下文不超过 200；ATT&CK 不超过请求 `limit` 且绝不超过 10。后台返回错误类型、超量列表或不完整 ATT&CK 字典时不能伪装成功。
- **失败有明确信号：** 超时与依赖不可用使用不同错误码；找不到允许的资源为 `NOT_FOUND`；不存在的 ATT&CK ID 返回 `[]`，不伪造一个相似技术；数据库/模型故障不能被伪装成“查无结果”。
- **期限和重试受控：** 整次调用默认十秒，读取首次加最多两次重试，证据与审计提交各只尝试一次；取消后不继续进入证据保存，审计不在总期限外无限等待。
- **成功和拒绝都可追溯：** `tool_calls` 中保存运行 ID、工具名、参数、开始/结束时间、成功标志、错误码；结果摘要保存 trace ID、结果数或拒绝原因。同次失败不产生重复审计。
- **读和写的边界解释一致：** 工具不能向模型开放任意 Shell、文件、URL 或真实处置；证据及审计的内部写入符合设计。原计划 Task 6 已勾选步骤，但仍须结合实际测试输出判断当前环境的通过情况。

### 7. 初学者学习要点

先学“接口契约”，再学调用代码：一个函数名称不够，还要知道参数类型、默认值、边界、结果类型和失败方式。MCP 使契约可以被客户端发现；策略代码才把契约变成必须遵守的规则。

纯函数不访问外部资源，适合先检查输入、快速测试边界。业务查询、证据保存和审计则分别有自己的失败情况。把这些职责分开，可以准确回答“是输入越权、没找到资源，还是数据库不可用”，也能证明非法输入没有触及数据源。

可信身份与模型提交的参数要分开。调查 ID 由服务器绑定，避免模型通过参数访问另一调查。告警允许列表进一步限制材料范围；“时间在附近”不等于“有权查看”。

重试是一种有条件的恢复机制：只读查询常能重试，提交结果不明确的写入不能盲目重复。十秒是整次调用的总资源预算，要覆盖线程、网络、SQL 和审计，而不是在每一层各写一个十秒就认为完成了限时。

最后区分“日志事实”与“知识解释”。Evidence ID 追溯当前事件材料，Knowledge Chunk ID 追溯一般知识。知识库说 DNS 可以用于外泄，不等于已经证明某次 DNS 请求发生了外泄；下一任务的引用校验也不能代替这种事实判断。

## Task 7：ATT&CK RAG 和引用校验

### 1. 任务目标

把固定版本 ATT&CK 与可信内部响应手册建成可追溯的本地知识库，通过默认返回最多 8 条的混合检索提供解释材料，并把缺失或越权引用的报告声明标为 `unsupported`。

### 2. 设计初衷（为什么要做）

ATT&CK 是描述攻击行为和技术的知识体系；STIX 是承载这些结构化知识的数据格式。RAG（检索增强生成）先检索相关知识，再把它交给后续分析或报告生成。本任务实现知识准备、检索与引用校验，不会单凭检索就自动证明某个攻击真实发生。

单靠模型记忆可能说错技术编号、用到旧版本，或者给出无法核对的解释。单靠关键词又容易漏掉换一种说法的查询，例如“DNS 数据外泄”与英文技术说明。混合检索同时使用关键词与向量语义排序，再用 RRF（Reciprocal Rank Fusion，倒数排名融合）合并：它综合两份排名，而不要求关键词分数与向量距离具有相同量纲。

知识的来源也必须可检查。版本、来源 URI、下载时间、原文件 SHA-256 和知识块 ID 让人可以回到具体材料。固定数据与模型，才能比较重复实验；如果数据悄悄更新，检索结果变好或变坏都无法解释。

引用校验回答“报告引用的 ID 是否在当前允许范围内”。不做这一步，生成器可能引用不存在的证据，或借用另一个调查的证据。校验通过仍只表示引用存在且被允许，**不表示来源正文在语义上证明了声明**；后者需要分析逻辑和人工复核。`unsupported` 是声明校验状态，`unknown` 是证据不足时的业务判断，二者不能混用。

### 3. 详细执行步骤

1. **固定知识、模型和运行配置。** 原计划知识源为 MITRE Enterprise ATT&CK `v19.2` STIX 与内部响应手册；生产解析器固定官方源 Git 提交 `6cda5ad8462c79e14fbb872f4e09059b18e0cfc4`、版本 `19.2`、SHA-256 `dc1639caa5501d720e280cf1cbd8fbe009884a0c9b3e6e9ed9d0c25166c3d8f4`，不接受换一份内容却继续标称同版本。新增的本地嵌入实现使用 `fastembed==0.8.1`，模型名 `sentence-transformers/paraphrase-multilingual-MiniLM-L12-v2`，修订 `faf4aa4225822f3bc6376869cb1164e8e3feedd0`，384 维 CPU ONNX 推理。原计划 PostgreSQL `17`、pgvector 扩展镜像 `pgvector/pgvector:0.8.6-pg17-bookworm`、Python 客户端 `pgvector==0.5.0`；真实 `pyproject.toml` 固定客户端 `pgvector==0.3.6`。扩展版本与 Python 包版本是两个概念，文档必须记录差异，不能把客户端版本冒充数据库扩展版本。

2. **显式准备材料，避免运行时自动联网。** `rag/cli.py` 的 `prepare` 命令下载并核验 `enterprise-attack-19.2.json`，生成 `enterprise-attack-19.2.manifest.json`，准备 `model/` 文件与模型清单，再做向量计算和数据库写入。默认目录是 `data/knowledge`；`.env.example` 的 `RAG_DATA_DIRECTORY=data/knowledge` 由配置解析为仓库根目录下的绝对路径。`--data-directory` 必须与运行配置指向同一目录，避免“准备在 A、查询却读 B”。模型准备阶段校验每个固定文件的大小与 SHA-256；查询阶段只加载已验证本地文件，`local_files_only=True`，缺失模型时明确失败，不临时下载。

3. **先校验来源，再解析和切块。** `SourceManifest` 保存版本、原文件哈希、带时区下载时间和来源 URI。`parse_attack` 先对原始字节做哈希核对，再检查 STIX bundle、collection 版本、对象类型与唯一 MITRE 引用；只收录未撤销、未弃用的 `attack-pattern`，技术 ID 必须满足 `Tdddd` 或 `Tdddd.ddd` 格式，来源 URI 必须是规范 MITRE 技术页面。正文按最多 `1500` 字符切分，尽量沿句子/词边界，保留全部正文字符。不要先算向量再发现来源非法，因为那会浪费计算并可能污染知识库。

4. **阻止评测真值进入知识。** 递归检查输入中的评测、标签、攻击者真值字段；正式评测的 `labels/`、`attacks.log` 不能作为知识输入。内部手册必须显式 `trusted=True`，来源必须为规范的 `internal://knowledge/...`，路径与正文都检查已知真值标记。官方 STIX 中某些 malware/tool/indicator 的顶层 `labels` 是描述性分类，解析器有特定允许规则；这不是允许导入数据集答案。测试中的相关 Technique ID 是开发检索基准的评分依据，留在测试文件中，不导入知识表。

5. **生成稳定知识块 ID，再存 metadata 和向量。** `_make_chunks` 使用来源 URI、版本、STIX ID、标题、块序号、正文哈希和嵌入模型标识生成 `KC-` 加 60 个十六进制字符的 ID。相同内容与配置重复准备可以定位同一块；正文、标题或模型变化会生成不同知识块 ID，不能沿用旧身份。更换嵌入模型不等于更改官方 ATT&CK 数据版本，这两项需要分别记录。嵌入文本包含“标题 + 换行 + 正文”。向量先检查数量、非空维度、一致性、有限数值和非零幅值；本地模型另校验 384 维。`upsert_chunks` 分批最多 500 块，在事务中用 PostgreSQL `ON CONFLICT DO UPDATE` 保存来源、正文、元数据和向量；任一批失败应回滚整个操作。内部手册更新把旧块标记弃用但保留历史 ID，避免旧报告引用失去目标。

6. **处理精确技术 ID 与自然语言查询。** `retrieve_knowledge(query: str, top_k: int = 8)` 默认返回最多 8 条，内部接口允许 `top_k` 为 `1～50`，不接受 `True` 或小数；查询最多 4096 字符。空白、只有不可检索符号或含 NUL 的查询返回 `[]`。完整 Technique ID 查询只走精确路径，`T9999` 查不到就返回空，不用语义相似技术替换它。精确路径不需要实际加载模型权重，但仍需要数据库中有合格条目。自然语言路径先查关键词，再算查询向量、查语义排名，候选数为 `min(100, max(32, top_k * 4))`；默认候选数因此为 32。

7. **让两种真实检索各自排序，再做 RRF。** PostgreSQL 关键词通道用英文全文检索，标题权重 A、正文权重 B，并包含“数据外泄”等领域中文到英文词的转换；语义通道用 pgvector 余弦距离，越小越靠前。查询会过滤错误版本、错误官方哈希、错误来源、撤销/弃用、错误模型等条目；语义通道还过滤向量维度。普通 RAG 可以包括可信内部手册，而 MCP ATT&CK 工具设置 `attack_only=True`，只返回 ATT&CK。每条检索排名贡献 `1 / (60 + 排名)`，按知识块 ID 去重并累计；分数相同按 ID 排序，保证确定性，最后截到 `top_k`。Task 6 的 ATT&CK 外部工具仍限制最多 10 条，不能用内部 `top_k<=50` 放宽 MCP 边界。

8. **将事实声明拆成结构化字段再核对引用。** 每条 `FactualClaim` 包括 `claim_id`、`text`、`evidence_ids`、`knowledge_chunk_ids`。调用者向 `validate_citations` 提供“当前事件的证据 ID 集合”和“本报告已检索或获准使用的知识 ID 集合”。两类集合分别核对；没有任何引用为 `missing_citation`；任意一个引用不在对应集合中为 `invalid_citation`；两种情况均标记 `unsupported` 并记录无效 ID。有一个有效引用不能抵消另一个无效引用，全库存在也不能代替当前作用域授权。函数返回逐条结果，不主动抛出“整份报告失败”，报告层需要据此执行阻断或复核。

9. **分层验证，避免把演示当成真实验收。** `test_retrieval.py` 的 Repository/Embedder 是测试替身：它证明关键词、语义两个通道被调用、RRF 排名和上限正确，不证明真实语义召回。`test_postgres_retrieval.py` 使用临时写入的二维向量行证明 pgvector SQL 排序和过滤机制，但它也不是固定模型、完整官方语料的语义质量验收。`test_acceptance.py` 要求本地固定模型，真实 PostgreSQL 中匹配固定官方哈希、模型 ID 且向量非空的块数超过 500，12 条预先固定查询的平均 `Recall@8 >= 0.80`；实际召回还受来源、版本和撤销状态等过滤条件约束。必须显式设置 `RUN_RAG_ACCEPTANCE=1` 才运行；默认跳过不能记成“已通过”。

### 4. 关键代码/命令示例

**源码节选，加逐行教学注释：生产检索分支。** 以下是 `HybridRetriever.retrieve_knowledge` 完成输入校验后的方法体节选；它依赖方法已有的 `self`、`query`、`top_k` 与文件导入，不是可独立运行的脚本。

```python
check_execution()  # 查询依赖前检查当前执行预算，超时或取消时停止。
if TECHNIQUE_ID_PATTERN.fullmatch(query):  # 完整技术 ID 与自然语言走不同路径。
    return self._repository.exact(query.upper(), top_k)  # 查不到精确 ID 就返回空，不替换成近似技术。
candidates = min(100, max(32, top_k * 4))  # 多取候选后融合；默认 top_k=8 时每通道取 32 个。
keywords = self._repository.keyword(query, candidates)  # 取得关键词通道排名。
check_execution()  # 在向量计算前再次检查剩余预算。
vector = self._embedder.embed_query(query)  # 使用本地模型把查询转换为数值向量。
check_execution()  # 在数据库向量查询前检查预算。
semantic = self._repository.semantic(vector, candidates)  # 取得 pgvector 余弦距离排名。
return reciprocal_rank_fusion([keywords, semantic], top_k=top_k)  # 按名次融合、去重并截断输出。
```

**教学示例：理解 RRF 累积分数，不连接模型或数据库。** 调用真实函数，结果结构与知识工具一致；示例 ID 用于解释排序，不代表仓库已经保存了这些知识块。

```python
from evidencesoc.rag.retriever import reciprocal_rank_fusion  # 导入项目真实的融合函数。
def hit(chunk_id: str) -> dict[str, str]:  # 为教学构造一个符合六字段契约的结果。
    return {  # 这里只生成字典，没有把演示内容写入知识库。
        "knowledge_chunk_id": chunk_id,  # RRF 按这个标识去重。
        "technique_id": "T1048.003",  # 示例使用真实技术编号，但不是调查结论。
        "title": "Exfiltration Over Unencrypted Non-C2 Protocol",  # 标题字段帮助人工阅读。
        "summary": "Teaching example",  # 示例摘要，不冒充官方原文。
        "source_uri": "https://attack.mitre.org/techniques/T1048/003/",  # 规范技术页面 URI。
        "version": "19.2",  # 展示结果的版本字段。
    }  # 完成一个教学结果。
a, b, c = hit("KC-A"), hit("KC-B"), hit("KC-C")  # 这些短 ID 仅用于测试式演示，生产 ID 是哈希格式。
merged = reciprocal_rank_fusion([[b, a, b], [c, a]], top_k=8)  # A 在两通道均为第二；B 的重复不再加分。
print([item["knowledge_chunk_id"] for item in merged])  # 输出 ['KC-A', 'KC-B', 'KC-C']；B、C 同分按 ID 排序。
```

在上例中，A 得分 `1/62 + 1/62`，B 与 C 各得分 `1/61`。虽然 A 没在任何一份排名中居首，但两个通道都支持它，所以融合后领先。这个例子解释算法，不能证明“DNS 数据外泄”的实际语义检索质量。

**教学示例：存在、缺失和混合无效引用。** 调用的是真实引用校验器；ID 是明确标出的教学占位符，只测试集合校验逻辑。

```python
from evidencesoc.evidence.citations import FactualClaim, validate_citations  # 导入结构化声明和真实校验函数。
allowed_evidence = {"EV-teaching"}  # 教学作用域只允许这个现场证据 ID。
allowed_knowledge = {"KC-teaching"}  # 教学作用域只允许这个知识块 ID。
claims = [  # 一次批量校验多个独立声明。
    FactualClaim(claim_id="a", text="示例事实", evidence_ids=["EV-teaching"]),  # 引用在允许范围内。
    FactualClaim(claim_id="b", text="没有来源的示例事实"),  # 缺少两类引用，不能标为有支持。
    FactualClaim(claim_id="c", text="混合引用的示例事实", knowledge_chunk_ids=["KC-teaching", "KC-missing"]),  # 一个无效引用使整条不获支持。
]  # 声明必须来自报告层；校验器不自动从普通段落抽取事实。
checked = validate_citations(claims, allowed_evidence, allowed_knowledge)  # 两个命名空间分别核对。
print([(item.status, item.reason) for item in checked])  # 输出 supported/None、unsupported/missing_citation、unsupported/invalid_citation。
```

**操作命令说明：先验证逻辑，再准备材料与执行真实验收。** 以下只提供读者操作顺序，本次文档工作没有执行知识准备、数据库写入或真实服务验收。纯逻辑/模拟下载测试可先执行；准备命令会联网、下载模型并写入知识表；整个 `tests/rag` 包含真实 PostgreSQL 写入测试，需要已经迁移且允许测试写入的数据库。

```powershell
Set-Location 'D:\传智杯' # 从当前仓库根目录运行，保持服务、测试与数据路径一致。
uv run --project services/backend pytest services/backend/tests/rag/test_retrieval.py services/backend/tests/evidence/test_citations.py -v # 先验证融合、精确 ID 和引用作用域，不代表真实语义验收。
uv run --project services/backend pytest services/backend/tests/rag/test_embeddings.py services/backend/tests/rag/test_cli.py -v # 用测试替身检查固定文件校验、离线加载和目录一致性。
uv run --project services/backend python -m evidencesoc.rag.cli prepare # 操作者显式准备固定数据与模型，并把知识和向量写入已迁移的 PostgreSQL。
uv run --project services/backend pytest services/backend/tests/rag -v # 运行计划指定的测试目录；注意真实数据库测试的写入与清理。
$env:RUN_RAG_ACCEPTANCE = '1' # 显式启用完整官方语料与本地模型的验收，默认运行会跳过它。
uv run --project services/backend pytest services/backend/tests/rag/test_acceptance.py -v -s # 输出块数、每条固定查询召回率、平均 Recall@8，并检查 MCP 适配契约。
Remove-Item Env:RUN_RAG_ACCEPTANCE # 验收后移除开关，避免后续普通测试意外依赖完整环境。
```

原计划 Step 5 还安排 Git 提交，以下精确命令作为历史学习材料保留。本次只补充文档，不执行暂存或提交，也不把“写好学习总结”当成“Task 7 已重新验收”。

```powershell
git add services/backend/src/evidencesoc/rag services/backend/src/evidencesoc/evidence/citations.py services/backend/tests/rag # 原计划：暂存知识检索、引用校验和 RAG 测试。
git commit -m "feat: add hybrid attack knowledge retrieval" # 原计划：记录已验证的混合检索交付。
```

### 5. 核心文件说明

| 文件或目录 | 职责及阅读重点 |
|---|---|
| `services/backend/src/evidencesoc/rag/models.py` | 定义来源清单、知识块和嵌入接口；`extra="forbid"` 拒绝多余字段，清单日期必须带时区。 |
| `services/backend/src/evidencesoc/rag/ingest_attack.py` | 计划指定文件；固定 v19.2 官方提交及 SHA-256、解析合法对象、反真值污染、1500 字符切块、稳定 ID、事务 upsert、手册版本退休。 |
| `services/backend/src/evidencesoc/rag/embeddings.py` | 固定模型修订、文件大小和哈希，384 维本地 CPU 嵌入；区分显式下载准备与离线运行。 |
| `services/backend/src/evidencesoc/rag/retriever.py` | 计划指定文件；精确查询、PostgreSQL 全文检索、pgvector 余弦排序、RRF、默认 `top_k=8` 与合格来源过滤。 |
| `services/backend/src/evidencesoc/rag/cli.py` | `python -m evidencesoc.rag.cli prepare` 的真实入口；校验配置目录，准备官方源、本地模型和内部手册。 |
| `services/backend/src/evidencesoc/evidence/citations.py` | 计划指定文件；`FactualClaim`、`ValidatedClaim` 和 `validate_citations`；验证调用者给定范围内的引用，保留逐条理由。 |
| `services/backend/src/evidencesoc/persistence/tables.py` | `knowledge_chunks` 的来源、正文、metadata 和向量列定义；数据库迁移属于前置任务。 |
| `services/backend/src/evidencesoc/tools/attack_work.py`、`services/backend/src/evidencesoc/mcp_server/main.py` | 把混合检索接入原有只读工具、十秒预算和审计流程；工具结果只允许 ATT&CK。 |
| `services/backend/src/evidencesoc/config.py`、`.env.example`、`services/backend/pyproject.toml` | 知识目录、数据库地址和真实精确依赖版本；`LLM_MODE=fixture` 是调查模型模式，不是 RAG 已完成语义验收的标志。 |
| `data/samples/response-manual.txt` | CLI 实际导入的内部模拟响应手册，版本 `1.0`，来源 `internal://knowledge/simulated-response`，与 ATT&CK 知识分开标记。 |
| `data/knowledge/enterprise-attack-19.2.json`、`data/knowledge/enterprise-attack-19.2.manifest.json`、`data/knowledge/model/` | 默认配置下由 prepare 生成/验证的运行材料路径；这里描述的是准备位置，不承诺当前环境已经具备这些文件。 |
| `services/backend/tests/rag/test_retrieval.py`、`test_ingest_attack.py`、`test_embeddings.py`、`test_cli.py` | 分别检查融合分支、来源与事务、模型校验、准备流程；其中部分 ingest 测试也会连接真实 PostgreSQL。 |
| `services/backend/tests/rag/test_postgres_retrieval.py`、`test_acceptance.py` | 前者验证真实 SQL/pgvector 机制，后者验证固定完整语料与真实模型的 Recall@8，二者证据强度不同。 |
| `services/backend/tests/evidence/test_citations.py` | 引用缺失、越权、混合无效 ID、命名空间混用、输出不修改输入等测试；运行原计划 `tests/rag` 不会自动包含这个目录。 |

### 6. 完成验证标准

当前仓库已有 Task 7 的实现、单元测试、数据库测试和完整验收测试；原计划中的 Task 7 步骤仍显示未勾选。源码存在、计划勾选和本机测试通过是三种不同证据，本次只做文档与源码核对，不能凭此宣布当前机器已达到召回基线。

- **来源准备可核对：** 官方 STIX 版本 `19.2`、固定 URI、固定 SHA-256、带时区下载日期匹配；修改文件内容、版本或来源时必须拒绝。模型固定修订、文件哈希、文件大小和 384 维配置可核对，运行时不补下载。
- **知识结构与写入可靠：** 每块有来源、版本、标题、正文、原文件/正文哈希、嵌入模型和向量；最多 1500 字符；重复导入不制造重复块；错误向量在写入前拒绝；分批失败回滚；手册替换后旧引用目标保留而旧块退出检索。
- **无评测信息泄漏：** 标签、攻击者真值、`attacks.log` 和评测路径不能进入知识库；开发检索基准留在测试层。拒绝规则测试通过不意味着已经自动审计所有未来人工输入，操作者仍要选择可信手册。
- **混合检索机制真实：** PostgreSQL 全文排名与 pgvector 余弦排序都参与自然语言检索，RRF 去重、累积分数且排序可复现；默认最多 8 条；精确 `T9999` 结果为空。MCP 适配最多 10 条且不返回内部手册。
- **正式质量门槛明确：** `RUN_RAG_ACCEPTANCE=1` 下真实验收要求匹配固定官方哈希、模型 ID 且向量非空的知识块数大于 500，12 条固定查询的平均 `Recall@8 >= 0.80`，并额外要求“DNS 数据外泄”包含 `T1048.003`。这些计数条件不代替检索阶段对来源、版本和撤销状态的过滤。Recall@8 是“前八条中召回的相关技术数 / 该查询预设相关技术数”，当前验收先逐查询计算，再取平均；不是检查八条结果中有多少条正确的 Precision@8。
- **测试替身不替代质量验收：** fixture 仓库、fake embedder、短演示数据、二维向量排序测试分别证明接口/算法/SQL 机制；它们都不能充当完整官方语料、固定 384 维模型和 pgvector 的语义验收。测试输出出现 skipped，必须明确报告跳过，不能算通过完整质量门槛。
- **引用失败可被上层使用：** 缺引用、跨事件引用、未获准知识 ID、任何一个无效 ID、两种命名空间混用均标记 `unsupported`；调用者提供正确作用域，报告层根据结果阻断无支持声明或转人工复核。这个函数不验证语义蕴含、不自动扫描整份自然语言报告，也不会独自确认攻击成立。

### 7. 初学者学习要点

把 RAG 拆成三个阶段学习：准备阶段确认“材料从哪里来”；检索阶段回答“哪些材料与问题有关”；引用阶段确认“输出说的来源是否存在且允许使用”。生成答案是后续应用行为，不能把这三个阶段都理解成“调用模型聊天”。

向量是一组描述文本特征的数字，语义检索比较这些数字之间的距离。它能帮助找到不同措辞的相关知识，但距离接近并不等于事实成立。同一库中的向量必须匹配模型与维度，否则比较缺乏意义；不能以固定假向量的单元测试替代真实模型质量检验。

RRF 使用排名而不是原始分数，这使全文检索与语义检索能够合并。先扩大候选集再融合，有助于保留不同通道发现的条目；默认结果最多八条是输出契约，不能理解为数据库只查八条候选。

哈希可以检验材料是否改变，不能凭空证明材料可信。这个项目同时固定官方来源、提交、版本和哈希，并要求内部手册显式受信任，才建立起可检查的来源链。知识块 ID 的作用是追溯具体片段，不能把一个 `KC-` 字符串随意编到报告里。

最后学习“验证范围”。单元测试看局部逻辑，数据库测试看实际查询机制，完整质量验收看固定数据和真实模型的召回表现。引用集合校验看的是存在与授权，安全分析还要看内容是否支持结论。这些验证互相补充，任何一项都不能代替其他项。

## Task 8：六角色 LangGraph 调查工作流

### 1. 任务目标

把告警调查组织成六个可观察、可恢复的业务角色，使一条演示告警经过证据收集、分析、人工审批、模拟处置和效果验证，并在证据不足时有界停止。

### 2. 设计初衷（为什么要做）

如果把全部调查工作塞进一次模型问答，初学者很难回答“现在做到哪一步了”“这个判断引用了哪条日志”“重启后从哪里继续”。Task 8 用 LangGraph 把过程拆开：每个角色负责一段工作，共享结构化状态，图决定下一步去哪里。六角色是六个业务节点，不是六个无限自主运行的模型进程；当前代码混合使用确定性规则、只读工具和模型。

| 角色 / 节点名 | 当前主要职责 | 输出的主要状态字段 |
|---|---|---|
| 告警分诊 / `triage` | 从业务存储加载事件关联的告警，进入分诊状态 | `alerts`、`status` |
| 证据收集 / `collect` | 通过三个只读 MCP 工具获取日志、上下文和 ATT&CK 知识 | `evidence`、`knowledge` |
| 威胁分析 / `analyze` | 从已有证据判断来源与攻击类型，校验引用 | `origin`、`classification` |
| 攻击链重构 / `reconstruct` | 按观察时间组织有证据引用的攻击步骤 | `attack_steps` |
| 响应决策 / `respond` | 生成风险、影响、预览、回滚和验证查询齐全的模拟方案 | `response_plan` |
| 效果验证 / `validate` | 重新查询证据，核对已批准的模拟动作及目标 | `validation_result` |

当前分诊节点主要加载告警，不能把原计划中的完整告警聚合、去重和风险评分算法都写成已经在此节点实现。当前 `validate` 是确定性检查；结构化模型调用主要用于 `analyze`、`reconstruct`、`respond`。

本任务延续公共契约：调查消费领域模型、RAG、三个只读 MCP 工具和 PostgreSQL Checkpointer，提供异步 `run_investigation(incident_id: str)` 与节点事件。所有安全结论必须引用存在的 Evidence ID；知识引用用于支持技术映射，不能代替日志证明某次攻击实际发生。`dataset_labels` 默认保持空，Agent 不读取 `labels/`、`attacks.log` 或攻击者真值。Strix 只提供架构参考，不引入它的 CLI、内部模块或运行依赖。

“能中断”是安全边界，“能恢复”是可靠性边界：人工批准前没有模拟动作；拒绝后保存理由并停止；数据库检查点保存过程，后端重启后才能找到待审批或待继续的调查。

### 3. 详细执行步骤

1. **先规定状态转换的行为，再阅读对应测试。** 原计划要求覆盖正常闭环、证据不足回退一次、第二次转人工、模型超时、审批拒绝、检查点恢复和验证失败。当前 `tests/agents/test_graph.py`、`test_nodes.py` 和 `test_acceptance.py` 分别覆盖图行为、节点边界和真实依赖验收。读测试时关注输入与断言，而不把“有测试代码”当成“本次已经测通过”。

2. **建立一份结构化调查状态。** `InvestigationState` 使用 `TypedDict` 描述字典字段，保存 `incident_id`、`trace_id`、状态、告警、证据、知识、来源、分类、攻击步骤、方案、审批、验证、模拟记录、回退计数、降级标记、错误与事件。状态采用可序列化数据，便于检查点保存。`TypedDict` 主要帮助类型检查，并不自动完成运行时校验；运行时依靠 Pydantic 领域模型和引用检查。

3. **让节点返回状态增量。** “增量”就是只返回这一步改变的字段。例如收集节点返回新的证据和知识，不必重新生成全部调查状态。当前普通字段合并时采用本次值，`events` 单独通过 `Annotated[..., add]` 追加；证据与知识由 `merge_by_id` 按 ID 合并，避免重查同一条记录就产生重复证据。不要把字典的所有列表都理解为自动追加。

4. **按六角色建立有向图，并设置分支。** 正常路线为 `triage → collect → analyze → reconstruct → respond → approval → simulate → validate`。`approval`、`simulate`、`retry`、`review` 是控制节点，不增加业务角色数量。`analyze` 缺少分类或返回 `unknown` 时，首次进入 `retry`，将 `fallback_count` 设置为 1，再到 `collect`；第二次仍不足进入 `review`，保存 `manual_review` 后结束。发生节点依赖错误通常进入 `failed`；非法证据引用转人工复核。它们都是明确的终态，不是无限继续尝试。

5. **把模型输出限制在 Schema 内，并统一重试预算。** Pydantic Schema 规定分析、步骤和方案的形状，禁止多余字段，约束 ID 长度、步骤顺序和模拟动作类型。模型输出还必须通过有效引用、来源实体真实出现、ATT&CK 技术有检索知识等校验。当前 `_structured` 的 `range(3)` 表示“首次调用 + 最多两次重试”，每次模型调用由 `asyncio.wait_for` 设置超时，默认 60 秒。模型客户端自身设为 `max_retries=0`，避免外层两次、内层又两次造成重试次数失控。最终只保存 `MODEL_TIMEOUT`、`MODEL_INVALID_OUTPUT` 等错误码，不保存可能带密钥的原始异常文字。

6. **提供 fixture / 规则降级。** `LLM_MODE=fixture` 时不调用云模型；模型不可用、超时或输出反复不合法时，也转用 `fallback.py` 的规则，并明确 `fallback_used=true`。`fallback_count` 是“证据不足回退次数”，`fallback_used` 是“是否用了规则降级”，二者含义不同。当前规则从已有日志的 HTTP 请求、路径、消息等观察字段识别 SQL 注入模式，按实际时间重构步骤，并从实际观察到的 IP 生成模拟方案；它不会凭空添加 Evidence ID，也不会凭告警标题或标签宣称攻击成功。只有检索结果中确有可信 T1190 知识时才映射 T1190，没有知识就保留空技术列表。

7. **在审批处中断，并把批准绑定到当时的方案。** `interrupt(...)` 保存等待人工的状态和方案摘要；审批接口之后通过 `Command(resume=...)` 恢复同一个 `thread_id`。恢复时检查审批的 `response_plan_id` 和 `plan_sha256`，防止用户批准 A 方案后实际执行已改动的 B 方案。`decided_by` 和理由必须有效；拒绝进入 `rejected` 并保留理由，不进入模拟和验证。这里的 `thread_id` 是 LangGraph 调查执行标识，当前取 `incident_id`，不是 Codex 聊天 ID。

8. **只记录白名单模拟动作，并再次取证验证。** 只允许 `block_ip_simulated`、`isolate_host_simulated`、`disable_account_simulated`；每个动作必须具有目标、风险、影响、预览、回滚和受限验证查询。当前执行器生成带 `simulated=true` 的记录，不调用真实防火墙、账号系统或主机隔离。验证节点重新查询证据，检查审批、动作和观察目标是否一致；有新证据不代表已经真的封禁流量。`success` 只表示本模拟闭环检查成功，`failure` 表示核对失败，`insufficient_evidence` 表示新证据不足，后者进入人工复核。

9. **接入 PostgreSQL 检查点和业务持久化。** `checkpoint.py` 用 `PostgresSaver` 管理检查点表，`setup()` 负责检查点结构准备；`services.py` 另行保存业务事件、角色运行、方案、审批、攻击步骤与验证结果。两者职责不同：检查点回答“下一步执行什么”，业务表回答“已经得到了哪些结果”。同步 psycopg 操作通过 `asyncio.to_thread` 移出异步事件循环，适配当前 Windows 子进程工具链。单进程异步锁和 PostgreSQL advisory lock 避免同一调查并发运行；动作记录用方案 ID 与序号生成执行标识，恢复路径和审批状态检查共同避免重复模拟。

10. **保留公共工具与环境约束。** 三个工具为 `search_security_events`、`get_alert_context`、`lookup_attack_technique`，不提供任意 Shell、任意文件读取或任意 URL 请求。公共上限为事件 `limit <= 200`、上下文单侧窗口 `<= 900` 秒、ATT&CK `<= 10` 条、单次工具超时 10 秒、最多两次重试。当前工作流收集常用 `limit=100`、窗口前后各 900 秒、知识检索 `limit=8`；效果验证不得扩大原调查时间和实体范围，结果上限不得超过该调查的 100 条。MVP 不引入 MySQL、Milvus、Neo4j、Redis，也不做真实封禁、账号禁用、隔离或公网扫描。

相关固定版本沿用准备书：项目 Python 3.12.14（系统 Python 3.13.6 保留）、uv 0.12.16、LangChain 1.4.1、LangGraph 1.2.11、langchain-openai 1.6.2、langgraph-checkpoint-postgres 3.1.2、langchain-mcp-adapters 0.3.2、mcp 1.30.0、Pydantic 2.13.5、pydantic-settings 2.15.0、SQLAlchemy 2.0.54、Alembic 1.20.0、psycopg[binary,pool] 3.3.5、PostgreSQL 17、pytest 9.1.1、pytest-asyncio 1.4.0。直接依赖固定精确版本，间接依赖由提交的 `uv.lock` 锁定；原计划开发基线是 Windows 10.0.26200.9457、WSL 2.7.3.0、Docker Engine 29.7.2 和 Docker Compose 5.5.0，Git 2.55.0、Node.js 24.15.0、pnpm 11.19.0 为仓库公共工具链。

### 4. 关键代码/命令示例

下面是 `state.py` 的**源码节选，省略了其他状态字段**；每一行注释说明其作用。此处只描述数据结构，不会启动调查。

```python
from operator import add  # 导入列表相加函数，供事件列表追加使用。
from typing import Annotated, Any, TypedDict  # 导入类型标注工具；它们不会替代运行时校验。
class InvestigationState(TypedDict, total=False):  # 允许节点只返回部分字段，便于表达状态增量。
    incident_id: str  # 关联业务事件，同时用于当前图的 thread_id。
    evidence: list[dict[str, Any]]  # 保存证据结构化记录，结论用 Evidence ID 引用它们。
    fallback_count: int  # 记录证据不足导致的回退次数，最多一次。
    fallback_used: bool  # 表示是否使用了 fixture 或规则降级。
    events: Annotated[list[dict[str, Any]], add]  # 为这个列表注册追加规则，保留先前节点事件。
```

下面是 `_analysis_route` 的**等价教学示例**，展示关键分支；真实函数还先处理 `failed`、`manual_review` 等状态，不能用此节选直接替换源码。

```python
def route_after_analysis(state):  # 根据当前分析结果选择下一节点。
    classification = state.get("classification") or {}  # 没有分类时使用空字典，安全读取字段。
    primary_type = classification.get("primary_type")  # 获取当前攻击类型判断。
    if primary_type in (None, "unknown"):  # 没有支持的类型时视为证据不足。
        return "retry" if state.get("fallback_count", 0) == 0 else "review"  # 首次回退，再不足则交给人工。
    return "reconstruct"  # 有受支持分类时继续攻击链重构。
```

下面是审批节点的**源码节选**，省略了决定保存与事件发布。它要放在 `build_graph()` 内部的 `approval(state)` 中阅读，依赖当前文件已经导入的 `interrupt`、`ApprovalRecord` 和 `_plan_hash`。中断会交给图保存执行位置；它不是通过一个线程一直阻塞着等待用户。

```python
plan = ResponsePlan.model_validate(state["response_plan"])  # 先确认当前方案符合领域契约。
digest = _plan_hash(state["response_plan"])  # 固定方案内容的摘要，供批准与执行前核对。
resume = interrupt({  # 在此保存检查点并把待审批信息交给调用方。
    "incident_id": state["incident_id"],  # 标识需要审批的业务调查。
    "response_plan": plan.model_dump(mode="json"),  # 让人工看到当时的完整方案。
    "plan_sha256": digest,  # 方案变化后不能沿用对旧内容的批准。
    "requires_approval": True,  # 明确必须经过人工决定。
})  # 恢复时 interrupt 返回调用方提交的决定数据。
record = ApprovalRecord.model_validate(resume["approval"])  # 校验审批人、理由、时间和决定。
if record.response_plan_id != plan.response_plan_id or resume.get("plan_sha256") != digest:  # ID 和内容都必须匹配。
    raise ValueError("approval does not match pending response plan")  # 不匹配就拒绝继续。
```

`Command(resume=...)` 将决定交回同一个检查点线程。下面是**等价教学示例**，需要已经创建的 `graph`、审批记录 `record` 与待审批快照 `pending`；公开业务入口还会加锁、检查状态并记录结果，因此不能绕过它直接给运行中的生产图注入决定。

```python
from langgraph.types import Command  # 使用 LangGraph 的恢复命令。
resume_data = {  # 组装与审批节点契约一致的恢复数据。
    "approval": record.model_dump(mode="json"),  # 把经过校验的人工记录转成可序列化字典。
    "plan_sha256": pending["plan_sha256"],  # 使用待审批快照里的摘要。
}  # 恢复数据不能自行变更当前响应方案。
await graph.ainvoke(Command(resume=resume_data), config={"configurable": {"thread_id": incident_id}})  # 在异步函数中恢复同一调查，而不是新建另一条执行。
```

**原计划命令原样保留，增加逐行注释；它们用于说明计划的验证与提交安排。当前用户要求不提交 Git，本次未执行以下命令。** 从当前仓库根目录运行第 2 行才具有正确的相对路径；准备书早期出现过的 `D:\桌面\传智杯` 是历史位置，当前工作区为 `D:\传智杯`。

```powershell
Set-Location "D:\传智杯" # 进入当前仓库根目录，使 services/backend 路径可解析。
uv run --project services/backend pytest services/backend/tests/agents -v # 原计划的完整图测试命令；当前目录内含会写真实服务的验收测试。
git add services/backend/src/evidencesoc/agents services/backend/tests/agents # 原计划暂存范围，仅保留记录，本次不执行。
git commit -m "feat: add six-role investigation workflow" # 原计划提交说明，仅保留记录，本次不提交。
```

**当前可运行的 fixture 学习验证命令**：下列选择的节点/图/模型测试使用测试替身，不调用云模型，不执行真实 PostgreSQL/OpenSearch 验收；需要已经安装项目锁定依赖。本次只核对代码，没有运行这些测试。

```powershell
Set-Location "D:\传智杯" # 从当前仓库根目录运行测试。
$env:LLM_MODE = "fixture" # 选择配置实际支持的 fixture 模式，而不是不存在的命令行参数。
uv run --project services/backend pytest services/backend/tests/agents/test_graph.py services/backend/tests/agents/test_nodes.py services/backend/tests/agents/test_model.py -v # 学习六角色、回退、审批和模型边界行为。
```

若需要真实闭环演示，已有 `services/backend/tests/agents/test_acceptance.py` 会读取 `data/samples/sql-injection.jsonl`，创建隔离索引和业务数据，启动新进程恢复 PostgreSQL 检查点，并在结束时清理。它需要已就绪的 PostgreSQL、OpenSearch、业务迁移和 ATT&CK 知识数据，**不是只读测试**，本次不执行。准备好演示环境后可运行：

```powershell
Set-Location "D:\传智杯" # 确保验收文件路径以仓库根目录为基准。
uv run --project services/backend pytest services/backend/tests/agents/test_acceptance.py -v # 运行真实依赖与跨进程恢复验收，会写演示服务数据。
```

`services/backend/README.md` 当前为空，不能声称它提供了 `--fixtures` 等演示参数。真实配置只接受 `LLM_MODE=fixture` / `LLM_MODE=deepseek`；真实验收测试显式构造 `Settings(llm_mode="fixture", opensearch_index=隔离索引)`，并使用已有 SQL 注入样例。

### 5. 核心文件说明

下列路径均相对于当前仓库 `D:\传智杯`。原计划要求创建的路径全部保留；实际新增辅助文件也列出，便于初学者沿调用方向阅读。

| 文件或目录 | 阅读时应理解的职责 |
|---|---|
| `services/backend/src/evidencesoc/agents/state.py` | 原计划文件；共享结构化状态及 `events` 的追加规则。 |
| `services/backend/src/evidencesoc/agents/nodes/*.py` | 原计划节点目录；当前六个方法集中在 `nodes/__init__.py` 的 `NodeHandlers`，没有必要虚构六个独立节点文件。 |
| `services/backend/src/evidencesoc/agents/graph.py` | 原计划文件；图连线、条件路由、引用闸门、审批中断、模拟执行、恢复和公开异步入口。 |
| `services/backend/src/evidencesoc/agents/fallback.py` | 原计划文件；允许的观察字段、SQL 模式判断、确定性攻击步骤与模拟方案。 |
| `services/backend/tests/agents/test_graph.py` | 原计划测试文件；六角色闭环、一次回退、拒绝、恢复、并发审批、事件回放等行为。 |
| `services/backend/src/evidencesoc/agents/models.py` | 节点输出 Schema 和三个模拟动作白名单；防止过长 ID、乱序步骤、任意动作与扩大验证查询。 |
| `services/backend/src/evidencesoc/agents/model.py` | 把筛选后的状态交给模型，使用结构化输出；提示词强调日志是不可信数据、结论必须有引用。 |
| `services/backend/src/evidencesoc/agents/checkpoint.py` | PostgreSQL 检查点、连接池和异步适配；检查点结构由 saver 的 `setup()` 准备。 |
| `services/backend/src/evidencesoc/agents/services.py` | 业务结果持久化与只读 MCP 调用；证据归属/哈希检查、角色运行去重和验证查询边界。 |
| `services/backend/tests/agents/test_nodes.py`、`test_model.py`、`test_services.py` | 节点、模型请求、服务持久化和工具契约的细粒度测试。 |
| `services/backend/tests/agents/test_api_trace.py`、`test_acceptance.py` | trace 在 MCP 调用链的传递、真实依赖六角色与跨进程恢复验收。 |
| `services/backend/migrations/versions/a8f02c68d901_add_investigation_terminal_states.py` | 扩展业务状态约束，允许明确保存 `manual_review` 与 `rejected`。 |
| `services/backend/src/evidencesoc/config.py`、`.env.example` | 实际支持的 fixture/deepseek 配置、数据库、搜索和知识目录；不能为演示随意杜撰参数。 |

### 6. 完成验证标准

原计划完成标志是“一条演示告警走完六角色、审批、模拟处置和验证，重启后能恢复”。进一步展开，应核对：

- 审批前为 `awaiting_approval`，有响应方案，有证据和步骤引用，没有模拟执行记录；批准后六个角色都留下可观察的开始/完成记录。
- 证据不足最多重新收集一次；第二次仍不足保存 `manual_review`，不生成没有依据的方案，不继续模拟。
- fixture 不调用云模型，输出结构化数据并标记 `fallback_used=true`；模型失败最多调用三次，错误信息不泄露密钥。
- 缺失、伪造或跨调查 Evidence ID 不能通过；来源 IP、主机、服务必须在引用证据中出现，评测真值不能进入调查事实。
- 审批必须对应当前待批准方案；拒绝保留理由；重复或并发审批不能重复模拟；修改过的方案不能沿用旧批准。
- 真实 PostgreSQL 检查点能在新进程中恢复；已模拟后重启应继续验证，而不是再模拟一次。内存检查点单元测试不足以证明进程重启持久性。
- 验证重新查询新证据，区别模拟成功、失败与证据不足；任何 `success` 都必须明确仅验证模拟，不声称真实封禁或漏洞利用成功。

本次为文档整理，仅阅读了代码与测试，未执行写服务的测试、真实闭环验收或重启实验。因此以上是验收要求和已有测试覆盖点，不能当成本次新测得的结果。

### 7. 初学者学习要点

把图想成业务流程图，把状态想成所有角色共同更新的一份调查表，把增量想成一个角色只填写自己负责的几栏。节点负责计算，路由负责决定顺序，Schema 负责约束数据，引用校验负责确认来源，这几层解决的是不同问题。

分清三种“再来一次”：证据不足回退重新收集、模型调用重试、服务重启从检查点恢复。它们分别由 `fallback_count`、模型重试预算、持久化检查点管理，不应共享一个含糊的“重试次数”。同样，fixture 是模型降级策略，不会自动取消数据库、搜索、MCP 等业务依赖。

人工审批也不是一个界面按钮那么简单。它需要中断位置、持久化决定、审批人和理由、方案摘要、恢复命令以及重复执行防护。一个流程“已保存 approved 字段”并不等于可以随意执行任何方案。

最后，观察到 SQL 注入请求、推测它可能对应某项 ATT&CK 技术、证明成功利用、证明处置真正生效，是四种不同强度的结论。当前规则演示主要建立前两类事实与映射，并验证模拟流程；证据不足时保留未知，比输出漂亮但无来源的结论更可靠。

## Task 9：FastAPI、SSE 和审计

### 1. 任务目标

把 Task 8 工作流接入可校验的 REST API 和可断线回放的 SSE，持久化告警幂等与人工决定，并为整次调查留下可追踪、无明文秘密的审计日志。

### 2. 设计初衷（为什么要做）

前端需要用 HTTP 创建调查、查看结果和提交审批，但一次调查可能比一次 HTTP 请求长得多。如果调查直接依赖浏览器连接，刷新页面就可能把过程打断；如果事件只存在内存里，重启后也无法给用户补发关键状态。Task 9 因此把 HTTP 请求、后台调查任务、持久化状态和 SSE 订阅分开：请求提交工作，后台任务继续运行，SSE 负责读取已经保存的事件。

幂等解决“相同告警因网络重试被创建两遍”；审批防重解决“重复点击或并发请求引发重复处置”；trace ID 解决“前端错误、HTTP 审计、角色和工具记录如何串起来”；日志脱敏解决“排查问题时不能顺手泄露凭证”。这些都是对真实业务问题的约束，而不只是给接口加几个字段。

本任务消费 Task 8 工作流，面向准备书第 4.2 节的 REST/SSE 公共契约。相关固定版本为 FastAPI 0.141.1、sse-starlette 3.4.11、structlog 26.1.0、httpx 0.28.1；Python、uv、Pydantic、SQLAlchemy、psycopg、Alembic 和 PostgreSQL 版本沿用 Task 8 的固定基线。

### 3. 详细执行步骤

1. **先列出接口契约和失败行为。** 当前请求模型禁止额外字段，约束标题、ID 长度、分页大小和时区时间；创建调查必须在 `alert_id`、`incident_id` 中恰好提供一个；审批与拒绝必须给出 `reason`、`decided_by`。原计划失败测试覆盖幂等告警、非法请求、调查创建、SSE 顺序、断线重连、重复审批和统一错误体。

| 方法与公共路径 | 当前职责与需要注意的状态 |
|---|---|
| `POST /api/v1/alerts` | 接入告警，支持 `Idempotency-Key`；首次 201，相同请求重放 200，冲突 409。引用的源日志事件必须已经存在。 |
| `GET /api/v1/alerts` | 按 `page`、`page_size` 分页，可按 severity、status 筛选；每页上限 200。 |
| `GET /api/v1/incidents/{id}` | 聚合持久化事件、证据、知识、攻击链、角色运行、方案、审批和验证结果。 |
| `POST /api/v1/investigations` | 新建调查通常 202，复用既有调查为 200；返回 `investigation_id`、`incident_id`、`trace_id` 与 `stream_url`。 |
| `GET /api/v1/investigations/{id}/stream` | 按递增序号读取持久化 SSE 事件，支持 `Last-Event-ID`。 |
| `POST /api/v1/response-plans/{id}/approve` | 接受当前待审批方案的批准决定，返回 202，后台恢复工作流。 |
| `POST /api/v1/response-plans/{id}/reject` | 接受拒绝及理由，返回 202，后台恢复到拒绝终态。 |
| `GET /api/v1/evaluations/{id}` | 已实现读取 `EvaluationRunTable` 中已有评测记录；不存在则 404。它不等于已经实现 Task 13 的完整实验执行、评分和结果生产流程。 |
| `GET /health/live` | 检查进程存活，不要求所有业务依赖健康。 |
| `GET /health/ready` | 检查工作流恢复准备情况、数据库与 OpenSearch；依赖不可用返回 503。 |

表中的 `{id}` 是公共契约写法，当前源码分别使用 `incident_id`、`investigation_id`、`plan_id`、`evaluation_id` 等参数名，实际 URL 含义相同。

2. **把幂等与调查元数据放入数据库。** `ApiStore.ingest_alert` 规范化请求后计算 SHA-256，保存幂等键、请求摘要和告警 ID。同一键同一内容返回已有告警；同一键换内容返回冲突，不能偷偷修改旧告警。显式提供的 `alert_id` 同样做内容一致性检查。创建调查按事件复用已有调查，数据库对 `incident_id` 设置唯一约束；数据事务和锁帮助处理并发请求，而不只靠进程内字典。

3. **由后台 Runner 执行工作流。** `InvestigationRunner.start` 先持久化 `investigation.started`，再调度后台任务。SSE 请求只读取存储，不启动一个新的六角色工作流。创建请求返回 202 表示“已接受”，不表示“六角色已经全部完成”。启动时 `recover()` 扫描未终结调查；待人工审批且没有决定的调查继续等待，已有 `pending_decision` 的调查可以恢复。主程序还会定期重试准备与恢复，依赖恢复后可继续服务。

4. **把图内部事件转换成固定 SSE 事件。** 图内部使用 `node.started`、`node.completed`、`approval.decided` 等事件；Runner 转成公共事件名并带上调查 ID、事件 ID 和 trace。公共事件固定为 `investigation.started`、`agent.started`、`evidence.added`、`agent.completed`、`approval.required`、`decision.recorded`、`validation.completed`、`investigation.failed`、`investigation.completed`。节点失败也通过 `agent.completed` 携带失败状态，整个调查随后进入相应终态。拒绝终态当前通过 `investigation.completed` 携带 `status=rejected` 表达，前端必须读取数据状态，不能只看事件名字推断批准成功。

5. **为持久化事件分配递增序号并去重。** `api_investigation_events` 以调查 ID 和 `sequence` 作为复合主键，每个调查自己的事件从 1 递增，不是全系统共用一个序号。`append_event` 在锁定调查记录的事务中增加 `last_sequence`，并使用 `dedup_key` 避免恢复时重复发布同一源事件或同一条证据。同一去重键若对应不同内容会报冲突。`finalize` 把终态事件、API 状态和业务事件状态在一个事务里提交，避免看到 completed 却漏掉末尾事件。

6. **实现 SSE 断线回放。** 首次订阅游标为 0；客户端记住最后处理的 `id`，重连时通过 `Last-Event-ID` 传回，服务端只查询 `sequence > cursor` 的事件。非 ASCII 数字、负数或超过当前最大序号的游标返回 422。响应使用 `text/event-stream`，带 `id`、`event`、JSON `data`；15 秒心跳、10 秒发送超时，当前循环每 0.05 秒查看新事件。终态前再补查一次尾部事件，减少完成瞬间漏发的风险。浏览器断线只是结束该订阅，后台调查继续。回放不能保证前端业务副作用自动只发生一次；前端也应按事件 ID 去重，并在重连后通过详情接口核对状态。

7. **先保存人工决定，再恢复图。** `record_decision` 检查方案是否属于当前调查、状态是否 `awaiting_approval`、是否已有审批或待处理决定，再把 `pending_decision` 持久化。HTTP 层随后发布 `decision.recorded` 并调度恢复；工作流使用 Task 8 的方案摘要与 `Command(resume=...)`。重复审批当前返回 409，不是再执行一次。若在决定已保存、图尚未消费时进程退出，启动恢复仍可找到这份决定。

8. **统一错误体和 trace。** 正常调查生成持久化 trace ID，创建、详情、SSE、审批和工具调用沿用它；一般 HTTP 请求先生成请求 trace，关联调查后切换到调查 trace。响应头提供 `X-Trace-ID`，错误体采用 `error.code`、`error.message`、`error.trace_id`。404、409、422、503 有稳定含义。验证错误不直接返回 Pydantic 原始错误详情，因为其中可能包含用户提交的秘密。

9. **在最终日志出口统一脱敏。** `logging.py` 同时处理 structlog 和普通 Python/第三方库 logging，在 JSON 渲染前递归清理敏感字段、SecretStr/SecretBytes、URL 凭证、查询参数、Bearer/Basic 认证、API Key、密码和已注册密钥的编码形式；异常仅保留类型，删除可能带秘密的堆栈文本。主程序启动时注册配置中的秘密，并关闭 uvicorn 默认访问日志。HTTP 审计只记录 method、路由模板、status_code、duration_ms、trace_id，不直接记录完整 URL、请求体、Cookie 或 Authorization。SSE 发布输出还会去掉原始日志 `raw` 并脱敏，避免把未过滤日志整包展示给前端。脱敏规则仍需持续用测试验证，不能以“用了 structlog”推断已经安全。

10. **做契约、恢复和性能验收。** SQLite/内存检查点测试适合先验证 API 行为，真实 TCP、PostgreSQL、OpenSearch、MCP 验收再检查跨进程恢复、并发审批、断线回放和日志。原计划性能要求为“不含模型调用的普通 API 本机 P95 < 500 ms；创建调查后 2 秒内收到首个 SSE 事件”。P95 指 95% 的样本耗时不超过该值，并非一次请求快就达标。当前真实验收测试对告警列表和事件详情各采样 100 次，另检查首个 TCP SSE 事件用时；它们是已写入测试的要求，本次没有执行、没有测量数据。

### 4. 关键代码/命令示例

下面是 `sse.py` 的**教学节选**，省略轮询、终态补发和连接检查；它说明持久化记录如何成为 SSE 帧，每条有效代码都有逐行注释。

```python
import json  # 将事件数据序列化为 SSE 的 JSON data 字符串。
async def replay_frames(runner, investigation_id, cursor):  # 使用已有 Runner 和客户端最后确认的序号。
    pending = await runner.call("list_events", investigation_id, cursor)  # 从存储查询大于游标的事件，按序号排序。
    for item in pending:  # 依次发送持久化记录，不能随意重排。
        cursor = item["id"]  # 记录本次已发送事件的序号。
        yield {  # 交给 EventSourceResponse 构造 SSE 帧。
            "id": str(cursor),  # SSE id 是文本；客户端用它恢复读取位置。
            "event": item["event"],  # 使用约定的公共事件名称。
            "data": json.dumps(item["data"], ensure_ascii=False),  # 保留中文，发送结构化事件数据。
        }  # 结束当前帧；完整接口还会继续等待新事件。
```

下面是调用实际 `redact` 的**可独立理解的教学示例**；示例值均为虚构测试文本，不是真实凭证。

```python
from evidencesoc.logging import redact  # 导入生产日志也使用的递归脱敏函数。
sample = {"Authorization": "Bearer demo-token", "nested": {"password": "demo-password"}}  # 构造顶层和嵌套敏感字段。
clean = redact(sample)  # 返回脱敏副本，敏感值变成 [REDACTED]。
assert clean["Authorization"] == "[REDACTED]"  # 确认认证字段不会原样输出。
assert clean["nested"]["password"] == "[REDACTED]"  # 确认嵌套密码同样被处理。
```

**原计划提交命令原样保留，当前不执行、不提交 Git。** 计划没有给 Task 9 单独的 pytest 命令；下面另列当前实际测试命令。

```powershell
Set-Location "D:\传智杯" # 当前仓库根目录，不是历史的 D:\桌面\传智杯。
git add services/backend/src/evidencesoc/api services/backend/tests/api # 原计划暂存 API 和测试；本次只保留记录。
git commit -m "feat: expose investigation and approval APIs" # 原计划提交说明；按用户要求本次不提交。
```

**当前可运行的 API 学习测试命令**：只选择本地测试替身文件，排除真实服务验收；本次未执行。

```powershell
Set-Location "D:\传智杯" # 从仓库根目录解析项目和测试路径。
$env:LLM_MODE = "fixture" # 使用真实支持的配置值，不需要模型密钥。
uv run --project services/backend pytest services/backend/tests/api/test_investigation_flow.py services/backend/tests/api/test_storage.py services/backend/tests/api/test_runner.py services/backend/tests/api/test_logging.py services/backend/tests/test_openapi_contract.py -v # 验证流程、持久化行为、后台调度、脱敏和 OpenAPI 契约。
```

**当前后端启动命令**：需要 `.env` 与已就绪的 PostgreSQL、OpenSearch、业务迁移及知识数据；fixture 仅替代模型，不替代这些依赖。README 当前为空，命令依据 `main.py`、`config.py` 和真实 TCP 验收子进程核对。主程序恢复任务可能写入业务与检查点，本次未启动。

```powershell
Set-Location "D:\传智杯\services\backend" # 在后端目录使用其 pyproject.toml 与 uv.lock。
$env:LLM_MODE = "fixture" # 选择规则模式；实际只有 fixture/deepseek 两个模式。
uv run uvicorn evidencesoc.main:app --host 127.0.0.1 --port 8000 --loop asyncio --no-access-log # 启动 FastAPI，保留统一审计入口并关闭默认访问日志。
```

启动后可从另一个 PowerShell 终端只读检查，不要把 live 成功误当成依赖 ready：

```powershell
Invoke-RestMethod -Uri "http://127.0.0.1:8000/health/live" # 检查进程是否存活。
Invoke-RestMethod -Uri "http://127.0.0.1:8000/health/ready" # 检查业务依赖是否就绪，不就绪会返回 503。
Invoke-RestMethod -Uri "http://127.0.0.1:8000/api/v1/alerts?page=1&page_size=50" # 读取告警分页，为后续调查选择已有告警 ID。
```

**告警幂等教学示例**：下面两个 POST 会创建或复用告警；`SE-替换为已导入事件ID` 必须换成 Task 5 已经持久化的真实事件，不能只构造一个形状正确的 ID。本次没有执行请求。第一次通常返回 201，完全相同的第二次返回 200 并复用告警；保持同一个键但改变内容应返回 409。

```powershell
$apiBase = "http://127.0.0.1:8000" # 访问已启动的本机服务。
$alertHeaders = @{ "Idempotency-Key" = "teaching-alert-001" } # 用业务稳定标识表达这是同一次逻辑接入。
$alertBody = @{ title = "SQL 注入教学告警"; severity = "high"; event_ids = @("SE-替换为已导入事件ID") } | ConvertTo-Json # 关联已导入事件，示例不含评测答案。
$firstAlert = Invoke-RestMethod -Method Post -Uri "$apiBase/api/v1/alerts" -Headers $alertHeaders -ContentType "application/json" -Body $alertBody # 首次接入并保存请求摘要和幂等键。
$replayedAlert = Invoke-RestMethod -Method Post -Uri "$apiBase/api/v1/alerts" -Headers $alertHeaders -ContentType "application/json" -Body $alertBody # 重放完全相同请求，服务应返回已有记录。
$firstAlert.alert_id -eq $replayedAlert.alert_id # 应为 True；结果相同才说明重放没有创建第二个告警。
```

**真实流程调用教学示例**：把示例告警 ID 替换为分页结果或上述接入结果中已存在、且关联原始事件及合适时间的演示告警，才可实际运行。下面调用会创建调查和记录审批，不是本次执行记录。先运行创建和详情读取，待详情返回 `awaiting_approval` 后人工阅读 `response_plan.actions` 的风险、影响、预览、回滚与验证查询，再选择批准或拒绝；不要一次粘贴全部命令就当作完成审批。

```powershell
$apiBase = "http://127.0.0.1:8000" # 指向已启动的本机 API。
$demoAlertId = "AL-替换为实际演示告警ID" # 这是占位符，必须换成已有告警的真实 ID。
$investigationBody = @{ alert_id = $demoAlertId } | ConvertTo-Json # 创建调查时只提供 alert_id，不同时提供 incident_id。
$createdInvestigation = Invoke-RestMethod -Method Post -Uri "$apiBase/api/v1/investigations" -ContentType "application/json" -Body $investigationBody # 接受调查并获取业务 ID、trace 和 stream_url。
$detail = Invoke-RestMethod -Uri "$apiBase/api/v1/incidents/$($createdInvestigation.incident_id)" # 读取详情；异步调查可能尚未到审批，需要稍后再读。
$planId = $detail.response_plan.response_plan_id # 只有详情已到 awaiting_approval 且方案存在时才能使用此 ID。
$decisionBody = @{ reason = "已查看风险、影响、回滚和验证查询，同意模拟"; decided_by = "demo-reviewer" } | ConvertTo-Json # 由人工审查后的明确决定构造请求。
Invoke-RestMethod -Method Post -Uri "$apiBase/api/v1/response-plans/$planId/approve" -ContentType "application/json" -Body $decisionBody # 仅在人工决定批准时调用；拒绝应改用 reject 并填写真实拒绝理由。
```

SSE 可用 Windows 的 `curl.exe`，不要误用 PowerShell 可能映射的 `curl` 别名。连接通常会持续等待；使用同一个调查 ID，保存最后已处理序号后重连：

```powershell
curl.exe -N "http://127.0.0.1:8000$($createdInvestigation.stream_url)" # 首次订阅现有调查，-N 关闭输出缓冲，显示 id/event/data。
$lastSeenEvent = "3" # 教学占位序号；必须替换为该调查实际已处理的最后事件 ID。
curl.exe -N -H "Last-Event-ID: $lastSeenEvent" "http://127.0.0.1:8000$($createdInvestigation.stream_url)" # 断线后仅补发大于该序号的事件，不创建新调查。
```

**真实验收命令**：以下测试会写真实数据库、搜索索引、运行检查点或启动 API 子进程；需准备演示环境，本次未执行。`EVIDENCESOC_TEST_POSTGRES=1` 是连接恢复测试的显式开关，不是 fixture 参数。

```powershell
Set-Location "D:\传智杯" # 从仓库根目录定位验收文件。
uv run --project services/backend pytest services/backend/tests/api/test_live_acceptance.py -v -s # 实测 TCP 流程、重启回放、并发审批、P95、首事件和秘密脱敏，会写真实服务。
$env:EVIDENCESOC_TEST_POSTGRES = "1" # 显式允许 PostgreSQL 连接恢复专项测试。
uv run --project services/backend pytest services/backend/tests/api/test_checkpoint_recovery.py -v # 创建检查点并中断该测试自己的数据库连接，验证恢复能力。
```

### 5. 核心文件说明

| 文件或目录（相对 `D:\传智杯`） | 职责与原计划对应关系 |
|---|---|
| `services/backend/src/evidencesoc/api/alerts.py` | 原计划文件；告警接入、`Idempotency-Key`、分页筛选。 |
| `services/backend/src/evidencesoc/api/investigations.py` | 原计划文件；创建调查、事件详情、已有评测结果读取。 |
| `services/backend/src/evidencesoc/api/responses.py` | 原计划文件；批准/拒绝，先保存决定再调度图恢复。 |
| `services/backend/src/evidencesoc/api/sse.py` | 原计划文件；游标校验、持久化事件回放、心跳、终态补发和连接结束。 |
| `services/backend/tests/api/test_investigation_flow.py` | 原计划测试文件；API 闭环、幂等、统一错误、重连、拒绝、重复审批与依赖恢复。 |
| `services/backend/src/evidencesoc/api/models.py` | 严格请求模型、返回 Schema、统一错误体及 OpenAPI 错误声明。 |
| `services/backend/src/evidencesoc/api/storage.py`、`tables.py` | 持久化幂等键、请求摘要、调查状态、待处理决定与有序去重事件；终态原子提交。 |
| `services/backend/src/evidencesoc/api/runner.py` | 后台任务、启动恢复、图事件到公共 SSE 事件的转换、去 raw 与脱敏。 |
| `services/backend/src/evidencesoc/api/dependencies.py`、`errors.py` | 从请求获取 Runner，统一安全错误映射，避免回显请求秘密。 |
| `services/backend/src/evidencesoc/logging.py` | 统一 JSON 日志出口、敏感值注册、嵌套字段和文本脱敏。它是单个文件，不是 logging 目录。 |
| `services/backend/src/evidencesoc/main.py` | 应用生命周期、路由注册、后台恢复、HTTP 审计、live/ready 和依赖检查。 |
| `services/backend/migrations/versions/b6d091c3e217_add_durable_api_coordination.py` | 新增 `api_alert_payloads`、`api_idempotency_keys`、`api_investigations`、`api_investigation_events` 及唯一/序号约束；接在终态扩展迁移后。 |
| `services/backend/tests/api/test_storage.py`、`test_runner.py`、`test_logging.py` | 持久化、任务竞争/恢复、递归脱敏与异常清理的针对性测试。 |
| `services/backend/tests/api/test_live_acceptance.py`、`test_checkpoint_recovery.py` | 真实 TCP 及依赖验收、数据库连接恢复；包含服务写入，不能当作只读检查。 |
| `services/backend/tests/test_openapi_contract.py` | 核对 API 路由与生成契约，包括已经存在的评测结果读取路径。 |

### 6. 完成验证标准

原计划完成标志是“浏览器断线重连不丢关键状态，日志中无明文秘密”。验收时应逐项核对：

- 相同 `Idempotency-Key` 与相同请求重放得到同一告警；修改内容报 409；存储重启后幂等仍然成立。
- 非法请求返回统一错误体；输入正文、查询参数或请求头中的秘密不能出现在错误响应和日志中。
- 创建调查得到可追踪 ID 和 SSE 地址；六角色事件顺序可解释，每个调查的事件序号递增，所有事件都沿用该调查 trace。
- 重连传 `Last-Event-ID` 后只获取更新事件；关键状态和终态不丢，后端重启后可以从持久化事件补发；SSE 断开不取消后台调查。
- 批准前没有模拟，拒绝停止并保留理由；重复或并发审批只接受一次；已保存但未消费的决定重启后仍能恢复。
- HTTP 审计至少有 method、路由模板、status_code、duration_ms、trace_id；Authorization、Cookie、API Key、密码、模型密钥、URL 凭证、异常文字和编码形式的秘密不得进入日志。
- `/health/live` 与 `/health/ready` 含义分明；依赖故障时 ready 为 503，恢复后重新可用；评测读取只返回已有记录，无记录为 404。
- **性能要求：** 不含模型调用的普通 API 本机 **P95 < 500 ms**；从创建调查开始到收到首个 SSE 事件 **< 2 秒**。测试必须说明采样数量、接口、硬件/依赖环境和计时起点，不能用模型完成耗时替代普通 API 延迟。

本次没有启动后端、写演示数据或执行验收测试，也没有新的 P95 或首 SSE 测量结果。源码中存在相关断言，可以说明“已提供验证方式”，不能写成“本机性能已达标”。

### 7. 初学者学习要点

HTTP 202 表示服务接受了请求；工作流状态才回答业务是否完成。SSE 是服务端持续推送事件的单向通道，不是客户端发审批命令的地方；审批仍走 POST。先分清“命令接口”和“状态订阅”，就能理解为什么断线不应把调查取消。

持久化有三个互补层面：业务结果供详情查询；LangGraph 检查点供工作继续；API 事件供前端回放。只保存其中一个，无法同时保证结果查询、过程恢复和实时界面恢复。幂等、去重键、唯一约束和事务也各有职责，不是加上一个请求头就自然可靠。

`trace_id` 是定位同一次调查的线索，SSE `id` 是该调查中事件的位置，Evidence ID 是事实来源，`response_plan_id` 是审批对象。不要把它们混作一个 ID，更不要通过仅有 trace 就认定某个事实有证据。

安全日志的关键是控制记录范围和最终输出边界：审计只记录需要排障的元信息，再统一脱敏；不要先把整份请求、响应或异常堆栈写入磁盘，再指望之后清理。阅读测试时同时练习正常行为、异常行为、恢复行为和可观测性，才算理解一套 API 如何支撑可靠工作流。
