# Task10 前端运营与调查界面操作指南

## 当前状态与验收入口（2026-10-18）

本节为当前执行口径；后面的 2026-09-28 起步步骤及分阶段验证记录保留为历史资料。Task10 原功能验收为 105 项单元测试、61 项浏览器测试通过，浏览器失败、跳过和 flaky 均为 0，lint、typecheck 和生产构建通过。61 项是模拟 API 边界及真实后端用例的混合回归；真实批准、拒绝闭环使用 `LLM_MODE=fixture` 规则模式，不代表真实模型能力或全部用例均接入真实后端。见 [2026-10-16 集成记录](../../acceptance/task12-integration-2026-10-16.json)和 [2026-10-18 证据复核](../../acceptance/task1-12-verification-2026-10-18.json)。这些历史数量和报告保持原样。

维护代码提交为 `5646db4`，后端两个 P2 及生产发现的审批后轮询缺陷均已关闭。后端全量 747 项无跳过、搜索相关 215 项、SSE 21 项、验收入口 18 项、前端 110 项及最终生产浏览器 62 项通过，静态门禁与新正常校准 MCP live/隔离/清理通过。最终生产无失败、跳过、flaky 或重试，源码和知识输入前后未变。详细证据见 [readiness 维护小节](../../acceptance/task12-readiness.md)及已验收的 [维护记录](../../acceptance/task12-maintenance-2026-10-18.json)；旧 JSON/JUnit 和冻结数据保持原样。维护分支的本地 main 整合另记。

日常启动以 [前端 README](../../../apps/web/README.md)及现有配置为准，默认访问 `http://127.0.0.1:3000`。`BACKEND_URL` 由前端服务进程读取，指向 FastAPI；前端、后端两个进程的 `FRONTEND_ORIGIN` 必须与实际浏览器来源精确一致。后端源码默认 `LLM_MODE=fixture`、`DEMO_SESSION_ENABLED=false`；需要本地演示账户时显式开启后重启后端。不要因使用了不同的 `localhost` 来源而放宽 Origin 校验。

历史第 1～3 节的分支创建、追加依赖、测试配置/主题重建，以及第 3.2、4.1 节的页面生成器不应在现有实现上重新执行；这会覆盖已完成的业务实现或改写锁定环境。历史第 5～7 节关于缺少端点、代理、会话和 SSE 的判断也不是当前缺口清单。历史命令和勾选不等于现在仍需安装或重新开发；先核对现有文件与验收记录，新增工作只按本节待执行范围开展。

### 已实现：生产模式与隔离启动

统一入口为 [scripts/task10_browser_acceptance.py](../../../scripts/task10_browser_acceptance.py)。从当前独立 checkout/worktree 的仓库根目录执行；使用锁定的 backend Python 环境及 pnpm，无需硬编码本机路径。先通过安全进程环境设置三个必要变量：`TASK10_POSTGRES_ADMIN_URL` 为有创建/删除本轮测试库及准备 `vector` 权限的本地管理连接，`OPENSEARCH_URL` 为可创建/删除本轮索引的本地服务，`RAG_DATA_DIRECTORY` 为含固定 STIX、manifest 和完整模型的已准备离线目录。不要把凭据写在命令参数或报告中；两个服务 URL 拒绝 query/fragment，checkout 中除 `.env.example` 外的隐式 dotenv 输入会被拒绝。详细准备见 [前端 README](../../../apps/web/README.md)。

```powershell
uv run --project services/backend python scripts/task10_browser_acceptance.py --web-mode production --api-port 8018 --web-port 3018 --artifacts-root .backups/task12-browser-acceptance
```

单独验证开发模式时，选择另一组空闲端口和独立报告目录：

```powershell
uv run --project services/backend python scripts/task10_browser_acceptance.py --web-mode dev --api-port 8019 --web-port 3019 --artifacts-root .backups/task12-browser-acceptance
```

- Playwright 的 `PLAYWRIGHT_WEB_MODE=dev|production` 默认 `dev`，未知值失败；统一入口默认 `production`。生产先运行 `build`，成功后才用 `start`，失败不复用旧产物；开发使用 `dev`。两种模式禁止复用现有 Web 进程，使用单 worker、零重试，端口占用即失败。
- 每次分配独立运行 ID、数据库、OpenSearch 索引和报告目录；入口准备扩展/迁移、离线知识、样例、后端及真实用例变量，统一代理地址和前后端 `FRONTEND_ORIGIN`。真实用例准备不足即失败，不转换为 skip。不要手动把代理与直连检查指向不同后端。
- 清理仅处理本轮创建的进程、索引和数据库，各项独立尝试并记录结果；任何清理失败都否决验收。运行前后校验源码及知识 hash，步骤日志脱敏并保留失败报告，不依赖旧忽略目录中的脚本。
- 全量浏览器回归混合模拟接口和真实服务；报告必须按实际用例区分，不能只凭 `*-live.spec.ts` 文件名分类。统计读取与写入串行，各真实调查使用独立告警、幂等键及浏览器 context；开发和生产报告独立保留。

### 已实现：续办 SSE 输出兼容与真实用例

续办事件仅在后端 `api/sse.py` 输出层，将已有持久化的 `plan.renewal_requested`、`plan.renewed` 映射为既有 `status`，提供 `status=reconstructing`。原生产者、持久化事件名及载荷、事件 ID/顺序和去重键保持原样；主回放与终态 tail 共用适配，真正未知事件仍 reset。新方案实际就绪后继续发布 `approval.required`，不把旧方案续办提前解释为新方案已可审批。后端相关专项 21 项通过；前端沿用已有公共事件名。

`responses.spec.ts` 保留模拟接口的受理/链接测试；新增 `response-renewal-live.spec.ts` 使用本轮拥有的真实案件与过期准备辅助函数，在原生 EventSource 已连接后通过页面续办，检查状态、新方案审批事件及无 `UNKNOWN_EVENT` reset。该辅助函数只接受本轮库与本轮案件，不提供生产强制过期 API；用例不替换 EventSource 或模拟后端响应。它还检查旧方案不可审批、新方案须人工批准、游标重连、模拟验证及刷新后的状态。

首轮生产 `maintenance_prod_a` 的构建成功，浏览器 60 通过、2 失败、0 跳过/重试，验收失败记录和成功清理证据保留。该轮发现验证结果先落库时页面会提前停止轮询；现改为案件终态后才停止，保证随后落库的模拟执行快照能被刷新，新回归已纳入 110 项前端单元通过结果。新 SSE 用例的空闲连接等待也已覆盖既有心跳周期，保留原生事件断言。

最终 `maintenance_prod_b` 的生产构建及 62 项浏览器测试通过：6 项真实服务契约/流程、7 项真实服务外壳 smoke、49 项模拟 API 边界；0 失败/跳过/flaky/重试。它覆盖批准、拒绝、续办、游标恢复、刷新及会话/Origin，源码/知识输入未变，六项清理成功。报告保存模式、用例分类、计数、受测提交/hash、案件 ID、报告 hash 和失败历史，不能只以最终 REST 快照证明 SSE 兼容。Task13 正式模型运行数仍为 0，截止日期、负责人、投入和模型/费用上限仍待补充；Task14 总验收与 Task15 材料不因本轮维护通过而自动完成。

---

## 历史操作正文（2026-09-28 起）

更新：2026-09-28，已按 Task8、Task9 合入 main 后的实际代码调整。

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** 按已有前端设计，让用户通过界面完成告警、调查、证据查看、人工决定、模拟处置和验证。

**Architecture:** 在现有 `apps/web` 的 Next.js App Router 中开发。页面壳共享主题与导航，业务交互按 feature 拆分；普通请求与 SSE 通过同源代理连接 FastAPI。后端业务数据为真源，前端样例仅用于开发和可重复测试。

**Tech Stack:** 已有 Next.js、React、TypeScript、TanStack Query、React Flow、ECharts、Vitest、Playwright；新增 Ant Design、Next.js 样式 Registry、Dagre。

## 全局约束与本次核对结果

- 开源、免费、自托管；只允许模拟处置。
- 以 `docs/EvidenceSOC-前端完整设计与实施方案.md` 的 1.2 版为视觉依据。
- 批准和拒绝均要求填写理由；调查完成与验证成功分别显示。
- 宽屏调查 3:6:3，空间不足使用证据抽屉；审批宽屏 7:3，窄屏自然重排。
- 后端返回的未知字段显示“未提供”，不得从样例补造正式结果。
- `generated.ts` 从实际 OpenAPI 生成，不手改。
- 本轮只更新操作说明与接入示例，未安装依赖、启动服务或实现 Task10 业务页面。

**关键分支情况（2026-09-28）：** Task8（`8f18d44`）、Task9（`57bf2a0`）已快进合并到本地 `main`，HEAD 为 `1f1dbfa`。开始 Task10 时直接从 main 创建开发分支。前端设计文档中“HTTP 只有健康检查”的基线是合并前记录，现在应以实际 `api/` 代码及 OpenAPI 为准。

现有工作区还有未跟踪的设计资料。先看 `git status`，保留这些资料；不要执行 `git reset --hard` 或 `git clean`。

---

## 1. 从 main 创建 Task10 分支

- [ ] 在 PowerShell 中执行：

```powershell
Set-Location 'D:\传智杯'
git status --short
git log -3 --oneline main
git switch -c codex/task10-frontend main
git branch --show-current
Test-Path 'services/backend/src/evidencesoc/api/investigations.py'
```

最后两项应分别得到 `codex/task10-frontend` 和 `True`。如果该 Task10 分支已经创建，使用 `git switch codex/task10-frontend`，不要覆盖已有分支。

如果 Git 提示现有修改会被覆盖，先保存对应改动再切换，不强制切换。不要把所有现有未提交文件当成 Task10 新增内容。

- [ ] 打开设计预览：

```powershell
Start-Process -FilePath 'D:\传智杯\docs\frontend-previews\index.html'
```

依次查看总览、调查、审批和颜色规范；在调查页点击步骤，观察证据联动；缩窄窗口观察抽屉。预览是设计参照，不连接后端。

## 2. 安装缺少的前端依赖并启动

- [ ] 在项目根目录执行：

```powershell
node --version
pnpm --version
pnpm install --frozen-lockfile
pnpm --dir apps/web add --save-exact antd@6.6.5 @ant-design/nextjs-registry@1.3.0 @ant-design/cssinjs@2.1.2 @dagrejs/dagre@3.1.1
pnpm --dir apps/web why @ant-design/cssinjs
pnpm --dir apps/web dev
```

当前已核对本机 Node `v24.15.0`、pnpm `11.19.0`。新增版本来自设计方案候选，并重新核对了 antd/Registry 的 peer 元数据；仍需实际构建和 SSR 验收。已有 React Flow、ECharts、Query、Vitest、Playwright，不必重复安装。默认不安装 ProComponents。

浏览器访问 `http://127.0.0.1:3000`。初始欢迎页说明开发服务器可用，还不代表业务完成。启动命令保持运行；后续检查使用另一个终端。

## 3. 先补测试入口，再做主题和页面壳（M0）

- [ ] 修改 `apps/web/package.json` 的 scripts，保留现有四项，补充：

```json
"test": "vitest run",
"test:e2e": "playwright test",
"typecheck": "next typegen && tsc --noEmit"
```

- [ ] 新建 `apps/web/vitest.config.ts`，避免把 Playwright 文件当作单元测试运行：

```ts
import { defineConfig } from 'vitest/config';

export default defineConfig({
  test: {
    environment: 'node',
    include: ['src/**/*.test.ts'],
  },
});
```

状态 reducer、图数据转换的测试放在 `src` 对应功能目录；视觉 Token 不需要镜像实现的单元测试。

- [ ] 新建 `apps/web/playwright.config.ts`：

```ts
import { defineConfig, devices } from '@playwright/test';

export default defineConfig({
  testDir: './e2e',
  use: {
    baseURL: 'http://127.0.0.1:3000',
    trace: 'retain-on-failure',
  },
  projects: [{ name: 'chromium', use: { ...devices['Desktop Chrome'] } }],
  webServer: {
    command: 'pnpm dev --hostname 127.0.0.1 --port 3000',
    url: 'http://127.0.0.1:3000',
    reuseExistingServer: !process.env.CI,
  },
});
```

- [ ] 安装测试浏览器（已有对应浏览器缓存时无需重复下载）：

```powershell
pnpm --dir apps/web exec playwright install chromium
```

- [ ] 新建 `apps/web/e2e/shell.spec.ts`，先固定可验收的页面壳：

```ts
import { test, expect } from '@playwright/test';

test('总览具有导航且桌面没有页面横向溢出', async ({ page }) => {
  await page.setViewportSize({ width: 1440, height: 900 });
  await page.goto('/');
  await expect(page.getByRole('heading', { name: '运营总览', exact: true })).toBeVisible();
  await expect(page.getByRole('navigation', { name: '主导航' })).toBeVisible();
  const overflows = await page.evaluate(() =>
    document.documentElement.scrollWidth > document.documentElement.clientWidth
  );
  expect(overflows).toBe(false);
});
```

运行 `pnpm --dir apps/web test:e2e e2e/shell.spec.ts`，当前欢迎页应失败。实现页面壳后重新运行，应通过。完整闭环测试另建 `e2e/investigation.spec.ts`，按第 8 节操作顺序验收。

- [ ] 按 `apps/web/AGENTS.md`，先阅读已安装 Next.js 的本地文档，重点是 layouts/pages、route groups、route handlers 和 server/client components。
- [ ] 新建 `src/lib/theme/socTokens.ts`，集中保存设计第 3 节的色值、字号、间距；由它派生 antd、图谱、图表主题。
- [ ] 新建 `src/app/providers.tsx`：客户端组件，统一包裹 ConfigProvider、antd App、QueryClientProvider；QueryClient 只在当前 Provider 初始化一次。
- [ ] 修改 `src/app/layout.tsx`：`lang="zh-CN"`，修改标题和说明，接入 AntdRegistry 和 Providers。离线演示按设计换用系统字体，移除需要下载 Google 字体的依赖路径。
- [ ] 修改 `src/app/globals.css`：固定深色，采用 canvas/surface/elevated 三级背景、8px 圆角、1px 边框、14px 业务正文；去掉脚手架的系统浅深色自动切换。
- [ ] 新建 `src/components/shell/SocShell.tsx` 和 `src/app/(soc)/layout.tsx`：64px 顶栏、64px 左导航、24px 内容留白，导航使用 `aria-label="主导航"`。
- [ ] 将原 `src/app/page.tsx` 迁入 `src/app/(soc)/page.tsx`；不能同时保留两个映射 `/` 的 page。

App Router 的 Ant Design 首屏样式接入参考：[Ant Design 官方 Next.js 指南](https://ant.design/docs/react/use-with-next/)。

**M0 验收：** 页面壳测试通过；表格、输入、抽屉、弹窗首屏样式一致；刷新无水合错误；生产构建成功。这里只证明基础工程可用。

### 3.1 可以先照着建立的基础接入代码

以下四段是主题与 Provider 的接入示例。当前工作区已安装依赖并接入这些基础文件；页面壳可用第 3.2 节的 PowerShell 脚本生成。按钮、标签和组件细节仍按完整设计验收。

**新建 `D:\传智杯\apps\web\src\lib\theme\socTokens.ts`：**

```ts
export const socTokens = {
  canvas: '#0B1220',
  surface: '#111B2E',
  elevated: '#17243B',
  text: '#F1F5F9',
  textSecondary: '#B6C4D8',
  textMuted: '#8B9CB5',
  border: '#2B3C55',
  controlBorder: '#657E9E',
  primary: '#4FAFC2',
  primaryHover: '#65C1D2',
  primaryActive: '#3994A8',
  error: '#F2A0A5',
  warning: '#F6C76B',
  success: '#76D7AE',
} as const;
```

**新建 `D:\传智杯\apps\web\src\app\providers.tsx`：**

```tsx
'use client';

import { useState, type ReactNode } from 'react';
import { App as AntdApp, ConfigProvider, theme } from 'antd';
import zhCN from 'antd/locale/zh_CN';
import { QueryClient, QueryClientProvider } from '@tanstack/react-query';
import { socTokens as t } from '@/lib/theme/socTokens';

export default function Providers({ children }: { children: ReactNode }) {
  const [queryClient] = useState(() => new QueryClient({
    defaultOptions: {
      queries: { staleTime: 10_000, retry: 2 },
      mutations: { retry: false },
    },
  }));

  return (
    <QueryClientProvider client={queryClient}>
      <ConfigProvider
        locale={zhCN}
        theme={{
          algorithm: theme.darkAlgorithm,
          token: {
            colorPrimary: t.primary,
            colorPrimaryHover: t.primaryHover,
            colorPrimaryActive: t.primaryActive,
            colorBgBase: t.canvas,
            colorBgContainer: t.surface,
            colorBgElevated: t.elevated,
            colorText: t.text,
            colorTextSecondary: t.textSecondary,
            colorTextTertiary: t.textMuted,
            colorBorder: t.controlBorder,
            colorBorderSecondary: t.border,
            colorError: t.error,
            colorWarning: t.warning,
            colorSuccess: t.success,
            fontSize: 14,
            borderRadius: 8,
            boxShadow: 'none',
            boxShadowSecondary: 'none',
          },
          components: { Button: { primaryColor: t.canvas } },
        }}
      >
        <AntdApp>{children}</AntdApp>
      </ConfigProvider>
    </QueryClientProvider>
  );
}
```

这里采用普通 useQuery，由根 Provider 保持同一浏览器页面中的 QueryClient；后续如果改成 Suspense/服务端预取模式，按 [TanStack SSR 指南](https://tanstack.com/query/latest/docs/framework/react/guides/advanced-ssr) 调整实例生命周期和 hydration。

**替换 `D:\传智杯\apps\web\src\app\layout.tsx`：**

```tsx
import type { Metadata } from 'next';
import type { CSSProperties, ReactNode } from 'react';
import { AntdRegistry } from '@ant-design/nextjs-registry';
import Providers from './providers';
import { socTokens as t } from '@/lib/theme/socTokens';
import './globals.css';

export const metadata: Metadata = {
  title: 'EvidenceSOC',
  description: '证据驱动的安全调查与模拟响应工作台',
};

const variables = {
  '--soc-canvas': t.canvas,
  '--soc-surface': t.surface,
  '--soc-elevated': t.elevated,
  '--soc-text': t.text,
  '--soc-text-secondary': t.textSecondary,
  '--soc-text-muted': t.textMuted,
  '--soc-border': t.border,
  '--soc-control-border': t.controlBorder,
  '--soc-primary': t.primary,
} as CSSProperties;

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="zh-CN" style={variables}>
      <body>
        <AntdRegistry><Providers>{children}</Providers></AntdRegistry>
      </body>
    </html>
  );
}
```

**替换 `D:\传智杯\apps\web\src\app\globals.css` 的脚手架基础样式：**

```css
@import 'tailwindcss';

:root { color-scheme: dark; }
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100dvh;
  background: var(--soc-canvas);
  color: var(--soc-text);
  font-family: 'Microsoft YaHei', 'PingFang SC', system-ui, sans-serif;
  font-size: 14px;
  line-height: 1.5;
}
a { color: var(--soc-primary); }
button, input, textarea, select { font: inherit; }
:focus-visible {
  outline: 2px solid var(--soc-primary);
  outline-offset: 2px;
}
pre { max-width: 100%; overflow: auto; }
```

保存以上文件后，先运行 `pnpm --dir apps/web lint`、`pnpm --dir apps/web exec tsc --noEmit` 和 `pnpm --dir apps/web build`。然后建立 `(soc)` 页面壳并完成 shell.spec.ts；前端首页仍是脚手架时，壳测试失败是预期。

### 3.2 用 PowerShell 生成页面框架

主题与 Providers 接入并通过类型检查后，执行已保存的脚本 `D:\传智杯\docs\frontend-previews\create-task10-m0.ps1`。它会生成公共页面壳、运营总览，以及告警列表、调查列表、响应审批三个占位页；这些页面尚未接入业务 API，未知指标显示“—”。

先在原来运行 `pnpm dev` 的终端按 `Ctrl+C` 停止服务。在项目根目录执行：

```powershell
Set-Location 'D:\传智杯'
# 当前在 main 且未创建 Task10 分支时执行；已有分支按第 1 节复用。
git switch -c codex/task10-frontend
powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'D:\传智杯\docs\frontend-previews\create-task10-m0.ps1'
pnpm --dir 'D:\传智杯\apps\web' dev --hostname 127.0.0.1
```

脚本只写入列出的 11 个文件，先备份已有内容并校验哈希，再移除原 `src/app/page.tsx`，避免与 `(soc)/page.tsx` 争用首页。备份位于 `.backups` 下独立的时间戳目录。生成后重启开发服务，并打开 `http://127.0.0.1:3000`，让 Next.js 更新旧首页的开发路由类型；否则旧 `.next/dev/types` 可能引用已迁移的页面。

保留开发服务运行，在另一个 PowerShell 终端执行：

```powershell
pnpm --dir 'D:\传智杯\apps\web' typecheck
pnpm --dir 'D:\传智杯\apps\web' lint
pnpm --dir 'D:\传智杯\apps\web' exec playwright test e2e/shell.spec.ts --workers=1
```

预期首页标题为“运营总览”，四个导航入口可用；浏览器窄窗口显示菜单按钮并可开关抽屉。这里完成的是页面框架，真实数据与调查、审批交互继续按第 4 节实现。

2026-09-28 验证：生成器通过 Windows PowerShell 5.1 执行；主工作区已生成四个页面，类型检查、lint、默认 Next.js 生产构建和 `shell.spec.ts` 的 7 项布局与导航测试均通过。临时副本中的首页基线测试也从失败转为通过。本轮验证范围为公共页面框架。

### 3.3 使用 Codex 分阶段实施时的具体指令

如果准备让 Codex 写代码，可以先发送下面这段，完成后检查结果再进入下一阶段：

```text
开始实施 Task10 的 M0，按 docs/EvidenceSOC-前端完整设计与实施方案.md 和
docs/superpowers/plans/2026-09-27-task10-operation-guide.md 执行。
从 main 创建或复用 codex/task10-frontend，保留当前设计资料。
完成依赖安装、主题 Token、AntdRegistry、Providers、公共页面壳、
Vitest/Playwright 配置和页面壳测试。固定深色、64px 顶栏与窄导航，
根页面不横向溢出；API/数据源健康未知时明确显示未知。
运行与 M0 有关的检查及生产构建，修复错误。暂不提交或合并。
```

## 4. 按闭环逐页实现（M1～M3）

所有文件以下列 `apps/web/src` 为基准。每一行完成后，先在浏览器验证对应行为，再做下一行。

| 顺序 | 页面与关键文件 | 具体操作与验收 |
|---|---|---|
| 1 | `app/(soc)/alerts/page.tsx`、`features/alerts/` | 表格展示标题、严重性、时间和状态；先接 Task9 已支持的 severity/status/page/page_size。未实现的关键词和时间筛选不做成假操作。 |
| 2 | `app/(soc)/alerts/[id]/page.tsx` | 展示告警摘要、关联日志和调查入口。Task9 尚无单告警详情读取端点，补后端接口后支持直接 URL 和刷新，不仅依赖列表内存。 |
| 3 | `features/alerts/StartInvestigationButton.tsx` | POST investigations，当前只传 alert_id；提交期间禁用按钮，用返回的 incident_id 跳转，保存 investigation_id。 |
| 4 | `app/(soc)/incidents/page.tsx`、`app/(soc)/incidents/[id]/page.tsx` | 详情先消费 Task9 的 IncidentDetail；调查列表需补列表接口。宽屏上下文/画布/证据 3:6:3，窄屏证据 Drawer。 |
| 5 | `features/investigations/AttackGraph.tsx`、`AttackStageList.tsx`、`graphLayout.ts` | 将 attack_steps 转换为稳定 ID 节点，用 Dagre 横向布局；sequence/occurred_at 只支持顺序展示，不把顺序推断为已证实因果。提供等价阶段列表。 |
| 6 | `features/investigations/AgentProgressSteps.tsx`、`AgentRunDetails.tsx` | 横向展示真实六角色记录、完成时间、错误和输出；未生成 run 时显示未开始，不用计时器假造执行进度。 |
| 7 | `features/evidence/EvidenceInspector.tsx` | 节点→引用证据列表→选中证据详情。展示真实 Evidence ID、来源、查询、完整哈希；原文与读取校验状态需要新增后端端点。 |
| 8 | `app/(soc)/responses/page.tsx`、`app/(soc)/responses/[id]/page.tsx`、`features/responses/DecisionForm.tsx` | 展示模拟动作、目标、风险、影响、回滚和验证条件；批准/拒绝均校验 trim 后非空理由；桌面 7:3，按钮不覆盖表单。响应队列和直接方案详情需补读取接口。 |
| 9 | `features/responses/ValidationResult.tsx` | 决策 accepted 后重新读案件，分别显示批准、模拟执行、验证结论。验证使用 success/failure/insufficient_evidence，不把 completed 显示成风险解除。 |

UI 可以先用 `src/test/fixtures/` 的公开固定样例开发，标识“界面样例”。正式模式请求失败时显示失败和重试，不能自动切换成样例成功。

### 4.1 接入真实告警列表

后端 `/health/live`、`/health/ready` 正常，且 `GET /api/v1/alerts?page=1&page_size=20` 返回 `items/total/page/page_size` 后，可执行 `D:\传智杯\docs\frontend-previews\create-task10-m1-alerts.ps1`。这个阶段只读取告警列表：严重性、当前状态、分页、刷新、错误重试和 URL 筛选恢复。列表状态来自最近一次关联调查，不表示风险已解除。

需要已有的 `D:\传智杯\apps\web\src\lib\api\generated.ts`；缺少时先生成当前后端契约：

```powershell
pnpm --dir 'D:\传智杯\apps\web' exec openapi-typescript 'http://127.0.0.1:8000/openapi.json' -o 'D:\传智杯\apps\web\src\lib\api\generated.ts'
```

保持后端运行，在前端服务终端按 `Ctrl+C`，然后执行：

```powershell
Set-Location 'D:\传智杯'
powershell.exe -NoProfile -ExecutionPolicy Bypass -File 'D:\传智杯\docs\frontend-previews\create-task10-m1-alerts.ps1'
pnpm --dir 'D:\传智杯\apps\web' dev --hostname 127.0.0.1
```

脚本先备份受影响文件，再生成本阶段文件；既有 OpenAPI 类型、主题、Providers 和公共导航保持复用。`.env.local` 缺少 `BACKEND_URL` 时追加默认 `http://127.0.0.1:8000`，已有设置保持原值。创建或修改环境配置后需要重启开发服务。

访问 `http://127.0.0.1:3000/alerts`。在另一个终端检查前端代理和实现：

```powershell
Invoke-RestMethod 'http://127.0.0.1:3000/api/v1/alerts?page=1&page_size=20' | ConvertTo-Json -Depth 6
pnpm --dir 'D:\传智杯\apps\web' typecheck
pnpm --dir 'D:\传智杯\apps\web' lint
pnpm --dir 'D:\传智杯\apps\web' test
pnpm --dir 'D:\传智杯\apps\web' exec playwright test --workers=1
pnpm --dir 'D:\传智杯\apps\web' build
```

这里的代理检查请求 **3000** 端口，确认经前端连接真实后端。`total: 0` 时页面显示“暂无告警”；有筛选但未匹配时提供“清除筛选”，页码越界时提供“回到第一页”。分页总量取后端 `total`，默认每页 20 条，筛选变更回到第一页。同一筛选的后台更新失败会保留上次成功结果并明确提示；首次加载失败不会显示为 0 条。当前没有关键词、时间窗口和客户端排序操作，接口失败不会使用样例数据替代。

2026-09-29 验证：生成器在临时副本通过 Windows PowerShell 5.1 执行；环境文件追加与既有配置保留、备份及 OpenAPI 类型保留已核对。类型检查、lint、11 项单元测试、6 项告警页面测试、7 项公共页面壳测试及默认 Next.js 生产构建通过。另有 3 项临时验收覆盖真实代理返回当前空列表、写方法返回 405 和空数据基线；真实后端返回 `total: 0`，页面相应显示“暂无告警”。本轮只准备生成脚本，未将 M1 写入主工作区的 `apps/web`。

下一步按第 6.1 节准备真实日志和告警，再补单告警详情接口、实现告警详情与启动调查；列表接入阶段不扩展调查、证据或审批业务。

## 5. 核对 Task9 真实契约，再补设计所需端点

当前 main 已包含 Task9，应以 `services/backend/src/evidencesoc/api/models.py` 和运行中的 `/docs` 为准。

| 项目 | Task9 已有行为 | 前端设计要求与后续工作 |
|---|---|---|
| 创建调查 | 请求只能提供 alert_id 或 incident_id 中的一项；无 mode 字段，额外字段被拒绝 | 设计的 `mode: rules/model` 是新增提案，不能直接发送。当前模式由后端 LLM_MODE 配置。 |
| 告警列表 | page/page_size/severity/status；默认 50 条 | UI 可主动请求 20；时间、query、handling_status 需要后端同步扩展。 |
| 案件详情 | GET incidents/{id} 返回 evidence、attack_steps、runs、response_plan、approval、validation_result、simulation 等 | 先使用真实字段；设计里的独立调查快照、revision、stream_cursor 尚需增加。 |
| 人工决定 | reason、decided_by；返回 202 accepted | 当前未声明 plan_version；方案版本、有效期、服务端会话身份需补后端契约。不能仅在前端显示版本号就声称支持版本冲突。 |
| SSE | 事件 ID 为十进制序号；支持 Last-Event-ID；15 秒注释 ping | 当前没有设计的 after 参数、业务 heartbeat/reset 协议。先按真实协议实现，再扩展并联测。 |
| 页面读取 | 已有告警列表、案件详情 | 缺少告警单详情、案件列表、证据原文校验、响应列表/详情、统计聚合、源健康及会话读取。 |

Task9 的待复核状态名为 `manual_review`，设计提案为 `needs_review`；先映射真实状态显示中文，若改后端名字则同步迁移与类型。拒绝目前会发 `investigation.completed` 且 payload.status 为 rejected，待复核会发 investigation.failed；必须读业务状态与最终案件快照，不能仅按 SSE 事件名称显示成功/失败。

优先补影响闭环的单告警、证据详情和响应详情读取；再补调查/响应列表、仪表盘聚合与健康。缺少服务端统计时显示未接入，不能从分页列表计算全量数量。

## 6. 启动真实后端并生成类型

- [ ] 在项目根目录启动业务依赖：

```powershell
Set-Location 'D:\传智杯'
docker compose up -d --wait postgres opensearch
docker compose ps
uv sync --project services/backend --frozen
uv run --project services/backend alembic -c services/backend/alembic.ini upgrade head
```

使用现有 `.env`；没有时才从 `.env.example` 创建，并保持数据库配置与 Compose 一致。离线规则演示使用 `LLM_MODE=fixture`，不要把设计的 rules/model 直接写进这个配置值。

本轮先验证告警列表，不需要下载 ATT&CK 知识。实际启动调查前，如果本地知识尚未准备，再使用 Task7 的入口：`uv run --project services/backend python -m evidencesoc.rag.cli prepare`；首次准备可能需要网络下载，后续离线演示使用已准备数据。

- [ ] 在一个终端保持 FastAPI 运行：

```powershell
uv run --project services/backend uvicorn evidencesoc.main:app --app-dir services/backend/src --host 127.0.0.1 --port 8000
```

- [ ] 在另一个终端检查：

```powershell
Invoke-RestMethod 'http://127.0.0.1:8000/health/live'
Invoke-RestMethod 'http://127.0.0.1:8000/health/ready'
Invoke-RestMethod 'http://127.0.0.1:8000/api/v1/alerts?page=1&page_size=20' | ConvertTo-Json -Depth 6
pnpm --dir apps/web exec openapi-typescript http://127.0.0.1:8000/openapi.json -o src/lib/api/generated.ts
```

访问 `http://127.0.0.1:8000/docs`，确认存在业务接口。告警列表返回 `items: []`、`total: 0` 表示当前没有告警，不代表接口失败。只有 live 正常不能证明依赖可用；ready 检查工作流初始化、数据库和 OpenSearch，不检查 ATT&CK 知识是否已准备。ready 失败时先处理数据库迁移、OpenSearch 与工作流/MCP 初始化错误，不要用 mock 隐藏失败。

- [ ] 在 `apps/web/.env.local` 设置 `BACKEND_URL=http://127.0.0.1:8000`，这是 Task10 新增的服务端代理配置，不是已有自动功能。
- [ ] 告警列表先使用专门的 `src/app/api/v1/alerts/route.ts`。后续为其他业务路径增加同源代理；若使用 `[...path]`，只接受白名单路径，注意已有具体路由优先匹配。普通 JSON 和 SSE 分开处理，透传真实 HTTP 状态与错误，客户端断开时取消上游流。
- [ ] 新建 `src/lib/api/client.ts`、`queryKeys.ts`，统一普通请求、取消、错误和 Query key。浏览器只访问同源 `/api/v1/*`。

### 6.1 让告警列表有真实数据

后端就绪后列表为空通常是没有创建告警，而不是前端出错。仓库现已提供 [Task10 演示数据脚本](../../../scripts/seed-task10.py)，以 5 条固定样本日志创建 1 条持久化告警，不启动调查或审批。

脚本会检查后端就绪、导入样本并核对 OpenSearch 文档，再用固定 ID 和幂等键创建告警；created_at 与样本日志时间窗口一致。实际实现以脚本文件为准。

**在项目根目录执行：**

```powershell
uv run --project services/backend python scripts/seed-task10.py
Invoke-RestMethod 'http://127.0.0.1:8000/api/v1/alerts?page=1&page_size=20' | ConvertTo-Json -Depth 6
```

预期 seed 输出真实 alert_id 和 event_count，列表 items 中出现演示告警。脚本文件已经存在，可直接运行。它会把告警 created_at 对齐样本事件窗口，以供后续调查检索；重复运行复用已有事件和告警。正常删除告警时关联的幂等记录也会级联清理，若重跑出现冲突，应先核对同 ID 告警的数据来源。

2026-09-30 验证：实际运行脚本两次。首次导入 5 条样本事件并创建告警 AL-TASK10-F9F66CC72C2A5E70291B78A4；第二次导入 0 条、复用 5 条事件且未新增告警，列表 total 始终为 1。前端同源代理返回该告警，真实数据浏览器用例通过。当前仅有告警列表；单告警详情和启动调查仍按第 4 节继续实现。

## 7. 接入实时恢复与最后完成总览（M4～M5）

- [ ] 新建 `features/investigations/useInvestigationStream.ts`、`streamReducer.ts`。先读案件，再按 investigation_id 订阅；按事件 ID 去重，关键状态变化重新读取案件；页面离开时关闭连接。
- [ ] 使用 `addEventListener` 订阅后端命名事件；只写 `onmessage` 不足以处理带 event 字段的业务事件。
- [ ] 先验证同一 EventSource 的 Last-Event-ID 自动重连；当前后端完整重放时必须能去重。
- [ ] 再成对扩展后端快照游标/after/reset/heartbeat 与前端恢复；快照和订阅之间的无漏更新验收通过后，才宣称满足设计第 10 节。
- [ ] SSE 的注释 ping 不触发浏览器 message，不能拿它实现前端活动计时。没有业务 heartbeat 时不要照抄 30 秒 watchdog。
- [ ] 审批按钮提交中禁用；未知网络结果先查询决定，不自动重复 POST；冲突时保留输入并读最新方案。
- [ ] `features/dashboard/` 接入后端真实聚合，ECharts 显示趋势和状态；顶部与首页共用健康查询。首页不加载攻击图组件。
- [ ] 完成 1920/1440/1280/1024/390 视口和真实 200% 缩放检查；Grid/Flex 子项 `min-width:0`，表格/画布仅局部横向滚动。

## 8. 最终验收、检查与提交

手动操作顺序：

1. 从告警列表选中真实样例告警，打开详情。
2. 点击启动调查，进入返回的真实 incident_id。
3. 观察六角色真实状态；点击攻击步骤，打开其 Evidence ID 对应证据。
4. 查看查询、完整哈希及后端校验结果。
5. 打开响应详情，读目标、风险、影响、回滚、验证条件。
6. 填写理由并批准，确认“仅模拟处置”，等到后端模拟与验证结果。
7. 用另一条调查验证拒绝；另测证据不足、校验异常、断线重连和方案版本冲突。

本地数据源先入库 `data/samples/sql-injection.jsonl`，再创建引用实际 event_ids 的告警。仓库没有现成日志导入 CLI：可新建独立 seed 脚本调用 `IngestionService.import_file`，使用 EventRepository 与 OpenSearchEventStore，并按实际报告检查失败/提交/刷新；已有真实示例在 Task9 的 `tests/api/test_live_acceptance.py` 的 seed 和告警创建段。该测试会清理自己的数据，不会留下前端演示告警。不得直接拿静态预览中的 Evidence ID 或 event ID 提交后端。

配置、业务实现和对应测试完成后，在根目录执行：

```powershell
pnpm --dir apps/web lint
pnpm --dir apps/web typecheck
pnpm --dir apps/web test
pnpm --dir apps/web test:e2e
pnpm --dir apps/web build
```

若有后端扩展，同时运行相关 API/工作流测试：

```powershell
uv run --project services/backend pytest services/backend/tests/api services/backend/tests/agents -q
```

先确认单元测试存在；Vitest 的无测试报错不能通过 `--passWithNoTests` 当作 Task10 验收成功。Mock E2E 与真实后端闭环应分开记录，全部通过才算交付。

提交前：

```powershell
git status --short
git diff --stat
git add apps/web pnpm-lock.yaml
git diff --cached --stat
git commit -m "feat: add soc investigation user interface"
```

后端扩展与本指南/设计资料按实际变更显式暂存；不要把既有文档删除或无关文件一并提交。

**建议今天的完成范围：** 第 1～3 步（分支、依赖、测试入口、主题与导航壳）。完成后再做告警→调查入口。完整 Task10 的标准是真实后端闭环及恢复验收，不是首页截图完成。

参考：[原 Task10 定义](../../EvidenceSOC-project-preparation.md)、[完整设计](../../EvidenceSOC-前端完整设计与实施方案.md)、[Playwright 官方配置](https://playwright.dev/docs/test-configuration)。
