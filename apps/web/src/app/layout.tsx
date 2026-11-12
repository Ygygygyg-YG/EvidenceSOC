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
  '--soc-primary-hover': t.primaryHover,
  '--soc-primary-active': t.primaryActive,
  '--soc-error': t.error,
  '--soc-warning': t.warning,
  '--soc-success': t.success,
} as CSSProperties;

export default function RootLayout({ children }: { children: ReactNode }) {
  return (
    <html lang="zh-CN" style={variables}>
      <body>
        <AntdRegistry>
          <Providers>{children}</Providers>
        </AntdRegistry>
      </body>
    </html>
  );
}