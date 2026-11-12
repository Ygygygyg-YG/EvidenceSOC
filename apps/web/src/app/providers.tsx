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
            colorTextLightSolid: t.canvas,
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
          components: {
            Button: { primaryColor: t.canvas },
          },
        }}
      >
        <AntdApp>{children}</AntdApp>
      </ConfigProvider>
    </QueryClientProvider>
  );
}