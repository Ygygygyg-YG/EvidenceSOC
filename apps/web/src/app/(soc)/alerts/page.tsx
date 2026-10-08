import type { Metadata } from 'next';
import { Suspense } from 'react';
import AlertsList from '@/features/alerts/AlertsList';

export const metadata: Metadata = { title: '告警列表 | EvidenceSOC' };

export default function AlertsPage() {
  return <Suspense fallback={<div><h1>告警列表</h1><p role="status">正在加载告警…</p></div>}><AlertsList /></Suspense>;
}
