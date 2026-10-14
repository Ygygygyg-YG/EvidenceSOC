import type { Metadata } from 'next';
import { Suspense } from 'react';
import AlertDetail from '@/features/alerts/AlertDetail';

export const metadata: Metadata = { title: '告警详情 | EvidenceSOC' };

export default async function AlertDetailPage({ params }: PageProps<'/alerts/[id]'>) {
  const { id } = await params;
  return <Suspense fallback={<p role="status">正在加载告警详情…</p>}><AlertDetail id={id} /></Suspense>;
}
