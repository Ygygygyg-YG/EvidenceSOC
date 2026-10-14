import type { Metadata } from 'next';
import { Suspense } from 'react';
import ResponseDetail from '@/features/responses/ResponseDetail';

export const metadata: Metadata = { title: '响应方案详情 | EvidenceSOC' };

export default async function ResponsePlanPage({ params }: PageProps<'/responses/[id]'>) {
  const { id } = await params;
  return <Suspense fallback={<p role="status">正在加载响应方案…</p>}><ResponseDetail id={id} /></Suspense>;
}
