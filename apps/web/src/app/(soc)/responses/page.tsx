import type { Metadata } from 'next';
import { Suspense } from 'react';
import ResponsesList from '@/features/responses/ResponsesList';

export const metadata: Metadata = { title: '响应审批 | EvidenceSOC' };

export default function ResponsesPage() {
  return <Suspense fallback={<p role="status">正在加载响应方案…</p>}><ResponsesList /></Suspense>;
}
