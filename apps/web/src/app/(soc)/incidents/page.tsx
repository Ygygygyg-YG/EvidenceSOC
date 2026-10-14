import type { Metadata } from 'next';
import { Suspense } from 'react';
import IncidentsList from '@/features/incidents/IncidentsList';

export const metadata: Metadata = { title: '调查列表 | EvidenceSOC' };

export default function IncidentsPage() {
  return <Suspense fallback={<div><h1>调查列表</h1><p role="status">正在加载案件…</p></div>}><IncidentsList /></Suspense>;
}
