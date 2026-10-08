import type { Metadata } from 'next';
import IncidentDetail from '@/features/incidents/IncidentDetail';

export const metadata: Metadata = { title: '案件详情 | EvidenceSOC' };

export default async function IncidentDetailPage({ params, searchParams }: {
  params: Promise<{ id: string }>;
  searchParams: Promise<{ from?: string | string[] }>;
}) {
  const [{ id }, query] = await Promise.all([params, searchParams]);
  return <IncidentDetail id={id} from={typeof query.from === 'string' ? query.from : null} />;
}
