import DashboardOverview from '@/features/dashboard/DashboardOverview';
import { Suspense } from 'react';

export default function OverviewPage() {
  return <Suspense fallback={<p role="status">正在读取运营统计…</p>}><DashboardOverview /></Suspense>;
}
