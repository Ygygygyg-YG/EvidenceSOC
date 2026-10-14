import { proxyError, proxyGet, validPlanId } from '../proxy';

export const runtime = 'nodejs';
export async function GET(request: Request, { params }: { params: Promise<{ id: string }> }): Promise<Response> {
  const { id } = await params;
  if (!validPlanId(id)) return proxyError(400, 'INVALID_PLAN_ID', '响应方案编号无效。');
  return proxyGet(request, `/api/v1/response-plans/${encodeURIComponent(id)}`);
}
