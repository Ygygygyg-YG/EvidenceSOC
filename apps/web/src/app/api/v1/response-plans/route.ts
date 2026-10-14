import { proxyGet } from './proxy';

export const runtime = 'nodejs';
export async function GET(request: Request): Promise<Response> {
  return proxyGet(request, '/api/v1/response-plans', ['page', 'page_size', 'decision_state']);
}
