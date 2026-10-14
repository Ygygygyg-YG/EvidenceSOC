import { proxySessionGet } from './proxy';

export const runtime = 'nodejs';
export async function GET(request: Request): Promise<Response> {
  return proxySessionGet(request);
}
