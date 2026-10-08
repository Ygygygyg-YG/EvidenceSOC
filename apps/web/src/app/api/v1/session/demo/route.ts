import { proxyDemoSessionPost } from '../proxy';

export const runtime = 'nodejs';
export async function POST(request: Request): Promise<Response> {
  return proxyDemoSessionPost(request);
}
