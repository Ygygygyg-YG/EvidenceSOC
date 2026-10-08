import { proxyRenewal } from '../../proxy';

export const runtime = 'nodejs';
export async function POST(request: Request, { params }: { params: Promise<{ id: string }> }): Promise<Response> {
  const { id } = await params;
  return proxyRenewal(request, id);
}
