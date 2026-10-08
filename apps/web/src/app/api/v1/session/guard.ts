const demoCookieName = 'evidencesoc_demo_session';

export function demoSessionCookie(request: Request): string | null {
  const matches = (request.headers.get('cookie') ?? '').split(';').map((part) => part.trim())
    .filter((part) => part.startsWith(`${demoCookieName}=`));
  if (matches.length !== 1) return null;
  const value = matches[0].slice(demoCookieName.length + 1);
  return value.length > 0 && value.length <= 2048 ? `${demoCookieName}=${value}` : null;
}

export function trustedWriteOrigin(request: Request): string | null {
  const configured = process.env.FRONTEND_ORIGIN?.trim() || 'http://127.0.0.1:3000';
  const origin = request.headers.get('origin');
  try {
    return origin === configured && request.headers.get('host') === new URL(configured).host
      ? origin : null;
  } catch {
    return null;
  }
}
