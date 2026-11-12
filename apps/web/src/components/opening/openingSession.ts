export const OPENING_SESSION_KEY = 'evidencesoc.intro.seen.v1';
export const OPENING_COOKIE_NAME = 'evidencesoc_intro_seen';
export const OPENING_COOKIE_VALUE = '1';
export const OPENING_COOKIE_ASSIGNMENT = `${OPENING_COOKIE_NAME}=${OPENING_COOKIE_VALUE}; Path=/; SameSite=Lax`;

type SessionStore = Pick<Storage, 'getItem' | 'setItem'>;

export function readCookieValue(cookieHeader: string, name: string): string | null {
  for (const item of cookieHeader.split(';')) {
    const separator = item.indexOf('=');
    if (separator < 0) continue;
    const key = item.slice(0, separator).trim();
    if (key !== name) continue;
    const value = item.slice(separator + 1).trim();
    try { return decodeURIComponent(value); }
    catch { return value; }
  }
  return null;
}

/** A failed read deliberately returns unseen so the opening remains skippable. */
export function readOpeningSeen(storage: SessionStore, readCookie: () => string): boolean {
  try {
    const stored = storage.getItem(OPENING_SESSION_KEY);
    const cookie = readCookieValue(readCookie(), OPENING_COOKIE_NAME);
    return stored === OPENING_COOKIE_VALUE || cookie === OPENING_COOKIE_VALUE;
  } catch {
    return false;
  }
}

/** Markers are independent: one unavailable mechanism must not prevent the other. */
export function markOpeningSeen(storage: SessionStore, writeCookie: (value: string) => void): void {
  try { storage.setItem(OPENING_SESSION_KEY, OPENING_COOKIE_VALUE); }
  catch { /* Session storage can be unavailable in privacy modes. */ }
  try { writeCookie(OPENING_COOKIE_ASSIGNMENT); }
  catch { /* Cookie writes can be blocked without blocking entry. */ }
}
