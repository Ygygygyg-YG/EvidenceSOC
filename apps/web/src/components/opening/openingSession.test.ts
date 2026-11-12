import { describe, expect, it } from 'vitest';
import {
  OPENING_COOKIE_ASSIGNMENT, OPENING_COOKIE_NAME, OPENING_SESSION_KEY,
  markOpeningSeen, readCookieValue, readOpeningSeen,
} from './openingSession';

function memoryStorage(initial: string | null = null) {
  let value = initial;
  return {
    getItem: (key: string) => key === OPENING_SESSION_KEY ? value : null,
    setItem: (key: string, next: string) => { if (key === OPENING_SESSION_KEY) value = next; },
    value: () => value,
  };
}

describe('opening session markers', () => {
  it('uses the production session key and session cookie attributes', () => {
    expect(OPENING_SESSION_KEY).toBe('evidencesoc.intro.seen.v1');
    expect(OPENING_COOKIE_NAME).toBe('evidencesoc_intro_seen');
    expect(OPENING_COOKIE_ASSIGNMENT).toBe('evidencesoc_intro_seen=1; Path=/; SameSite=Lax');
    expect(OPENING_COOKIE_ASSIGNMENT).not.toContain('Expires=');
    expect(OPENING_COOKIE_ASSIGNMENT).not.toContain('Max-Age=');
  });

  it('parses exact cookie names and preserves values containing equals signs', () => {
    expect(readCookieValue('other=1; evidencesoc_intro_seen=1; token=a=b', OPENING_COOKIE_NAME)).toBe('1');
    expect(readCookieValue('evidencesoc_intro_seen_extra=1', OPENING_COOKIE_NAME)).toBeNull();
    expect(readCookieValue('token=a=b', 'token')).toBe('a=b');
  });

  it('treats either readable marker as seen', () => {
    expect(readOpeningSeen(memoryStorage('1'), () => '')).toBe(true);
    expect(readOpeningSeen(memoryStorage(null), () => 'evidencesoc_intro_seen=1')).toBe(true);
    expect(readOpeningSeen(memoryStorage(null), () => 'other=1')).toBe(false);
  });

  it('fails open when either marker read throws', () => {
    const brokenStorage = { getItem: () => { throw new Error('blocked'); }, setItem: () => undefined };
    expect(readOpeningSeen(brokenStorage, () => 'evidencesoc_intro_seen=1')).toBe(false);
    expect(readOpeningSeen(memoryStorage('1'), () => { throw new Error('blocked'); })).toBe(false);
  });

  it('attempts both writes independently when one mechanism fails', () => {
    let cookie = '';
    const storage = memoryStorage();
    markOpeningSeen(storage, (value) => { cookie = value; });
    expect(storage.value()).toBe('1');
    expect(cookie).toBe(OPENING_COOKIE_ASSIGNMENT);

    const brokenStorage = { getItem: () => null, setItem: () => { throw new Error('blocked'); } };
    markOpeningSeen(brokenStorage, (value) => { cookie = value; });
    expect(cookie).toBe(OPENING_COOKIE_ASSIGNMENT);
  });
});
