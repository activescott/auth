import { describe, it, expect } from 'vitest';
import crypto from 'node:crypto';
import jwt from 'jsonwebtoken';
import {
  generateState,
  generatePKCE,
  createStateCookie,
  readStateCookie,
  clearStateCookie
} from '../base/state-cookie.js';
import type { OAuthStateCookiePayload } from '../base/state-cookie.js';

const SECRET = 'test-state-secret-at-least-32-chars-long!!';

const PAYLOAD: OAuthStateCookiePayload = {
  state: 'test-csrf-state',
  codeVerifier: 'test-code-verifier',
  provider: 'google'
};

function makeRequest(cookieValue: string): Request {
  return new Request('http://example.com/auth/google/callback', {
    headers: { Cookie: `__oauth_state=${cookieValue}` }
  });
}

function tokenFromSetCookie(setCookieHeader: string): string {
  return setCookieHeader.split(';')[0]?.split('=').slice(1).join('=') ?? '';
}

// ---------------------------------------------------------------------------
describe('generateState', () => {
  it('returns a non-empty string', () => {
    expect(generateState().length).toBeGreaterThan(0);
  });

  it('returns a unique value each call', () => {
    const values = new Set(Array.from({ length: 20 }, () => generateState()));
    expect(values.size).toBe(20);
  });
});

// ---------------------------------------------------------------------------
describe('generatePKCE', () => {
  it('returns codeVerifier and codeChallenge', () => {
    const { codeVerifier, codeChallenge } = generatePKCE();
    expect(codeVerifier).toBeTruthy();
    expect(codeChallenge).toBeTruthy();
  });

  it('codeChallenge is BASE64URL(SHA256(codeVerifier)) — RFC 7636 S256', () => {
    const { codeVerifier, codeChallenge } = generatePKCE();
    const expected = crypto.createHash('sha256').update(codeVerifier).digest('base64url');
    expect(codeChallenge).toBe(expected);
  });

  it('returns unique pairs each call', () => {
    const a = generatePKCE();
    const b = generatePKCE();
    expect(a.codeVerifier).not.toBe(b.codeVerifier);
    expect(a.codeChallenge).not.toBe(b.codeChallenge);
  });
});

// ---------------------------------------------------------------------------
describe('createStateCookie', () => {
  it('sets cookie name, Path, Max-Age, HttpOnly, SameSite', () => {
    const header = createStateCookie(PAYLOAD, SECRET);
    expect(header).toContain('__oauth_state=');
    expect(header).toContain('Path=/auth');
    expect(header).toContain('Max-Age=600');
    expect(header).toContain('HttpOnly');
    expect(header).toContain('SameSite=Lax');
  });

  it('adds Secure flag when option is set', () => {
    const header = createStateCookie(PAYLOAD, SECRET, { secure: true });
    expect(header).toContain('Secure');
  });

  it('omits Secure flag by default', () => {
    const header = createStateCookie(PAYLOAD, SECRET);
    expect(header).not.toContain('Secure');
  });
});

// ---------------------------------------------------------------------------
describe('readStateCookie', () => {
  it('round-trips the full payload', () => {
    const token = tokenFromSetCookie(createStateCookie(PAYLOAD, SECRET));
    const result = readStateCookie(makeRequest(token), SECRET);
    expect(result).not.toBeNull();
    expect(result?.state).toBe(PAYLOAD.state);
    expect(result?.codeVerifier).toBe(PAYLOAD.codeVerifier);
    expect(result?.provider).toBe(PAYLOAD.provider);
    expect(result?.redirectTo).toBeUndefined();
  });

  it('round-trips optional redirectTo', () => {
    const payload = { ...PAYLOAD, redirectTo: '/dashboard' };
    const token = tokenFromSetCookie(createStateCookie(payload, SECRET));
    const result = readStateCookie(makeRequest(token), SECRET);
    expect(result?.redirectTo).toBe('/dashboard');
  });

  it('returns null when no Cookie header', () => {
    const request = new Request('http://example.com');
    expect(readStateCookie(request, SECRET)).toBeNull();
  });

  it('returns null when state cookie is absent', () => {
    const request = new Request('http://example.com', {
      headers: { Cookie: 'session=abc; other=xyz' }
    });
    expect(readStateCookie(request, SECRET)).toBeNull();
  });

  it('returns null for wrong secret', () => {
    const token = tokenFromSetCookie(createStateCookie(PAYLOAD, SECRET));
    expect(readStateCookie(makeRequest(token), 'wrong-secret')).toBeNull();
  });

  it('returns null for expired cookie', () => {
    // Build a token with exp already in the past — jsonwebtoken respects the
    // exp claim when it's set directly in the payload alongside iss/aud.
    const expired = jwt.sign(
      {
        ...PAYLOAD,
        iss: 'auth-oauth-state',
        aud: 'auth',
        exp: Math.floor(Date.now() / 1000) - 60
      },
      SECRET
    );
    expect(readStateCookie(makeRequest(encodeURIComponent(expired)), SECRET)).toBeNull();
  });

  it('returns null for a tampered token', () => {
    const token = tokenFromSetCookie(createStateCookie(PAYLOAD, SECRET));
    const tampered = token.slice(0, -5) + 'XXXXX';
    expect(readStateCookie(makeRequest(tampered), SECRET)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
describe('clearStateCookie', () => {
  it('targets the correct cookie name', () => {
    expect(clearStateCookie()).toContain('__oauth_state=');
  });

  it('sets Max-Age=0 to expire immediately', () => {
    expect(clearStateCookie()).toContain('Max-Age=0');
  });

  it('preserves Path so the browser clears the right cookie', () => {
    expect(clearStateCookie()).toContain('Path=/auth');
  });
});
