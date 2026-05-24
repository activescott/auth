import { describe, it, expectTypeOf } from 'vitest';
import type { OAuthProviderConfig, OAuthProfile, TokenResponse } from '../types.js';

describe('OAuthProviderConfig', () => {
  it('requires clientId, clientSecret, oauthStateSecret', () => {
    const config: OAuthProviderConfig = {
      clientId: 'id',
      clientSecret: 'secret',
      oauthStateSecret: 'state-secret'
    };
    expectTypeOf(config).toMatchTypeOf<OAuthProviderConfig>();
  });

  it('accepts optional scopes and linkByVerifiedEmail', () => {
    const config: OAuthProviderConfig = {
      clientId: 'id',
      clientSecret: 'secret',
      oauthStateSecret: 'state-secret',
      scopes: ['openid', 'email'],
      linkByVerifiedEmail: true
    };
    expectTypeOf(config).toMatchTypeOf<OAuthProviderConfig>();
  });
});

describe('OAuthProfile', () => {
  it('requires id and rawClaims', () => {
    const profile: OAuthProfile = {
      id: '12345',
      rawClaims: {}
    };
    expectTypeOf(profile).toMatchTypeOf<OAuthProfile>();
  });

  it('accepts all optional fields', () => {
    const profile: OAuthProfile = {
      id: '12345',
      email: 'alice@example.com',
      emailVerified: true,
      name: 'Alice',
      givenName: 'Alice',
      familyName: 'Example',
      avatarUrl: 'https://example.com/avatar.jpg',
      rawClaims: { sub: '12345' }
    };
    expectTypeOf(profile).toMatchTypeOf<OAuthProfile>();
  });
});

describe('TokenResponse', () => {
  it('requires accessToken and tokenType', () => {
    const token: TokenResponse = {
      accessToken: 'tok',
      tokenType: 'Bearer'
    };
    expectTypeOf(token).toMatchTypeOf<TokenResponse>();
  });
});
