import { SecretScanner } from '../secret-scanner';

const scanner = new SecretScanner({});
const types = (text: string): string[] => scanner.scanContent(`${text}\n`, {}).map(m => m.type);
const PW = 'Vq7hR2mX9kLp4TzB';

describe('a connection string with an empty user (the canonical Redis form)', () => {
  it.each([
    ['redis', `redis://:${PW}@cache.acme.io:6379`, 'redis-url'],
    ['rediss', `rediss://:${PW}@cache.acme.io:6380`, 'redis-url'],
    ['postgres', `postgres://:${PW}@db.acme.io:5432/main`, 'postgresql-url'],
    ['postgresql', `postgresql://:${PW}@db.acme.io:5432/main`, 'postgresql-url'],
    ['mysql', `mysql://:${PW}@db.acme.io:3306/main`, 'mysql-url'],
    ['mongodb', `mongodb://:${PW}@db.acme.io`, 'mongodb-url'],
  ])('%s: reported', (_name, url, rule) => {
    expect(types(url)).toEqual([rule]);
  });

  it.each([
    ['a placeholder password', 'redis://:changeme@cache.acme.io:6379'],
    ['a variable reference', 'redis://:${REDIS_PASSWORD}@cache.acme.io:6379'],
    ['a compose service host with a template', 'redis://:<password>@cache:6379'],
  ])('still declined: %s', (_name, url) => {
    expect(types(url)).toEqual([]);
  });

  it.each([
    ['an empty password', 'redis://:@cache.acme.io:6379'],
    ['no userinfo at all', 'redis://cache.acme.io:6379'],
    ['a bare scheme', 'redis://:'],
  ])('not a credential: %s', (_name, url) => {
    expect(types(url)).toEqual([]);
  });
});
