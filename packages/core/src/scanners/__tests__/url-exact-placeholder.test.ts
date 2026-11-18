import { isNameShaped } from '../../utils/placeholder';
import { SecretScanner } from '../secret-scanner';

const scanner = new SecretScanner({});
const R = 'Kq8vZ3pXw9Lm2Tn';

interface Outcome {
  findings: number;
  kinds: Array<string | undefined>;
  declines: number;
}

const mark = (text: string): Outcome => {
  const ph = { count: 0, lines: [] as number[] };
  const m = scanner.scanContent(`${text}\n`, { inlineDirectives: 'mark', placeholderSkips: ph });
  return { findings: m.length, kinds: m.map(x => x.contextFilterNotHonoured), declines: ph.count };
};
const plain = (text: string): Outcome => {
  const ph = { count: 0, lines: [] as number[] };
  const m = scanner.scanContent(`${text}\n`, { placeholderSkips: ph });
  return { findings: m.length, kinds: m.map(x => x.contextFilterNotHonoured), declines: ph.count };
};

describe('mark mode: a URL is a counted decline only when its password is exactly a placeholder', () => {
  it.each([
    ['the word password, local host', 'postgres://user:password@localhost/db'],
    ['changeme on redis with an empty user', 'redis://:changeme@host:6379'],
    ['a case-insensitive word', 'mysql://app:Your_Password@db.acme.io/main'],
    ['PLACEHOLDER', 'mongodb://app:PLACEHOLDER@db.acme.io'],
    ['a ${VAR} template', 'postgres://app:${DB_PASS}@db.acme.io/main'],
    ['a $VAR template', 'redis://:$REDIS_PW@cache.acme.io:6379'],
    ['an angle template', 'postgres://app:<password>@db.acme.io/main'],
    ['a {{VAR}} template', 'postgres://app:{{db_pass}}@db.acme.io/main'],
    ['a $(cmd) template', 'postgres://app:$(pw)@db.acme.io/main'],
    ['a run of x', 'postgres://app:xxxxxxxx@db.acme.io/main'],
    ['a run of stars', 'redis://:**@cache.acme.io:6379'],
  ])('%s: one counted decline, no finding', (_name, url) => {
    expect(mark(url)).toEqual({ findings: 0, kinds: [], declines: 1 });
  });

  it.each([
    ['%2e decodes to a letter: the raw text hides "example"', `postgres://app:%2exampleKq8vZ3pXw9Lm2Tn@db.prod.acme.io/main`, 'url-context'],
    ['%2d decodes to a hyphen', `redis://u:%2dummyKq8vZ3pXw9Lm2Tn@db.prod.acme.io:6379`, 'url-context'],
    ['a marker as a substring', 'postgres://user:example123@h.acme.io/db', 'url-context'],
    ['a marker as a substring of a longer word', 'postgres://user:Contest2024Qz@h.acme.io/db', 'url-context'],
    ['user equal to password', `postgres://${R}:${R}@db.prod.acme.io/main`, 'url-context'],
    ['a placeholder word plus a digit', 'postgres://app:changeme1@db.prod.acme.io/main', 'url-context'],
    ['a marker only in the host', `postgres://app:${R}@example-cache.acme.io:5432/main`, 'url-context'],
    ['a bare host with a real password', `postgres://app:${R}@db/main`, 'url-context'],
    ['a plainly real password', `postgres://app:${R}@db.prod.acme.io/main`, undefined],
  ])('%s: kept', (_name, url, kind) => {
    expect(mark(url)).toEqual({ findings: 1, kinds: [kind], declines: 0 });
  });

  it.each([
    ['a `#` before the real password parameter', `postgres://app:placeholder@db.prod.acme.io/main?application_name=x#&password=${R}`],
    ['a `?` inside the userinfo', 'postgres://app:${PW?}@db.prod.acme.io/main?password=' + R],
    ['an encoded query key', `postgres://app:placeholder@db.prod.acme.io/main?pass%77ord=${R}`],
    ['an unlisted key', `postgres://app:placeholder@db.prod.acme.io/main?password2=${R}`],
    ['two @ (which one ends the userinfo is a guess)', `postgres://app:password@${R}@db.prod.acme.io/main`],
    ['an exact placeholder with a query at all', 'postgres://app:placeholder@db.prod.acme.io/main?sslmode=require'],
  ])('a placeholder password never clears a token a driver reads differently: %s', (_name, url) => {
    expect(mark(url)).toEqual({ findings: 1, kinds: ['url-context'], declines: 0 });
  });

  it.each([
    ['braces around a real password', `postgres://app:{${R}}@db.prod.acme.io/main`],
    ['angle brackets around a real password', `postgres://app:<${R}>@db.prod.acme.io/main`],
    ['a dollar and braces around a real password', `postgres://app:$` + `{${R}}@db.prod.acme.io/main`],
    ['a dollar before a real password', `postgres://app:$${R}@db.prod.acme.io/main`],
    ['double braces around a real password', `postgres://app:{{${R}}}@db.prod.acme.io/main`],
    ['a command substitution around a real password', `postgres://app:$(${R})@db.prod.acme.io/main`],
    ['a name with a digit run of four', 'postgres://app:<password1234>@db.prod.acme.io/main'],
    ['a camelCase name', 'postgres://app:<yourPassword>@db.prod.acme.io/main'],
    ['a name longer than 64 characters', `postgres://app:<${'a'.repeat(65)}>@db.prod.acme.io/main`],
  ])('a template whose inside is not name-shaped is kept: %s', (_name, url) => {
    expect(mark(url)).toEqual({ findings: 1, kinds: ['url-context'], declines: 0 });
  });

  it.each([
    ['DB_PASSWORD', 'postgres://app:$' + '{DB_PASSWORD}@db.prod.acme.io/main'],
    ['a dotted name', 'postgres://app:<db.password>@db.prod.acme.io/main'],
    ['a hyphenated name', 'postgres://app:{your-password}@db.prod.acme.io/main'],
    ['a name with a digit', 'postgres://app:$(pg_pw_1)@db.prod.acme.io/main'],
    ['a $VAR with a digit', 'redis://:$REDIS_PW2@cache.acme.io:6379'],
  ])('a name-shaped template is a counted decline: %s', (_name, url) => {
    expect(mark(url)).toEqual({ findings: 0, kinds: [], declines: 1 });
  });

  it('isNameShaped: what counts as a name', () => {
    for (const ok of ['DB_PASSWORD', 'db.password', 'your-password', 'password 1', 'a', '_x', 'PW1', 'a'.repeat(64)]) {
      expect([ok, isNameShaped(ok)]).toEqual([ok, true]);
    }
    for (const bad of ['', '1abc', 'yourPassword', 'Kq8vZ3pXw9Lm2Tn', 'password1234', 'a'.repeat(65), 'two  spaces', 'a$b', 'pass1_2_3_4']) {
      expect([bad, isNameShaped(bad)]).toEqual([bad, false]);
    }
  });

  it('elsewhere a marker anywhere in the URL still declines it (unchanged)', () => {
    expect(plain('postgres://user:example123@h.acme.io/db')).toEqual({ findings: 0, kinds: [], declines: 1 });
    expect(plain(`postgres://${R}:${R}@db.prod.acme.io/main`)).toEqual({ findings: 0, kinds: [], declines: 1 });
  });
});

describe('mark mode: a URL with userinfo that no rule matched is kept', () => {
  it.each([
    ['the Azure single-server form', `postgres://myadmin@mydemoserver:${R}@x.postgres.database.azure.com:5432/db`, 'postgresql-url'],
    ['an apostrophe in the user', `mysql://o'neil:${R}@host.acme.io/db`, 'mysql-url'],
    ['mongodb', `mongodb://o'neil:${R}@host.acme.io`, 'mongodb-url'],
    ['redis', `redis://o'neil:${R}@host.acme.io:6379`, 'redis-url'],
  ])('%s: a finding for its rule, url-context', (_name, url, rule) => {
    const m = scanner.scanContent(`${url}\n`, { inlineDirectives: 'mark' });
    expect(m.map(x => [x.type, x.contextFilterNotHonoured])).toEqual([[rule, 'url-context']]);
  });

  it('elsewhere the rules still match nothing there (unchanged)', () => {
    expect(plain(`postgres://myadmin@mydemoserver:${R}@x.postgres.database.azure.com:5432/db`).findings).toBe(0);
  });

  it('an exact placeholder password in such a shape is still a counted decline', () => {
    expect(mark("mysql://o'neil:password@host.acme.io/db")).toEqual({ findings: 0, kinds: [], declines: 1 });
  });

  it.each([
    ['redis host and port', 'redis://host:6379/0'],
    ['postgres host and port', 'postgres://host:5432/db'],
    ['an IPv6 host', 'redis://[::1]:6379/0'],
    ['an empty password', 'redis://:@host'],
  ])('does not fire on %s', (_name, text) => {
    expect(mark(text).findings).toBe(0);
  });
});

describe('mark mode: the Azure rule', () => {
  const key = (k: string, name = 'acct'): string => `DefaultEndpointsProtocol=https;AccountName=${name};AccountKey=${k}`;

  it('an AccountKey that is exactly a run of x is a counted decline', () => {
    expect(mark(key('x'.repeat(30)))).toEqual({ findings: 0, kinds: [], declines: 1 });
  });
  it('a real key with a marker in the account name is kept, url-context', () => {
    expect(mark(key(`${R}${R}${R}${R}==`, 'examplestore'))).toEqual({ findings: 1, kinds: ['url-context'], declines: 0 });
  });
  it('AccountKey spelled twice is kept', () => {
    expect(mark(key('x'.repeat(30), 'AccountKey=example')).findings).toBe(1);
  });
});

describe('mark mode: what cannot be read is kept whole', () => {
  it('a contrived rule match with no userinfo and a marker in it is kept, url-context (elsewhere declined)', () => {
    const patterns = (scanner as unknown as { patterns: Map<string, { regex: RegExp }> }).patterns;
    const entry = patterns.get('redis-url') as { regex: RegExp };
    const original = entry.regex;
    entry.regex = /redis:\/\/[^\s]+/g;
    try {
      expect(mark('redis://example-cache.acme.io:6379')).toEqual({ findings: 1, kinds: ['url-context'], declines: 0 });
      expect(plain('redis://example-cache.acme.io:6379').findings).toBe(0);
    } finally {
      entry.regex = original;
    }
  });
});
