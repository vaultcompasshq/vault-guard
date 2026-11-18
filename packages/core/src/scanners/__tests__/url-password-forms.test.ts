import { SecretScanner } from '../secret-scanner';

const scanner = new SecretScanner({});
const run = (text: string): { findings: number; declines: number } => {
  const ph = { count: 0, lines: [] as number[] };
  const m = scanner.scanContent(`${text}\n`, { placeholderSkips: ph });
  return { findings: m.length, declines: ph.count };
};

describe('passwords that are masks or variable references are not credentials', () => {
  it.each([
    ['a Celery mask', 'redis://:**@cache.acme.io:6379'],
    ['a long mask', 'redis://:****************@cache.acme.io:6379'],
    ['a Windows environment variable', 'redis://:%REDIS_PW%@cache.acme.io:6379'],
    ['a string concatenation', "redis://:'+pw+'@cache.acme.io:6379"],
    ['a shell variable', 'redis://:$REDIS_PW@cache.acme.io:6379'],
    ['a template', 'redis://:${REDIS_PW}@cache.acme.io:6379'],
  ])('%s: a counted decline', (_name, url) => {
    expect(run(url)).toEqual({ findings: 0, declines: 1 });
  });

  it('a real password is still a finding', () => {
    expect(run('redis://:Kq8vZ3pXw9Lm2Tn@cache.acme.io:6379')).toEqual({ findings: 1, declines: 0 });
  });

  it('a password that merely contains a star is still a finding', () => {
    expect(run('redis://:Kq8*vZ3pXw9Lm2Tn@cache.acme.io:6379')).toEqual({ findings: 1, declines: 0 });
  });
});
