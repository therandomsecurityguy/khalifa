import { globMatch } from './glob';

describe('globMatch', () => {
  it.each([
    ['*', '', true],
    ['*', 'anything', true],
    ['lambda:Invoke*', 'lambda:invokefunction', true],
    ['lambda:invoke?unction', 'lambda:invokefunction', true],
    ['lambda:invoke?', 'lambda:invokefunction', false],
    ['get*secret*', 'getsecretvalue', true],
    ['arn:aws:iam::*:role/a*b*c', 'arn:aws:iam::1:role/axxbyyc', true],
    ['arn:aws:iam::*:role/a*b*c', 'arn:aws:iam::1:role/axxbyy', false],
    ['a.b', 'axb', false],
    ['a+b', 'a+b', true],
    ['', '', true],
    ['', 'x', false],
  ])('%s matches %s: %s', (pattern, text, expected) => {
    expect(globMatch(pattern, text)).toBe(expected);
  });

  it('stays fast on a pattern that makes a regex backtrack', () => {
    const started = Date.now();
    expect(globMatch(`${'*a'.repeat(40)}b`, 'a'.repeat(5000))).toBe(false);
    expect(Date.now() - started).toBeLessThan(1000);
  });
});
