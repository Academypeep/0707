const { EgressScopeContainment } = require('../lib/egress-scope');

describe('EgressScopeContainment', () => {
  test('allows primary target domain and subdomains', () => {
    const scope = new EgressScopeContainment({ target: 'example.com' });

    expect(scope.isAllowed('example.com').allowed).toBe(true);
    expect(scope.isAllowed('http://example.com/api').allowed).toBe(true);
    expect(scope.isAllowed('https://sub.example.com').allowed).toBe(true);
  });

  test('denies off-scope domains', () => {
    const scope = new EgressScopeContainment({ target: 'example.com' });

    const res = scope.isAllowed('https://evil.com');
    expect(res.allowed).toBe(false);
    expect(res.reason).toContain('SCOPE DENIED');
  });

  test('allows loopback addresses by default', () => {
    const scope = new EgressScopeContainment({ target: 'example.com' });

    expect(scope.isAllowed('localhost').allowed).toBe(true);
    expect(scope.isAllowed('127.0.0.1').allowed).toBe(true);
    expect(scope.isAllowed('::1').allowed).toBe(true);
  });

  test('assertAllowed throws on off-scope target', () => {
    const scope = new EgressScopeContainment({ target: 'example.com' });

    expect(() => scope.assertAllowed('https://unauthorized-target.org')).toThrow('SCOPE DENIED');
  });
});
