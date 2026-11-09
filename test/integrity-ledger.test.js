const { IntegrityLedger } = require('../lib/integrity-ledger');

describe('IntegrityLedger', () => {
  test('records finding receipts with sha256 hash', () => {
    const ledger = new IntegrityLedger();
    const entry = ledger.recordReceipt({ cwe: 'CWE-78', file: 'app.js' }, { status: 'verified' });

    expect(entry.receiptHash).toBeDefined();
    expect(entry.receiptHash).toHaveLength(64);
    expect(ledger.receipts).toHaveLength(1);
  });

  test('verifies claims against scan evidence', () => {
    const ledger = new IntegrityLedger();
    const res = ledger.verifyClaims({ scopeDenied: true, findings: [{ location: 'app.js:10' }] });

    expect(res.verified).toBe(true);
    expect(res.passedClaims).toBe(3);
  });
});
