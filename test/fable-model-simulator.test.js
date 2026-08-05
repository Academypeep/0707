/**
 * FableModelSimulator Test Suite
 * Verifies simulated vulnerability discovery and validation accuracy
 */

const { FableModelSimulator } = require('../lib/fable-model-simulator');

describe('FableModelSimulator', () => {
  test('should simulate hunt and detect critical sinks in JS code', () => {
    const code = `
      const evalResult = eval(untrusted);
      const execResult = child_process.exec(cmd);
    `;
    const findings = FableModelSimulator.simulateHunt(code, 'src/api.js', 'javascript');

    expect(Array.isArray(findings)).toBe(true);
    expect(findings.length).toBeGreaterThanOrEqual(1);

    const cweList = findings.map(f => f.cwe);
    expect(cweList).toContain('CWE-95'); // eval
    expect(cweList).toContain('CWE-78'); // exec
  });

  test('should simulate validation with high confidence for real findings', () => {
    const finding = {
      cwe: 'CWE-78',
      location: 'src/api.js:15',
      poc: 'payload_test'
    };

    const response = FableModelSimulator.simulateValidation(finding);
    expect(response).toContain('IS_REAL: YES');
    expect(response).toContain('CONFIDENCE: 92');
    expect(response).toContain('POC_CONFIRMED: payload_test');
  });
});
