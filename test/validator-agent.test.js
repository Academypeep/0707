/**
 * ValidatorAgent Test Suite
 * Verifies mock validation mode and FP tracking
 */

const { ValidatorAgent } = require('../lib/validator-agent');

describe('ValidatorAgent', () => {
  test('should initialize correctly with allowMock true', () => {
    const validator = new ValidatorAgent({
      allowMock: true,
      apiKey: 'mock-key'
    });
    expect(validator.allowMock).toBe(true);
  });

  test('should bypass real Anthropic SDK when allowMock is enabled', async () => {
    const validator = new ValidatorAgent({
      allowMock: true,
      apiKey: 'mock-key'
    });

    const finding = {
      cwe: 'CWE-78',
      title: 'Command Injection',
      severity: 'CRITICAL',
      location: 'test/phases-aggregation.test.js:15',
      evidence: 'exec(req.body.cmd)'
    };

    const result = await validator.validateFinding(finding);
    expect(result.isReal).toBe(true);
    expect(result.confidence).toBe(92);
  });

  test('should validate batch of findings and track stats', async () => {
    const validator = new ValidatorAgent({
      allowMock: true,
      apiKey: 'mock-key'
    });

    const mockFindings = [
      {
        cwe: 'CWE-89',
        title: 'SQL Injection',
        severity: 'HIGH',
        location: 'test/phases-aggregation.test.js:45'
      }
    ];

    const validated = await validator.validateFindings(mockFindings);
    expect(validated.length).toBe(1);
    expect(validator.getSummary().verified).toBe(1);
    expect(validator.getFalsePositiveRate()).toBe("0.0");
  });
});
