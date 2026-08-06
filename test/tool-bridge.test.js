/**
 * Unit tests for tool-bridge static analysis generation parser.
 */

const { parseSemgrepJson, parseSarif, buildStaticAnalysisSummary } = require('../lib/tool-bridge');

describe('tool-bridge Static Analysis Parser', () => {
  test('parseSemgrepJson should parse raw JSON schema to standard findings format', () => {
    const rawSemgrep = {
      results: [
        {
          check_id: "rules.security.javascript.eval",
          path: "app.js",
          start: { line: 10 },
          extra: {
            message: "Insecure use of eval detected",
            severity: "ERROR"
          }
        }
      ]
    };

    const parsed = parseSemgrepJson(rawSemgrep);
    expect(parsed.length).toBe(1);
    expect(parsed[0].tool).toBe('semgrep');
    expect(parsed[0].file).toBe('app.js');
    expect(parsed[0].line).toBe(10);
    expect(parsed[0].message).toContain('eval detected');
  });

  test('parseSarif should parse raw CodeQL SARIF schema correctly', () => {
    const rawSarif = {
      runs: [
        {
          tool: { driver: { name: 'codeql' } },
          results: [
            {
              ruleId: "js/sql-injection",
              message: { text: "SQL injection from HTTP parameter" },
              locations: [
                {
                  physicalLocation: {
                    artifactLocation: { uri: "src/db.ts" },
                    region: { startLine: 45 }
                  }
                }
              ]
            }
          ]
        }
      ]
    };

    const parsed = parseSarif(rawSarif);
    expect(parsed.length).toBe(1);
    expect(parsed[0].tool).toBe('codeql');
    expect(parsed[0].file).toBe('src/db.ts');
    expect(parsed[0].line).toBe(45);
    expect(parsed[0].checkId).toBe('js/sql-injection');
  });

  test('buildStaticAnalysisSummary should create clean concise prompt annotations', () => {
    const findings = [
      {
        tool: 'semgrep',
        checkId: 'rules.security.eval',
        message: 'Insecure eval usage',
        file: 'server.js',
        line: 12
      }
    ];

    const summary = buildStaticAnalysisSummary(findings, 'server.js');
    expect(summary).toContain('Static analysis annotations for server.js:');
    expect(summary).toContain('Insecure eval usage');
  });
});
