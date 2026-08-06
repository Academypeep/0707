/**
 * Unit test suite for CLI Argument Parsing logic
 */

const { parseCLIArgs } = require('../lib/cli-args-parser');

describe('CLI Args Parser', () => {
  test('should parse targets and outputs properly', () => {
    const rawArgs = ['--target', './src', '--output', './report.json', '--format', 'json'];
    const parsed = parseCLIArgs(rawArgs);

    expect(parsed.targetDir).toBe('./src');
    expect(parsed.output).toBe('./report.json');
    expect(parsed.format).toBe('json');
  });

  test('should parse list of modified files properly for PR checks', () => {
    const rawArgs = ['--files', 'app.js,blockchain1.ts index.js'];
    const parsed = parseCLIArgs(rawArgs);

    expect(parsed.files).toEqual(['app.js', 'blockchain1.ts', 'index.js']);
  });
});
