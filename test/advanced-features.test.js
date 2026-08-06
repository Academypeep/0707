/**
 * Advanced features: Fuzzer, Metrics and Trend Analysis tests
 */

const { FuzzerIntegration } = require('../lib/fuzzer-integration');
const { MetricsDashboard } = require('../lib/metrics-dashboard');
const fs = require('fs');
const path = require('path');

describe('Mythos Advanced Features (Fuzzing & Dashboard Trends)', () => {
  const historyPath = './reports/test_scan_history.json';

  afterAll(() => {
    // Clean up test reports
    if (fs.existsSync(historyPath)) {
      fs.unlinkSync(historyPath);
    }
    if (fs.existsSync('./fuzz-targets')) {
      fs.rmSync('./fuzz-targets', { recursive: true, force: true });
    }
  });

  test('FuzzerIntegration should correctly produce C++ libFuzzer harness output files', () => {
    const fuzzer = new FuzzerIntegration();
    const resultPath = fuzzer.generateCppHarness('protocol.h', 'parsePacket');

    expect(fs.existsSync(resultPath)).toBe(true);
    const content = fs.readFileSync(resultPath, 'utf8');
    expect(content).toContain('LLVMFuzzerTestOneInput');
    expect(content).toContain('parsePacket(fuzzyInput)');
  });

  test('MetricsDashboard should correctly write logs and build trend computations', () => {
    const dashboard = new MetricsDashboard({ historyFile: historyPath });

    // Log a few dummy scans
    dashboard.logScan({
      findingsCount: 3,
      costUSD: 4.55,
      durationSeconds: 120
    });

    dashboard.logScan({
      findingsCount: 5,
      costUSD: 5.80,
      durationSeconds: 150
    });

    const analysis = dashboard.generateTrendAnalysis();
    expect(analysis.scanCount).toBe(2);
    expect(analysis.aggregateUSD).toBe(10.35);
    expect(analysis.averageCostUSD).toBe(5.175);
    expect(analysis.totalFindingsFound).toBe(8);
  });
});
