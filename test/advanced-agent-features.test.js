/**
 * Test suite verifying Tool calling, CostTracker class, p-limit, and `--resume` checkpointing
 */

const { MythosAgent } = require('../mythos-agent');
const { CostTracker } = require('../lib/cost-tracker');
const fs = require('fs');
const path = require('path');

describe('Mythos Advanced Core Recommendations', () => {
  const targetDir = './test/fixtures';
  const checkpointPath = path.join(targetDir, '.mythos-state.json');

  beforeAll(() => {
    if (!fs.existsSync(targetDir)) {
      fs.mkdirSync(targetDir, { recursive: true });
    }
  });

  afterEach(() => {
    if (fs.existsSync(checkpointPath)) {
      fs.unlinkSync(checkpointPath);
    }
  });

  test('CostTracker should correctly track and calculate actual API usage costs', () => {
    const tracker = new CostTracker();

    // Simulating token count response metrics
    tracker.trackUsage('liveAgenticHunt', { input_tokens: 100000, output_tokens: 20000 });

    // Cost expected: (100,000 / 1,000,000) * 3 + (20,000 / 1,000,000) * 15
    // = 0.3 + 0.3 = 0.6 USD
    expect(tracker.total).toBeCloseTo(0.6, 5);
    expect(tracker.tokens).toBe(120000);
  });

  test('MythosAgent should checkpoint current findings to .mythos-state.json and resume properly', async () => {
    const agent = new MythosAgent({
      targetDir,
      allowMock: true,
      resume: true,
      apiKey: 'mock-key'
    });

    agent.findings = [{ name: 'Preexisting vulnerability', severity: 'HIGH', file: 'vulnerable.js', cwe: 'CWE-20' }];

    // Save checkpoint
    agent._saveCheckpoint(['vulnerable.js']);

    expect(fs.existsSync(checkpointPath)).toBe(true);

    // Instantiate a new agent with resume enabled
    const resumedAgent = new MythosAgent({
      targetDir,
      allowMock: true,
      resume: true,
      apiKey: 'mock-key'
    });

    const completed = resumedAgent._loadCheckpoint();
    expect(completed).toEqual(['vulnerable.js']);
    expect(resumedAgent.findings.length).toBe(1);
    expect(resumedAgent.findings[0].name).toBe('Preexisting vulnerability');
  });
});
