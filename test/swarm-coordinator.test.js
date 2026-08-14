const path = require('path');
const { SwarmCoordinator } = require('../lib/swarm-coordinator');

describe('SwarmCoordinator', () => {
  test('initializes 8 operator roles', () => {
    const swarm = new SwarmCoordinator({ targetDir: path.resolve(__dirname, '..') });
    expect(swarm.operators).toHaveLength(8);
    expect(swarm.operators).toContain('recon');
    expect(swarm.operators).toContain('scanner');
    expect(swarm.operators).toContain('exploiter');
  });

  test('executes autonomous mission end-to-end in mock mode', async () => {
    const targetDir = path.resolve(__dirname, '..');
    const swarm = new SwarmCoordinator({
      targetDir,
      target: 'localhost',
      allowMock: true,
      apiKey: 'mock-key'
    });

    const res = await swarm.executeMission('localhost');
    expect(res.operatorsExecuted.length).toBeGreaterThan(0);
    expect(res.reportPath).toBeDefined();
  });

  test('blocks off-scope mission execution', async () => {
    const targetDir = path.resolve(__dirname, '..');
    const swarm = new SwarmCoordinator({
      targetDir,
      target: 'authorized.com',
      allowMock: true
    });

    const res = await swarm.executeMission('unauthorized-external-domain.com');
    expect(res.status).toBe('denied');
    expect(res.reason).toContain('SCOPE DENIED');
  });
});
