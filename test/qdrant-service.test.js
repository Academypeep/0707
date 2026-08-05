/**
 * Qdrant integration & Distributed Database system unit test suite
 */

const { QdrantService } = require('../lib/qdrant-service');

describe('QdrantService & Distributed DB with Anomaly Detection', () => {
  let service;

  beforeAll(() => {
    service = new QdrantService();
  });

  test('detectAnomaly should identify normal vs anomalous vectors correctly', () => {
    const baseline = [1, 0, 0, 0];
    const normal = [0.95, 0.1, 0, 0];
    const anomaly = [0.1, 0.9, 0.3, 0];

    const normalResult = service.detectAnomaly(normal, baseline, 0.15);
    const anomalyResult = service.detectAnomaly(anomaly, baseline, 0.15);

    expect(normalResult.isAnomaly).toBe(false);
    expect(normalResult.distance).toBeLessThan(0.15);

    expect(anomalyResult.isAnomaly).toBe(true);
    expect(anomalyResult.distance).toBeGreaterThan(0.15);
  });

  test('buildRAGPrompt fallback should return original prompt when Qdrant search is mocked or offline', async () => {
    const originalPrompt = 'Analyze the current server access patterns.';
    const queryVector = Array(1536).fill(0.1);

    // Will catch and fall back to original prompt safely since we are offline
    const ragPrompt = await service.buildRAGPrompt('non_existent_collection', queryVector, originalPrompt);
    expect(ragPrompt).toContain(originalPrompt);
  });
});
