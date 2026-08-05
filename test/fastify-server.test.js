/**
 * Fastify Server unit testing suite
 */

const { buildFastifyServer } = require('../fastify-server');

describe('Fastify REST API & Mythos Agent Server Wrapper', () => {
  let server;

  beforeAll(() => {
    server = buildFastifyServer({ logger: false });
  });

  afterAll(async () => {
    await server.close();
  });

  test('/status endpoint should return service metadata', async () => {
    const response = await server.inject({
      method: 'GET',
      url: '/status'
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.status).toBe('online');
    expect(body.service).toContain('Mythos Agent');
  });

  test('/api/rank endpoint should retrieve prioritized list of files', async () => {
    const response = await server.inject({
      method: 'GET',
      url: '/api/rank'
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.success).toBe(true);
    expect(body.files.length).toBeGreaterThan(0);
    expect(body.files[0].path).toBeDefined();
  });

  test('/api/anomaly-detection endpoint should compute anomalies correctly', async () => {
    const response = await server.inject({
      method: 'POST',
      url: '/api/anomaly-detection',
      payload: {
        vector: [1, 0],
        baselineCentroid: [1, 0],
        threshold: 0.1
      }
    });

    expect(response.statusCode).toBe(200);
    const body = JSON.parse(response.body);
    expect(body.success).toBe(true);
    expect(body.isAnomaly).toBe(false);
  });
});
