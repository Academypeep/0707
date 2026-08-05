/**
 * REST API Fastify Server wrapping the Mythos Agent pipeline
 */

const Fastify = require('fastify');
const { MythosAgent } = require('./mythos-agent');
const { QdrantService } = require('./lib/qdrant-service');
const { VectorPostgresService } = require('./lib/vector-postgres-service');

function buildFastifyServer(options = {}) {
  const fastify = Fastify({
    logger: options.logger !== false
  });

  // Initialize service orchestrators
  const agent = new MythosAgent({
    targetDir: options.targetDir || '.',
    allowMock: true,
    apiKey: 'mock-key'
  });

  const qdrant = new QdrantService();
  const pgService = new VectorPostgresService();

  // Root status path
  fastify.get('/status', async (request, reply) => {
    return {
      status: 'online',
      service: 'Mythos Agent & Distributed Database System API',
      database: pgService.initialized ? 'PostgreSQL Vector' : 'Mock/Offline',
      timestamp: new Date().toISOString()
    };
  });

  // Rank local files
  fastify.get('/api/rank', async (request, reply) => {
    try {
      const ranked = agent.runFileRanking({ verbose: false });
      return {
        success: true,
        files: ranked.map(f => ({
          path: f.path,
          rank: f.rank,
          score: f.score,
          breakdown: f.breakdown
        }))
      };
    } catch (error) {
      reply.status(500);
      return { success: false, error: error.message };
    }
  });

  // Start autonomous hunting / VSP scan on a specific target file
  fastify.post('/api/hunt', async (request, reply) => {
    const { filePath, passAtK } = request.body || {};
    if (!filePath) {
      reply.status(400);
      return { success: false, error: 'filePath parameter is required.' };
    }

    try {
      const findings = await agent.huntFile(filePath, passAtK || 1);
      return {
        success: true,
        filePath,
        findingsCount: findings.length,
        findings
      };
    } catch (error) {
      reply.status(500);
      return { success: false, error: error.message };
    }
  });

  // Vector-based Anomaly detection endpoint
  fastify.post('/api/anomaly-detection', async (request, reply) => {
    const { vector, baselineCentroid, threshold } = request.body || {};
    if (!vector || !baselineCentroid) {
      reply.status(400);
      return { success: false, error: 'vector and baselineCentroid parameters are required.' };
    }

    try {
      const result = qdrant.detectAnomaly(vector, baselineCentroid, threshold || 0.15);
      return {
        success: true,
        ...result
      };
    } catch (error) {
      reply.status(500);
      return { success: false, error: error.message };
    }
  });

  return fastify;
}

// Start server if run directly
if (require.main === module) {
  const server = buildFastifyServer({ targetDir: '.' });
  const PORT = process.env.PORT || 3000;

  server.listen({ port: PORT, host: '0.0.0.0' }, (err, address) => {
    if (err) {
      server.log.error(err);
      process.exit(1);
    }
    console.log(`🚀 Fastify Mythos API running at ${address}`);
  });
}

module.exports = { buildFastifyServer };
