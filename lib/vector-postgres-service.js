/**
 * Vector PostgreSQL Database Service
 * Provides wrapper interfaces for storing vectors, logs, and findings in PG.
 * Also provides a vector similarity metric calculator for nearest-neighbor lookups.
 */

const { Client } = require('pg');

class VectorPostgresService {
  constructor(config = {}) {
    this.connectionString = config.connectionString || process.env.DATABASE_URL || 'postgresql://postgres:postgres@localhost:5432/mythos';
    this.client = null;
    this.initialized = false;
  }

  /**
   * Safe Init / Schema creation stub (using mock fallback if connection fails or offline)
   */
  async init() {
    try {
      this.client = new Client({
        connectionString: this.connectionString,
        statement_timeout: 5000
      });
      await this.client.connect();

      // Initialize extensions & tables if connected
      await this.client.query('CREATE EXTENSION IF NOT EXISTS vector;');
      await this.client.query(`
        CREATE TABLE IF NOT EXISTS vulnerability_embeddings (
          id UUID PRIMARY KEY,
          file_path TEXT NOT NULL,
          cwe TEXT NOT NULL,
          embedding vector(1536) NOT NULL,
          payload JSONB NOT NULL,
          created_at TIMESTAMPTZ DEFAULT NOW()
        );
      `);
      this.initialized = true;
      console.log('🐘 PostgreSQL connected and vector tables initialized.');
    } catch (error) {
      console.warn('⚠️ Vector Postgres database initialized in offline/mock fallback mode. Error:', error.message);
      this.client = null;
      this.initialized = false;
    }
  }

  /**
   * Save a vector embedding with finding payload
   */
  async saveEmbedding(id, filePath, cwe, embedding, payload) {
    if (!this.initialized || !this.client) {
      // Mock storage
      return { id, status: 'mock_saved', payload };
    }

    try {
      await this.client.query(
        'INSERT INTO vulnerability_embeddings (id, file_path, cwe, embedding, payload) VALUES ($1, $2, $3, $4, $5) ON CONFLICT (id) DO UPDATE SET payload = $5;',
        [id, filePath, cwe, JSON.stringify(embedding), JSON.stringify(payload)]
      );
      return { id, status: 'saved' };
    } catch (error) {
      throw new Error(`Failed to save embedding in Postgres: ${error.message}`);
    }
  }

  /**
   * Retrieve similar vulnerability vector embeddings using Cosine Distance
   */
  async searchSimilarEmbeddings(embedding, limit = 5) {
    if (!this.initialized || !this.client) {
      // Mock offline retrieval returns empty
      return [];
    }

    try {
      const response = await this.client.query(
        'SELECT id, file_path, cwe, payload, (embedding <=> $1) as distance FROM vulnerability_embeddings ORDER BY embedding <=> $1 LIMIT $2;',
        [JSON.stringify(embedding), limit]
      );
      return response.rows;
    } catch (error) {
      throw new Error(`Failed to query vectors in Postgres: ${error.message}`);
    }
  }

  /**
   * Close PG Client connection
   */
  async close() {
    if (this.client) {
      await this.client.end();
    }
  }
}

module.exports = { VectorPostgresService };
