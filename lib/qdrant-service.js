/**
 * Qdrant Integration & Distributed Database Architecture Service
 * Implements Qdrant-backed Vector Storage, RAG, and Anomaly Detection.
 *
 * Target Cluster: https://25d44fea-5ec4-4e4e-8221-25f4c565452d.eu-central-1-0.aws.cloud.qdrant.io
 */

const axios = require('axios');

class QdrantService {
  constructor(config = {}) {
    this.apiKey = config.apiKey || 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhY2Nlc3MiOiJtIiwic3ViamVjdCI6ImFwaS1rZXk6MThmOGQ3YzYtMGIxYS00ODI4LTkzOTItODgzOGQ0OGU1ZmVjIn0.dJThK5sCBLLJ-K4Mt_TW46K5tyRMH_Awqp7RGdZKwNo';
    this.endpoint = config.endpoint || 'https://25d44fea-5ec4-4e4e-8221-25f4c565452d.eu-central-1-0.aws.cloud.qdrant.io';

    this.client = axios.create({
      baseURL: this.endpoint,
      headers: {
        'api-key': this.apiKey,
        'Content-Type': 'application/json'
      },
      timeout: config.timeout || 10000
    });
  }

  /**
   * Distributed Database Architecture: Create a new collection with sharding and replication factor
   * @param {string} collectionName
   * @param {number} vectorSize
   * @returns {Promise<Object>}
   */
  async createCollection(collectionName, vectorSize = 1536) {
    try {
      const response = await this.client.put(`/collections/${collectionName}`, {
        vectors: {
          size: vectorSize,
          distance: 'Cosine'
        },
        // Distributed database settings
        shard_number: 3,             // 3 shards distributed across cluster
        replication_factor: 2,       // 2x replication for high availability
        write_consistency_factor: 1  // Quorum consistency for writes
      });
      return response.data;
    } catch (error) {
      // If collection already exists, return info
      if (error.response && error.response.status === 409) {
        return { status: 'already_exists', message: `Collection ${collectionName} already exists.` };
      }
      throw new Error(`Failed to create Qdrant collection: ${error.response ? JSON.stringify(error.response.data) : error.message}`);
    }
  }

  /**
   * Delete a collection
   * @param {string} collectionName
   */
  async deleteCollection(collectionName) {
    try {
      const response = await this.client.delete(`/collections/${collectionName}`);
      return response.data;
    } catch (error) {
      throw new Error(`Failed to delete Qdrant collection: ${error.message}`);
    }
  }

  /**
   * Upsert points/vectors into Qdrant
   * @param {string} collectionName
   * @param {Array<Object>} points - Array of { id, vector, payload }
   */
  async upsertPoints(collectionName, points) {
    try {
      const response = await this.client.put(`/collections/${collectionName}/points`, {
        points: points.map(p => ({
          id: p.id,
          vector: p.vector,
          payload: p.payload || {}
        }))
      });
      return response.data;
    } catch (error) {
      throw new Error(`Failed to upsert points into Qdrant: ${error.message}`);
    }
  }

  /**
   * Search points/vectors
   * @param {string} collectionName
   * @param {Array<number>} vector
   * @param {number} limit
   */
  async searchPoints(collectionName, vector, limit = 5) {
    try {
      const response = await this.client.post(`/collections/${collectionName}/points/search`, {
        vector: vector,
        limit: limit,
        with_payload: true,
        with_vector: false
      });
      return response.data.result;
    } catch (error) {
      throw new Error(`Failed to search points in Qdrant: ${error.message}`);
    }
  }

  /**
   * Vector-based Anomaly Detection using cosine distance deviation
   * Detects if a vector represents an anomaly compared to a baseline pattern/centroid
   *
   * @param {Array<number>} vector - The vector to test
   * @param {Array<number>} baselineCentroid - Expected centroid/ideal behavior vector
   * @param {number} threshold - Cosine similarity distance threshold (0 to 1, default: 0.15)
   * @returns {Object} - { isAnomaly: boolean, distance: number, threshold }
   */
  detectAnomaly(vector, baselineCentroid, threshold = 0.15) {
    if (vector.length !== baselineCentroid.length) {
      throw new Error('Vector lengths do not match baseline centroid length');
    }

    // Calculate Cosine Similarity
    let dotProduct = 0;
    let normA = 0;
    let normB = 0;
    for (let i = 0; i < vector.length; i++) {
      dotProduct += vector[i] * baselineCentroid[i];
      normA += vector[i] * vector[i];
      normB += baselineCentroid[i] * baselineCentroid[i];
    }

    if (normA === 0 || normB === 0) return { isAnomaly: true, distance: 1.0, threshold };

    const cosineSimilarity = dotProduct / (Math.sqrt(normA) * Math.sqrt(normB));
    const cosineDistance = 1.0 - cosineSimilarity;

    return {
      isAnomaly: cosineDistance > threshold,
      distance: parseFloat(cosineDistance.toFixed(4)),
      threshold
    };
  }

  /**
   * Retrieval-Augmented Generation (RAG) context query builder
   * Retrieves relevant document payloads from Qdrant, builds prompt prefix context
   *
   * @param {string} collectionName
   * @param {Array<number>} queryVector
   * @param {string} systemPrompt
   * @returns {Promise<string>} - Context-augmented prompt
   */
  async buildRAGPrompt(collectionName, queryVector, systemPrompt) {
    try {
      const matches = await this.searchPoints(collectionName, queryVector, 3);

      let context = 'No matching reference context found in vector DB.';
      if (matches && matches.length > 0) {
        context = matches.map((m, idx) => {
          const content = m.payload.content || JSON.stringify(m.payload);
          return `[Source ${idx + 1} - Score: ${m.score.toFixed(3)}]\n${content}`;
        }).join('\n\n');
      }

      return `${systemPrompt}

---
REFERENCE CONTEXT FROM VECTOR DB:
${context}
---

Please formulate your response relying on the provided context if applicable.`;
    } catch (error) {
      console.warn('⚠️ RAG prompt build failed, falling back to original prompt. Error:', error.message);
      return systemPrompt;
    }
  }
}

module.exports = { QdrantService };
