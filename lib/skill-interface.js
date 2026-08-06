/**
 * Standard Skill Interface Definition
 * Defines the strict interface and contract that external vendor packages
 * and modular plugins must implement to extend the Mythos Agent.
 */

class BaseSkill {
  constructor(name, version) {
    this.name = name || 'base-skill';
    this.version = version || '1.0.0';
  }

  /**
   * Main execution interface hook called during scans
   * @param {Object} context - Code context, file path, current ranked file metadata
   * @returns {Promise<Array<Object>>} - Discovered findings/predictions
   */
  async execute(context) {
    throw new Error('Skill execution hook must be implemented by vendor subclasses');
  }

  /**
   * Healthcheck interface hook verifying external tool/model endpoints
   * @returns {Promise<boolean>}
   */
  async isHealthy() {
    return true;
  }
}

module.exports = { BaseSkill };
