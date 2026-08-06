/**
 * Skill Manager
 * Dynamically loads configured external vendor skills and plugins
 * based on a local configuration file (config/skills.json).
 */

const fs = require('fs');
const path = require('path');

class SkillManager {
  constructor(options = {}) {
    this.configPath = options.configPath || './config/skills.json';
    this.skills = new Map();
  }

  /**
   * Load all configured skills dynamically
   */
  loadSkills() {
    const dir = path.dirname(this.configPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }

    // Generate default configuration if missing
    if (!fs.existsSync(this.configPath)) {
      const defaultConfig = {
        skills: [
          // Standard mock fallback plugin using local modules
          {
            name: "MockHeuristicScanner",
            version: "1.0.0",
            path: "../lib/mock-heuristic-skill",
            enabled: true
          }
        ]
      };
      fs.writeFileSync(this.configPath, JSON.stringify(defaultConfig, null, 2), 'utf8');
    }

    try {
      const config = JSON.parse(fs.readFileSync(this.configPath, 'utf8'));
      for (const entry of config.skills || []) {
        if (entry.enabled) {
          try {
            // Require the external package dynamically
            const SkillClass = require(entry.path);
            const skillInstance = new SkillClass();
            this.skills.set(entry.name, skillInstance);
            console.log(`🔌 Successfully loaded external skill: ${entry.name} v${entry.version}`);
          } catch (e) {
            console.warn(`⚠️ Failed to load external skill [${entry.name}] from path [${entry.path}]:`, e.message);
          }
        }
      }
    } catch (err) {
      console.warn('⚠️ Skill Manager failed to parse configurations:', err.message);
    }
  }

  /**
   * Run all loaded skills over a given context
   */
  async executeAll(context) {
    const allFindings = [];
    for (const [name, skill] of this.skills.entries()) {
      try {
        const findings = await skill.execute(context);
        if (Array.isArray(findings)) {
          allFindings.push(...findings.map(f => ({ ...f, sourceSkill: name })));
        }
      } catch (err) {
        console.error(`Error running skill ${name}:`, err.message);
      }
    }
    return allFindings;
  }
}

module.exports = { SkillManager };
