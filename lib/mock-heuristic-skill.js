const { BaseSkill } = require('./skill-interface');

/**
 * Mock heuristic scanner implementing the standard Skill contract.
 */
class MockHeuristicSkill extends BaseSkill {
  constructor() {
    super('MockHeuristicScanner', '1.0.0');
  }

  async execute(context) {
    // Simple heuristic detection simulation
    if (context && context.content && context.content.includes('eval(')) {
      return [{
        name: 'Evaluation of Dangerous Code Block (Dynamic Eval)',
        severity: 'CRITICAL',
        category: 'code-exec',
        file: context.path || 'unknown',
        line: 1,
        cwe: 'CWE-95',
        confidence: 0.9,
        description: 'Heuristic skill matched an inline eval statement inside the content.'
      }];
    }
    return [];
  }
}

module.exports = MockHeuristicSkill;
