/**
 * Unit test suite for the dynamic plugin & Skill contract architecture
 */

const { SkillManager } = require('../lib/skill-manager');
const { BaseSkill } = require('../lib/skill-interface');
const fs = require('fs');

describe('Mythos Skill Plugin Architecture', () => {
  const testConfigPath = './config/test-skills.json';

  afterAll(() => {
    if (fs.existsSync(testConfigPath)) {
      fs.unlinkSync(testConfigPath);
    }
  });

  test('SkillManager should correctly load and execute standard BaseSkill sub-classes', async () => {
    // Instantiate test manager directed to a custom test config path
    const manager = new SkillManager({ configPath: testConfigPath });
    manager.loadSkills(); // Initializes default config with MockHeuristicScanner

    expect(manager.skills.has('MockHeuristicScanner')).toBe(true);

    const activeScanner = manager.skills.get('MockHeuristicScanner');
    expect(activeScanner).toBeInstanceOf(BaseSkill);

    // Test execution trigger over normal context
    const cleanContext = { path: 'clean.js', content: 'const a = 12;' };
    const cleanFindings = await manager.executeAll(cleanContext);
    expect(cleanFindings.length).toBe(0);

    // Test execution trigger over target context matching eval
    const dirtyContext = { path: 'vulnerable.js', content: 'eval(req.body.code);' };
    const findings = await manager.executeAll(dirtyContext);
    expect(findings.length).toBe(1);
    expect(findings[0].cwe).toBe('CWE-95');
    expect(findings[0].sourceSkill).toBe('MockHeuristicScanner');
  });
});
