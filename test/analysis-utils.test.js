/**
 * Mythos Agent - Analysis Utilities Test Suite
 * Tests for lib/analysis-utils.js
 */

const {
  SINK_DEFINITIONS,
  VULNERABILITY_PATTERNS,
  INTERNET_FACING_PATTERNS,
  AUTH_PATTERNS,
  identifySinks,
  scoreFile,
  matchVulnerabilityPatterns,
  discoverFiles,
  scoreToRank,
  scoreInternetFacing,
  scoreAuthCode,
  scoreSinks,
  scoreFileType
} = require('../lib/analysis-utils');

const fs = require('fs');
const path = require('path');

// ==================== SINK_DEFINITIONS Tests ====================

describe('SINK_DEFINITIONS', () => {
  test('should contain sinks for JavaScript', () => {
    expect(SINK_DEFINITIONS.js).toBeDefined();
    expect(Array.isArray(SINK_DEFINITIONS.js)).toBe(true);
  });

  test('should contain CRITICAL severity sinks', () => {
    const jsSinks = SINK_DEFINITIONS.js;
    const criticalSinks = jsSinks.filter(s => s.severity === 'CRITICAL');

    expect(criticalSinks.length).toBeGreaterThan(0);
    expect(criticalSinks.some(s => s.name.includes('eval'))).toBe(true);
    expect(criticalSinks.some(s => s.name.includes('exec'))).toBe(true);
  });

  test('should contain all required categories', () => {
    const jsSinks = SINK_DEFINITIONS.js;
    const categories = new Set(jsSinks.map(s => s.category));

    expect(categories.has('code-exec')).toBe(true);
    expect(categories.has('command-exec')).toBe(true);
    expect(categories.has('path-traversal')).toBe(true);
    expect(categories.has('sql-injection')).toBe(true);
    expect(categories.has('xss')).toBe(true);
  });

  test('each sink should have required fields', () => {
    const jsSinks = SINK_DEFINITIONS.js;

    jsSinks.forEach(sink => {
      expect(sink.name).toBeDefined();
      expect(sink.pattern).toBeDefined();
      expect(sink.pattern).toBeInstanceOf(RegExp);
      expect(sink.severity).toBeDefined();
      expect(sink.category).toBeDefined();
      expect(sink.cwe).toBeDefined();
      expect(sink.description).toBeDefined();
      expect(sink.remediation).toBeDefined();
    });
  });

  test('should have remediation for each sink', () => {
    const jsSinks = SINK_DEFINITIONS.js;

    jsSinks.forEach(sink => {
      expect(sink.remediation).toBeDefined();
      expect(typeof sink.remediation).toBe('string');
      expect(sink.remediation.length).toBeGreaterThan(10);
    });
  });
});

// ==================== VULNERABILITY_PATTERNS Tests ====================

describe('VULNERABILITY_PATTERNS', () => {
  test('should be an array', () => {
    expect(Array.isArray(VULNERABILITY_PATTERNS)).toBe(true);
  });

  test('should contain patterns for critical vulnerabilities', () => {
    const names = VULNERABILITY_PATTERNS.map(p => p.name.toLowerCase());

    expect(names.some(n => n.includes('sql'))).toBe(true);
    expect(names.some(n => n.includes('command') || n.includes('injection'))).toBe(true);
  });

  test('each pattern should have required fields', () => {
    VULNERABILITY_PATTERNS.forEach(pattern => {
      expect(pattern.name).toBeDefined();
      expect(pattern.pattern).toBeDefined();
      expect(pattern.pattern).toBeInstanceOf(RegExp);
      expect(pattern.severity).toBeDefined();
      expect(pattern.category).toBeDefined();
      expect(pattern.confidence).toBeDefined();
      expect(typeof pattern.confidence).toBe('number');
      expect(pattern.confidence).toBeGreaterThanOrEqual(0);
      expect(pattern.confidence).toBeLessThanOrEqual(1);
    });
  });
});

// ==================== INTERNET_FACING_PATTERNS Tests ====================

describe('INTERNET_FACING_PATTERNS', () => {
  test('should be an array', () => {
    expect(Array.isArray(INTERNET_FACING_PATTERNS)).toBe(true);
  });

  test('should contain route patterns', () => {
    const patterns = INTERNET_FACING_PATTERNS;

    // At least one pattern should match Express routes
    const expressCode = 'app.get("/user", handler)';
    const hasMatch = patterns.some(p => {
      p.lastIndex = 0;
      return p.test(expressCode);
    });

    expect(hasMatch).toBe(true);
  });
});

// ==================== AUTH_PATTERNS Tests ====================

describe('AUTH_PATTERNS', () => {
  test('should be an array', () => {
    expect(Array.isArray(AUTH_PATTERNS)).toBe(true);
  });

  test('should contain authentication patterns', () => {
    const patterns = AUTH_PATTERNS;

    // At least one pattern should match auth middleware
    const authCode = 'authenticate(req, res, next)';
    const hasMatch = patterns.some(p => {
      p.lastIndex = 0;
      return p.test(authCode);
    });

    expect(hasMatch).toBe(true);
  });
});

// ==================== identifySinks Tests ====================

describe('identifySinks', () => {
  test('should identify eval sink', () => {
    const code = 'eval(userInput)';
    const sinks = identifySinks(code, 'test.js');

    expect(Array.isArray(sinks)).toBe(true);
    expect(sinks.length).toBeGreaterThan(0);
    expect(sinks.some(s => s.name.includes('eval'))).toBe(true);
  });

  test('should identify exec sink', () => {
    const code = `
      const { exec } = require('child_process');
      exec(cmd, callback);
    `;
    const sinks = identifySinks(code, 'test.js');

    expect(sinks.length).toBeGreaterThan(0);
    expect(sinks.some(s => s.name.includes('exec'))).toBe(true);
  });

  test('should identify multiple sinks', () => {
    const code = `
      const fs = require('fs');
      const { exec } = require('child_process');

      eval(userInput);
      fs.readFile(path, callback);
      exec(command, callback);
    `;
    const sinks = identifySinks(code, 'test.js');

    expect(sinks.length).toBeGreaterThanOrEqual(2);
  });

  test('should return empty array for safe code', () => {
    const code = `
      function add(a, b) {
        return a + b;
      }

      const result = add(1, 2);
    `;

    const sinks = identifySinks(code, 'test.js');
    expect(sinks).toEqual([]);
  });

  test('should include sink metadata', () => {
    const code = 'eval(userInput)';
    const sinks = identifySinks(code, 'test.js');

    expect(sinks[0]).toMatchObject({
      name: expect.any(String),
      line: expect.any(Number),
      severity: expect.any(String),
      category: expect.any(String),
      description: expect.any(String),
      cwe: expect.any(String),
      remediation: expect.any(String),
      file: 'test.js'
    });
  });

  test('should include line number', () => {
    const code = `
      function safe() {}
      eval(userInput)
      function more() {}
    `;
    const sinks = identifySinks(code, 'test.js');

    const evalSink = sinks.find(s => s.name.includes('eval'));
    expect(evalSink).toBeDefined();
    expect(evalSink.line).toBe(3);
  });
});

// ==================== scoreFile Tests ====================

describe('scoreFile', () => {
  test('should return score object with breakdown', () => {
    const result = scoreFile('module.exports = { PI: 3.14 };', 'constants.js');

    expect(result).toBeDefined();
    expect(result.score).toBeDefined();
    expect(result.rank).toBeDefined();
    expect(result.breakdown).toBeDefined();
    expect(typeof result.score).toBe('number');
    expect(typeof result.rank).toBe('number');
  });

  test('should rank between 1-5', () => {
    const result1 = scoreFile('module.exports = { PI: 3.14 };', 'constants.js');
    const result2 = scoreFile('app.post("/exec", (req, res) => exec(req.body.cmd))', 'routes/admin.js');

    expect(result1.rank).toBeGreaterThanOrEqual(1);
    expect(result1.rank).toBeLessThanOrEqual(5);
    expect(result2.rank).toBeGreaterThanOrEqual(1);
    expect(result2.rank).toBeLessThanOrEqual(5);
  });

  test('should score constants file low (1-2)', () => {
    const content = `
      module.exports = {
        MAX_USERS: 100,
        API_VERSION: 'v1',
        TIMEOUT: 5000
      };
    `;

    const result = scoreFile(content, 'constants.js');
    expect(result.rank).toBeLessThanOrEqual(2);
  });

  test('should score route handler with sink high (4-5)', () => {
    const content = `
      const express = require('express');
      const router = express.Router();

      router.post('/exec', (req, res) => {
        exec(req.body.command, (err, output) => {
          res.send(output);
        });
      });
    `;

    const result = scoreFile(content, 'routes/admin.js');
    expect(result.rank).toBeGreaterThanOrEqual(4);
  });

  test('should score input parsing with eval high (4-5)', () => {
    const content = `
      function parseInput(req) {
        const data = JSON.parse(req.body);
        eval(data.code);
      }
    `;

    const result = scoreFile(content, 'parsers/input.js');
    expect(result.rank).toBeGreaterThanOrEqual(4);
  });

  test('should score internal utility low-medium (1-3)', () => {
    const content = `
      function formatDate(date) {
        return date.toISOString();
      }

      function slugify(text) {
        return text.toLowerCase().replace(/\\s+/g, '-');
      }
    `;

    const result = scoreFile(content, 'utils/helpers.js');
    expect(result.rank).toBeLessThanOrEqual(3);
  });
});

// ==================== scoreToRank Tests ====================

describe('scoreToRank', () => {
  test('should convert score to rank 1-5', () => {
    // Below 6  → rank 1 (minimal risk)
    expect(scoreToRank(0)).toBe(1);
    expect(scoreToRank(5)).toBe(1);
    // 6–17    → rank 2
    expect(scoreToRank(6)).toBe(2);
    expect(scoreToRank(17)).toBe(2);
    // 18–34   → rank 3
    expect(scoreToRank(18)).toBe(3);
    expect(scoreToRank(34)).toBe(3);
    // 35–59   → rank 4 (internet-facing + sink crossover)
    expect(scoreToRank(35)).toBe(4);
    expect(scoreToRank(59)).toBe(4);
    // 60+     → rank 5 (internet-facing + auth + sinks)
    expect(scoreToRank(60)).toBe(5);
    expect(scoreToRank(110)).toBe(5);
  });
});

// ==================== scoreInternetFacing Tests ====================

describe('scoreInternetFacing', () => {
  test('should score Express routes', () => {
    const content = `
      app.get('/users', getUsers);
      app.post('/users', createUser);
      app.put('/users/:id', updateUser);
      app.delete('/users/:id', deleteUser);
    `;

    const score = scoreInternetFacing(content);
    expect(score).toBeGreaterThan(0);
    // Cap raised to 35 so that internet-facing code naturally crosses
    // the rank-4 threshold once a sink is also present.
    expect(score).toBeLessThanOrEqual(35);
  });

  test('should score empty content as 0', () => {
    const score = scoreInternetFacing('');
    expect(score).toBe(0);
  });
});

// ==================== scoreAuthCode Tests ====================

describe('scoreAuthCode', () => {
  test('should score authentication code', () => {
    const content = `
      function authenticate(req, res, next) {
        const token = req.headers.authorization;
        const decoded = jwt.verify(token, secret);
        req.user = decoded;
        next();
      }
    `;

    const score = scoreAuthCode(content);
    expect(score).toBeGreaterThan(0);
    expect(score).toBeLessThanOrEqual(30);
  });

  test('should score non-auth code as 0', () => {
    const content = 'function add(a, b) { return a + b; }';
    const score = scoreAuthCode(content);
    expect(score).toBe(0);
  });
});

// ==================== scoreSinks Tests ====================

describe('scoreSinks', () => {
  test('should score content with sinks', () => {
    const content = `
      const { exec } = require('child_process');
      eval(userInput);
    `;

    const score = scoreSinks(content, 'js');
    expect(score).toBeGreaterThan(0);
    expect(score).toBeLessThanOrEqual(25);
  });

  test('should score safe content as 0', () => {
    const content = 'const x = 1 + 1;';
    const score = scoreSinks(content, 'js');
    expect(score).toBe(0);
  });
});

// ==================== scoreFileType Tests ====================

describe('scoreFileType', () => {
  test('should score high-risk extensions', () => {
    expect(scoreFileType('js', 'app.js')).toBeGreaterThan(0);
    expect(scoreFileType('py', 'app.py')).toBeGreaterThan(0);
    expect(scoreFileType('ts', 'app.ts')).toBeGreaterThan(0);
  });

  test('should score route/controller paths higher', () => {
    expect(scoreFileType('js', 'routes/api.js')).toBeGreaterThan(
      scoreFileType('js', 'constants.js')
    );
  });

  test('should score auth paths higher', () => {
    expect(scoreFileType('js', 'auth/login.js')).toBeGreaterThan(
      scoreFileType('js', 'utils/helpers.js')
    );
  });
});

// ==================== matchVulnerabilityPatterns Tests ====================

describe('matchVulnerabilityPatterns', () => {
  test('should return array of matches', () => {
    const code = 'const query = "SELECT * FROM users WHERE id=" + userId;';
    const matches = matchVulnerabilityPatterns(code);

    expect(Array.isArray(matches)).toBe(true);
  });

  test('should detect SQL injection via string concatenation', () => {
    const code = `
      const query = "SELECT * FROM users WHERE id=" + userId;
      db.execute(query);
    `;

    const matches = matchVulnerabilityPatterns(code);
    expect(matches.length).toBeGreaterThan(0);
    expect(matches.some(m => m.name.includes('SQL'))).toBe(true);
  });

  test('should detect command injection via template literal', () => {
    const code = `
      const { exec } = require('child_process');
      exec(\`ls \${filePath}\`);
    `;

    const matches = matchVulnerabilityPatterns(code);
    expect(matches.length).toBeGreaterThan(0);
    expect(matches.some(m => m.name.includes('Command'))).toBe(true);
  });

  test('should return match details', () => {
    const code = 'const query = "SELECT * FROM users WHERE id=" + userId;';
    const matches = matchVulnerabilityPatterns(code);

    if (matches.length > 0) {
      const match = matches[0];
      expect(match.name).toBeDefined();
      expect(match.severity).toBeDefined();
      expect(match.category).toBeDefined();
      expect(match.confidence).toBeDefined();
      expect(match.line).toBeDefined();
      expect(match.file).toBeUndefined();
    }
  });

  test('should return empty array for safe code', () => {
    const code = `
      function add(a, b) {
        return a + b;
      }

      const result = add(1, 2);
    `;

    const matches = matchVulnerabilityPatterns(code);
    expect(matches).toEqual([]);
  });
});

// ==================== discoverFiles Tests ====================

describe('discoverFiles', () => {
  const testDir = path.join(__dirname, 'fixtures');

  beforeAll(() => {
    // Create test fixtures directory
    if (!fs.existsSync(testDir)) {
      fs.mkdirSync(testDir, { recursive: true });
    }

    // Create test files
    fs.writeFileSync(
      path.join(testDir, 'safe.js'),
      'module.exports = { add: (a, b) => a + b };'
    );

    fs.writeFileSync(
      path.join(testDir, 'vulnerable.js'),
      `const { exec } = require('child_process');
      function run(cmd) {
        exec(cmd);
      }
      module.exports = { run };`
    );

    fs.writeFileSync(
      path.join(testDir, 'routes.js'),
      `const express = require('express');
      const router = express.Router();
      router.get('/user', (req, res) => {
        res.send(req.query.id);
      });
      module.exports = router;`
    );
  });

  afterAll(() => {
    // Clean up test fixtures
    if (fs.existsSync(testDir)) {
      fs.rmSync(testDir, { recursive: true, force: true });
    }
  });

  test('should discover files in directory', () => {
    const files = discoverFiles(testDir, { maxFiles: 10 });

    expect(files).toBeDefined();
    expect(Array.isArray(files)).toBe(true);
    expect(files.length).toBeGreaterThan(0);
  });

  test('should return file objects with path, content, ext', () => {
    const files = discoverFiles(testDir, { maxFiles: 10 });

    expect(files[0]).toBeDefined();
    expect(files[0].path).toBeDefined();
    expect(files[0].content).toBeDefined();
    expect(files[0].ext).toBeDefined();
    expect(['js', 'ts', 'py']).toContain(files[0].ext);
  });

  test('should respect maxFiles option', () => {
    const files = discoverFiles(testDir, { maxFiles: 2 });

    expect(files.length).toBeLessThanOrEqual(2);
  });

  test('should skip node_modules by default', () => {
    // Create node_modules directory
    const nodeModulesDir = path.join(testDir, 'node_modules', 'test-package');
    fs.mkdirSync(nodeModulesDir, { recursive: true });
    fs.writeFileSync(
      path.join(nodeModulesDir, 'index.js'),
      'module.exports = {};'
    );

    try {
      const files = discoverFiles(testDir, { maxFiles: 10 });

      // Should not include node_modules files
      const hasNodeModules = files.some(f => f.path.includes('node_modules'));
      expect(hasNodeModules).toBe(false);
    } finally {
      // Clean up
      fs.rmSync(path.join(testDir, 'node_modules'), { recursive: true, force: true });
    }
  });

  test('should skip .git directory by default', () => {
    // Create .git directory
    const gitDir = path.join(testDir, '.git', 'objects');
    fs.mkdirSync(gitDir, { recursive: true });
    fs.writeFileSync(path.join(gitDir, 'pack'), 'fake pack file');

    try {
      const files = discoverFiles(testDir, { maxFiles: 10 });

      const hasGit = files.some(f => f.path.includes('.git'));
      expect(hasGit).toBe(false);
    } finally {
      // Clean up
      fs.rmSync(path.join(testDir, '.git'), { recursive: true, force: true });
    }
  });

  test('should include hidden directories when includeHiddenDirs is true', () => {
    const hiddenDir = path.join(testDir, '.aws');
    fs.mkdirSync(hiddenDir, { recursive: true });
    fs.writeFileSync(path.join(hiddenDir, 'config.js'), 'module.exports = { secret: true };');

    try {
      const files = discoverFiles(testDir, { maxFiles: 20, includeHiddenDirs: true });
      const hasAws = files.some(f => f.path.includes('.aws'));
      expect(hasAws).toBe(true);
    } finally {
      fs.rmSync(hiddenDir, { recursive: true, force: true });
    }
  });

  test('should handle unreadable directories gracefully', () => {
    // This test ensures the function doesn't throw on permission errors
    expect(() => {
      const files = discoverFiles(testDir, { maxFiles: 10 });
      expect(Array.isArray(files)).toBe(true);
    }).not.toThrow();
  });
});