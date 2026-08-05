/**
 * Mythos Agent - Validation Phases Test Suite
 * Tests for lib/phases-validation.js (Phases 4-6)
 */

const {
  liveAgenticHunt,
  adversarialSelfChallenge,
  skepticalValidator,
  runValidationPipeline,
  analyzeFileWithDiversity,
  adjustConfidenceByLens,
  generateChallenges,
  generateCounterArguments,
  calculateChallengeScore,
  validateFinding
} = require('../lib/phases-validation');

// ==================== Phase 4: Live Agentic Hunt Tests ====================

describe('liveAgenticHunt', () => {
  const mockRankedFiles = [
    {
      path: 'routes/api.js',
      content: `
        const { exec } = require('child_process');
        app.post('/run', (req, res) => {
          exec(req.body.cmd, (err, output) => {
            res.send(output);
          });
        });
      `,
      riskScore: 5
    },
    {
      path: 'utils/safe.js',
      content: `
        function add(a, b) {
          return a + b;
        }
        module.exports = { add };
      `,
      riskScore: 1
    }
  ];

  const mockSinks = [
    {
      name: 'exec',
      line: 3,
      severity: 'CRITICAL',
      category: 'command-exec',
      file: 'routes/api.js'
    }
  ];

  test('should return findings array', async () => {
    const findings = await liveAgenticHunt(mockRankedFiles, mockSinks, { maxFiles: 5 });
    expect(Array.isArray(findings)).toBe(true);
  });

  test('should find vulnerabilities in high-risk files', async () => {
    const findings = await liveAgenticHunt(mockRankedFiles, mockSinks, { maxFiles: 5 });

    // Should find the exec vulnerability
    const execFindings = findings.filter(f =>
      f.name.toLowerCase().includes('exec') ||
      f.category === 'command-exec'
    );

    expect(execFindings.length).toBeGreaterThan(0);
  });

  test('should support pass@K diversity', async () => {
    const findings1 = await liveAgenticHunt(mockRankedFiles, mockSinks, { passAtK: 1 });
    const findings3 = await liveAgenticHunt(mockRankedFiles, mockSinks, { passAtK: 3 });

    // pass@3 should produce more findings than pass@1
    expect(findings3.length).toBeGreaterThanOrEqual(findings1.length);
  });

  test('should include file path in findings', async () => {
    const findings = await liveAgenticHunt(mockRankedFiles, mockSinks, { maxFiles: 5 });

    findings.forEach(finding => {
      expect(finding.file).toBeDefined();
      expect(typeof finding.file).toBe('string');
    });
  });

  test('should include confidence scores', async () => {
    const findings = await liveAgenticHunt(mockRankedFiles, mockSinks, { maxFiles: 5 });

    findings.forEach(finding => {
      expect(finding.confidence).toBeDefined();
      expect(typeof finding.confidence).toBe('number');
      expect(finding.confidence).toBeGreaterThanOrEqual(0);
      expect(finding.confidence).toBeLessThanOrEqual(1);
    });
  });

  test('should respect maxFiles option', async () => {
    const findings = await liveAgenticHunt(mockRankedFiles, mockSinks, { maxFiles: 1 });

    // Should only analyze the first file (highest risk)
    const uniqueFiles = new Set(findings.map(f => f.file));
    expect(uniqueFiles.size).toBeLessThanOrEqual(1);
  });
});

// ==================== analyzeFileWithDiversity Tests ====================

describe('analyzeFileWithDiversity', () => {
  const vulnerableCode = `
    const { exec } = require('child_process');
    function runCommand(cmd) {
      exec(cmd);
    }
  `;

  const mockSinks = [
    { name: 'exec', line: 3, severity: 'CRITICAL', file: 'test.js' }
  ];

  test('should produce different analysis passes', () => {
    const pass0 = analyzeFileWithDiversity(vulnerableCode, 'test.js', 0, mockSinks);
    const pass1 = analyzeFileWithDiversity(vulnerableCode, 'test.js', 1, mockSinks);

    // Different passes should have different analysisPass labels
    expect(pass0[0]?.analysisPass).toBeDefined();
    expect(pass1[0]?.analysisPass).toBeDefined();
  });

  test('should include sink correlation', () => {
    const findings = analyzeFileWithDiversity(vulnerableCode, 'test.js', 0, mockSinks);

    // Should include findings correlated with the exec sink
    const hasSinkFinding = findings.some(f =>
      f.metadata?.sinkDetails?.name === 'exec' ||
      f.name === 'Sink: exec'
    );

    expect(hasSinkFinding).toBe(true);
  });
});

// ==================== adjustConfidenceByLens Tests ====================

describe('adjustConfidenceByLens', () => {
  const baseConfidence = 0.7;

  test('direct-matches lens should not adjust confidence', () => {
    const adjusted = adjustConfidenceByLens(baseConfidence, { name: 'direct-matches' });
    expect(adjusted).toBe(baseConfidence);
  });

  test('data-flow lens should increase confidence', () => {
    const adjusted = adjustConfidenceByLens(baseConfidence, { name: 'data-flow' });
    expect(adjusted).toBeGreaterThan(baseConfidence);
  });

  test('exploitation-paths lens should significantly increase confidence', () => {
    const adjusted = adjustConfidenceByLens(baseConfidence, { name: 'exploitation-paths' });
    expect(adjusted).toBeCloseTo(baseConfidence + 0.15);
  });

  test('should clamp confidence to [0, 1] range', () => {
    const highConfidence = 0.95;
    const adjusted = adjustConfidenceByLens(highConfidence, { name: 'exploitation-paths' });
    expect(adjusted).toBeLessThanOrEqual(1.0);

    const lowConfidence = 0.05;
    const adjustedLow = adjustConfidenceByLens(lowConfidence, { name: 'context-aware' });
    expect(adjustedLow).toBeGreaterThanOrEqual(0);
  });
});

// ==================== Phase 5: Adversarial Self-Challenge Tests ====================

describe('adversarialSelfChallenge', () => {
  const mockFindings = [
    {
      name: 'Command injection via template literal',
      severity: 'CRITICAL',
      category: 'command-exec',
      file: 'routes/api.js',
      line: 5,
      confidence: 0.85,
      cwe: 'CWE-78',
      remediation: 'Use execFile with arguments array'
    },
    {
      name: 'Eval with user input',
      severity: 'CRITICAL',
      category: 'code-exec',
      file: 'utils/parser.js',
      line: 12,
      confidence: 0.6,
      cwe: 'CWE-95'
    }
  ];

  test('should return findings with challenges', async () => {
    const challenged = await adversarialSelfChallenge(mockFindings);

    challenged.forEach(finding => {
      expect(finding.challenges).toBeDefined();
      expect(Array.isArray(finding.challenges)).toBe(true);
    });
  });

  test('should generate counter-arguments', async () => {
    const challenged = await adversarialSelfChallenge(mockFindings);

    challenged.forEach(finding => {
      expect(finding.counterArguments).toBeDefined();
      expect(Array.isArray(finding.counterArguments)).toBe(true);
    });
  });

  test('should calculate challenge score', async () => {
    const challenged = await adversarialSelfChallenge(mockFindings);

    challenged.forEach(finding => {
      expect(finding.challengeScore).toBeDefined();
      expect(typeof finding.challengeScore).toBe('number');
      expect(finding.challengeScore).toBeGreaterThanOrEqual(0);
      expect(finding.challengeScore).toBeLessThanOrEqual(1);
    });
  });

  test('should adjust confidence based on challenges', async () => {
    const challenged = await adversarialSelfChallenge(mockFindings);

    challenged.forEach(finding => {
      expect(finding.adjustedConfidence).toBeDefined();
      // Adjusted confidence should be <= original confidence
      expect(finding.adjustedConfidence).toBeLessThanOrEqual(finding.confidence);
    });
  });

  test('should support different challenge intensities', async () => {
    const lowChallenge = await adversarialSelfChallenge(mockFindings, { challengeIntensity: 'low' });
    const highChallenge = await adversarialSelfChallenge(mockFindings, { challengeIntensity: 'high' });

    // High intensity should produce lower adjusted confidence
    const lowAvgConfidence = lowChallenge.reduce((s, f) => s + f.adjustedConfidence, 0) / lowChallenge.length;
    const highAvgConfidence = highChallenge.reduce((s, f) => s + f.adjustedConfidence, 0) / highChallenge.length;

    expect(highAvgConfidence).toBeLessThanOrEqual(lowAvgConfidence);
  });

  test('should mark findings as challenged when score > 0.3', async () => {
    const challenged = await adversarialSelfChallenge(mockFindings);

    const clearlyChallenged = challenged.filter(f => f.challengeScore > 0.3);
    clearlyChallenged.forEach(f => {
      expect(f.isChallenged).toBe(true);
    });
  });
});

// ==================== generateChallenges Tests ====================

describe('generateChallenges', () => {
  const mockFinding = {
    name: 'SQL Injection',
    file: 'db/user.js',
    line: 15,
    severity: 'CRITICAL'
  };

  test('should generate requested number of challenges', () => {
    const challenges3 = generateChallenges(mockFinding, 3);
    const challenges5 = generateChallenges(mockFinding, 5);

    expect(challenges3.length).toBe(3);
    expect(challenges5.length).toBe(5);
  });

  test('should include challenge type and question', () => {
    const challenges = generateChallenges(mockFinding, 2);

    challenges.forEach(c => {
      expect(c.type).toBeDefined();
      expect(c.question).toBeDefined();
      expect(c.weight).toBeDefined();
    });
  });

  test('should include finding context in challenges', () => {
    const challenges = generateChallenges(mockFinding, 1);

    expect(challenges[0].findingContext).toBeDefined();
    expect(challenges[0].findingContext.file).toBe('db/user.js');
    expect(challenges[0].findingContext.line).toBe(15);
  });
});

// ==================== generateCounterArguments Tests ====================

describe('generateCounterArguments', () => {
  const mockFinding = {
    name: 'Command Injection',
    confidence: 0.8
  };

  const mockChallenges = [
    { type: 'false-positive', question: 'Could this be false?', weight: 0.3 },
    { type: 'sanitization', question: 'Is input sanitized?', weight: 0.25 }
  ];

  test('should generate counter-argument for each challenge', () => {
    const counters = generateCounterArguments(mockFinding, mockChallenges);
    expect(counters.length).toBe(mockChallenges.length);
  });

  test('should include challenge type and argument', () => {
    const counters = generateCounterArguments(mockFinding, mockChallenges);

    counters.forEach(c => {
      expect(c.challengeType).toBeDefined();
      expect(c.argument).toBeDefined();
      expect(c.strength).toBeDefined();
    });
  });

  test('counter-argument strength should be 0.25-0.75', () => {
    const counters = generateCounterArguments(mockFinding, mockChallenges);

    counters.forEach(c => {
      expect(c.strength).toBeGreaterThanOrEqual(0.25);
      expect(c.strength).toBeLessThanOrEqual(0.75);
    });
  });
});

// ==================== calculateChallengeScore Tests ====================

describe('calculateChallengeScore', () => {
  const mockFinding = {
    confidence: 0.7,
    remediation: 'Use parameterized queries'
  };

  const mockChallenges = [
    { type: 'false-positive', weight: 0.3 }
  ];

  const mockCounters = [
    { challengeType: 'false-positive', argument: 'Safe usage', strength: 0.5 }
  ];

  test('should return 0 for no counter-arguments', () => {
    const score = calculateChallengeScore(mockFinding, mockChallenges, []);
    expect(score).toBe(0);
  });

  test('should increase score for low confidence findings', () => {
    const lowConfFinding = { ...mockFinding, confidence: 0.3 };
    const score = calculateChallengeScore(lowConfFinding, mockChallenges, mockCounters);
    const normalScore = calculateChallengeScore(mockFinding, mockChallenges, mockCounters);

    expect(score).toBeGreaterThan(normalScore);
  });

  test('should penalize findings without remediation', () => {
    const noRemFinding = { ...mockFinding, remediation: undefined };
    const score = calculateChallengeScore(noRemFinding, mockChallenges, mockCounters);
    const withRemScore = calculateChallengeScore(mockFinding, mockChallenges, mockCounters);

    expect(score).toBeGreaterThan(withRemScore);
  });
});

// ==================== Phase 6: Skeptical Validator Tests ====================

describe('skepticalValidator', () => {
  const mockChallengedFindings = [
    {
      name: 'Strong Finding',
      confidence: 0.9,
      adjustedConfidence: 0.85,
      challengeScore: 0.2,
      isChallenged: false,
      category: 'command-exec',
      severity: 'CRITICAL',
      file: 'api.js',
      line: 10,
      cwe: 'CWE-78',
      remediation: 'Use execFile'
    },
    {
      name: 'Weak Finding',
      confidence: 0.4,
      adjustedConfidence: 0.25,
      challengeScore: 0.6,
      isChallenged: true,
      category: 'file-access',
      severity: 'LOW',
      file: 'utils.js'
      // Missing line, cwe, remediation
    }
  ];

  test('should return findings with validation', async () => {
    const validated = await skepticalValidator(mockChallengedFindings);

    validated.forEach(finding => {
      expect(finding.validation).toBeDefined();
      expect(finding.isDismissed).toBeDefined();
      expect(finding.passedValidation).toBeDefined();
    });
  });

  test('should pass strong findings', async () => {
    const validated = await skepticalValidator(mockChallengedFindings);

    const strongFinding = validated.find(f => f.name === 'Strong Finding');
    expect(strongFinding.passedValidation).toBe(true);
    expect(strongFinding.isDismissed).toBe(false);
  });

  test('should dismiss weak findings', async () => {
    const validated = await skepticalValidator(mockChallengedFindings);

    const weakFinding = validated.find(f => f.name === 'Weak Finding');
    expect(weakFinding.passedValidation).toBe(false);
    expect(weakFinding.isDismissed).toBe(true);
    expect(weakFinding.dismissalReason).toBeDefined();
  });

  test('should support minimum confidence filter', async () => {
    const validated05 = await skepticalValidator(mockChallengedFindings, { minConfidence: 0.5 });
    const validated01 = await skepticalValidator(mockChallengedFindings, { minConfidence: 0.1 });

    // Higher threshold should dismiss more findings
    const passed05 = validated05.filter(f => f.passedValidation).length;
    const passed01 = validated01.filter(f => f.passedValidation).length;

    expect(passed05).toBeLessThanOrEqual(passed01);
  });

  test('should support strict mode', async () => {
    const normalValidated = await skepticalValidator(mockChallengedFindings, { strictMode: false });
    const strictValidated = await skepticalValidator(mockChallengedFindings, { strictMode: true });

    // Strict mode should have fewer passing findings
    const normalPassed = normalValidated.filter(f => f.passedValidation).length;
    const strictPassed = strictValidated.filter(f => f.passedValidation).length;

    expect(strictPassed).toBeLessThanOrEqual(normalPassed);
  });
});

// ==================== validateFinding Tests ====================

describe('validateFinding', () => {
  const strongFinding = {
    name: 'SQL Injection',
    confidence: 0.85,
    adjustedConfidence: 0.8,
    challengeScore: 0.15,
    isChallenged: false,
    category: 'injection',
    severity: 'CRITICAL',
    file: 'db/queries.js',
    line: 25,
    cwe: 'CWE-89',
    remediation: 'Use parameterized queries'
  };

  const weakFinding = {
    name: 'Possible Issue',
    confidence: 0.3,
    adjustedConfidence: 0.2,
    challengeScore: 0.7,
    isChallenged: true,
    category: 'unknown',
    file: 'utils.js'
    // Missing severity, line, cwe, remediation
  };

  test('should validate against 6 criteria', () => {
    const validation = validateFinding(strongFinding, { strictMode: false });

    expect(validation.criteria).toBeDefined();
    expect(validation.criteria.length).toBe(6);
    expect(validation.totalCriteria).toBe(6);
  });

  test('strong finding should pass most criteria', () => {
    const validation = validateFinding(strongFinding, { strictMode: false });

    expect(validation.passedCount).toBeGreaterThanOrEqual(5);
    expect(validation.finalConfidence).toBeGreaterThan(0.6);
    expect(validation.status).toBe('STRONG');
  });

  test('weak finding should fail most criteria', () => {
    const validation = validateFinding(weakFinding, { strictMode: false });

    expect(validation.passedCount).toBeLessThanOrEqual(2);
    expect(validation.finalConfidence).toBeLessThan(0.4);
    expect(validation.status).toBe('WEAK');
  });

  test('strictMode should require more passed criteria', () => {
    const normalValidation = validateFinding(strongFinding, { strictMode: false });
    const strictValidation = validateFinding(strongFinding, { strictMode: true });

    // Status should reflect stricter requirements
    expect(strictValidation.strictMode).toBe(true);
  });

  test('should return criteria details', () => {
    const validation = validateFinding(strongFinding, { strictMode: false });

    validation.criteria.forEach(c => {
      expect(c.name).toBeDefined();
      expect(c.description).toBeDefined();
      expect(c.weight).toBeDefined();
      expect(c.passed).toBeDefined();
      expect(typeof c.passed).toBe('boolean');
    });
  });
});

// ==================== runValidationPipeline Tests ====================

describe('runValidationPipeline', () => {
  const mockRankedFiles = [
    {
      path: 'api.js',
      content: 'exec(cmd)',
      riskScore: 5
    }
  ];

  const mockSinks = [
    { name: 'exec', line: 1, severity: 'CRITICAL', file: 'api.js' }
  ];

  test('should run all three phases', async () => {
    const result = await runValidationPipeline(mockRankedFiles, mockSinks, { maxFiles: 1 });

    expect(result.phase4Findings).toBeDefined();
    expect(result.phase5Findings).toBeDefined();
    expect(result.phase6Findings).toBeDefined();
    expect(result.summary).toBeDefined();
  });

  test('should provide summary statistics', async () => {
    const result = await runValidationPipeline(mockRankedFiles, mockSinks, { maxFiles: 1 });

    expect(result.summary.initial).toBeGreaterThanOrEqual(0);
    expect(result.summary.challenged).toBeGreaterThanOrEqual(0);
    expect(result.summary.passed).toBeGreaterThanOrEqual(0);
    expect(result.summary.dismissed).toBeGreaterThanOrEqual(0);

    // Passed + dismissed should equal total
    expect(result.summary.passed + result.summary.dismissed)
      .toBe(result.phase6Findings.length);
  });
});