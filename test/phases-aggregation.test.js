/**
 * Mythos Agent - Aggregation Phases Test Suite
 * Tests for lib/phases-aggregation.js (Phases 7-9)
 */

const {
  aggregateFindings,
  liveExecValidator,
  dismissalMemoryTracking,
  runAggregationPipeline,
  generateFindingSignature,
  deduplicateFindings,
  rankFindings,
  validateFindingSafely,
  loadMemory,
  persistMemory,
  calculateMemoryStats,
  applyMemoryToFindings
} = require('../lib/phases-aggregation');

const fs = require('fs');
const path = require('path');

// ==================== Phase 7: Aggregation Tests ====================

describe('aggregateFindings', () => {
  const mockFindings = [
    {
      name: 'Command Injection',
      severity: 'CRITICAL',
      confidence: 0.9,
      file: 'api.js',
      line: 10,
      category: 'command-exec',
      isDismissed: false
    },
    {
      name: 'SQL Injection',
      severity: 'HIGH',
      confidence: 0.85,
      file: 'db/queries.js',
      line: 25,
      category: 'injection',
      isDismissed: false
    },
    {
      name: 'Weak Finding',
      severity: 'LOW',
      confidence: 0.3,
      file: 'utils.js',
      line: 5,
      category: 'file-access',
      isDismissed: true
    },
    // Duplicate of first finding (same signature)
    {
      name: 'Command Injection',
      severity: 'CRITICAL',
      confidence: 0.8,
      file: 'api.js',
      line: 10,
      category: 'command-exec',
      isDismissed: false
    }
  ];

  test('should filter out dismissed findings by default', () => {
    const result = aggregateFindings(mockFindings);
    const dismissedIncluded = result.some(f => f.isDismissed);
    expect(dismissedIncluded).toBe(false);
  });

  test('should include dismissed findings when requested', () => {
    const result = aggregateFindings(mockFindings, { includeDismissed: true });
    // Note: deduplication still applies, so duplicate is removed (4 -> 3)
    expect(result.length).toBe(3);
  });

  test('should deduplicate findings', () => {
    const result = aggregateFindings(mockFindings);
    // Should have 2 unique findings (one duplicate removed)
    expect(result.length).toBeLessThan(mockFindings.filter(f => !f.isDismissed).length);
  });

  test('should rank by severity by default', () => {
    const result = aggregateFindings(mockFindings);

    const severityOrder = {
      'CRITICAL': 5,
      'HIGH': 4,
      'MEDIUM': 3,
      'LOW': 2,
      'INFO': 1
    };

    for (let i = 1; i < result.length; i++) {
      const prevSeverity = severityOrder[result[i - 1].severity] || 0;
      const currSeverity = severityOrder[result[i].severity] || 0;
      expect(prevSeverity).toBeGreaterThanOrEqual(currSeverity);
    }
  });

  test('should support sorting by confidence', () => {
    const result = aggregateFindings(mockFindings, { sortBy: 'confidence' });

    for (let i = 1; i < result.length; i++) {
      expect(result[i - 1].confidence).toBeGreaterThanOrEqual(result[i].confidence);
    }
  });

  test('should support sorting by file', () => {
    const result = aggregateFindings(mockFindings, { sortBy: 'file' });

    for (let i = 1; i < result.length; i++) {
      expect(result[i - 1].file.localeCompare(result[i].file)).toBeLessThanOrEqual(0);
    }
  });
});

// ==================== generateFindingSignature Tests ====================

describe('generateFindingSignature', () => {
  test('should generate consistent signature', () => {
    const finding = {
      name: 'Test',
      file: 'test.js',
      line: 10,
      category: 'test'
    };

    const sig1 = generateFindingSignature(finding);
    const sig2 = generateFindingSignature(finding);

    expect(sig1).toBe(sig2);
  });

  test('should generate different signatures for different findings', () => {
    const finding1 = { name: 'Test', file: 'test.js', line: 10, category: 'test' };
    const finding2 = { name: 'Test', file: 'test.js', line: 11, category: 'test' };

    const sig1 = generateFindingSignature(finding1);
    const sig2 = generateFindingSignature(finding2);

    expect(sig1).not.toBe(sig2);
  });

  test('should handle missing fields gracefully', () => {
    const finding = { name: 'Test' };
    const signature = generateFindingSignature(finding);

    expect(typeof signature).toBe('string');
    expect(signature.length).toBe(16); // First 16 chars of sha256 hex
  });

  test('should produce hex string', () => {
    const finding = { name: 'Test', file: 'test.js', line: 10, category: 'test' };
    const signature = generateFindingSignature(finding);

    expect(signature).toMatch(/^[0-9a-f]{16}$/);
  });
});

// ==================== deduplicateFindings Tests ====================

describe('deduplicateFindings', () => {
  const duplicateFindings = [
    { name: 'Injection', file: 'api.js', line: 10, category: 'injection', confidence: 0.9 },
    { name: 'Injection', file: 'api.js', line: 10, category: 'injection', confidence: 0.8 },
    { name: 'XSS', file: 'views.js', line: 5, category: 'xss', confidence: 0.7 }
  ];

  test('should remove duplicates with same signature', () => {
    const result = deduplicateFindings(duplicateFindings, 'signature');
    expect(result.length).toBe(2);
  });

  test('should keep higher confidence finding when deduping', () => {
    const result = deduplicateFindings(duplicateFindings, 'signature');
    const injectionFinding = result.find(f => f.name === 'Injection');
    expect(injectionFinding.confidence).toBe(0.9);
  });

  test('should support file-based deduplication', () => {
    const result = deduplicateFindings(duplicateFindings, 'file');
    // api.js has 2 findings, views.js has 1 - should reduce to 2
    expect(result.length).toBe(2);
  });

  test('should support category-based deduplication', () => {
    const findings = [
      { name: 'Injection 1', file: 'api.js', line: 10, category: 'injection', confidence: 0.9 },
      { name: 'Injection 2', file: 'api.js', line: 5, category: 'injection', confidence: 0.8 },
      { name: 'XSS', file: 'views.js', line: 5, category: 'xss', confidence: 0.7 }
    ];

    const result = deduplicateFindings(findings, 'category');
    // Note: category dedup uses file:category key, so same file+category dedups to 1
    expect(result.length).toBe(2); // One per unique file:category combination
  });

  test('should return all findings with dedupeBy=none', () => {
    const result = deduplicateFindings(duplicateFindings, 'none');
    expect(result.length).toBe(duplicateFindings.length);
  });
});

// ==================== rankFindings Tests ====================

describe('rankFindings', () => {
  const findings = [
    { name: 'Low', severity: 'LOW', confidence: 0.9 },
    { name: 'Critical', severity: 'CRITICAL', confidence: 0.7 },
    { name: 'Medium', severity: 'MEDIUM', confidence: 0.8 },
    { name: 'High', severity: 'HIGH', confidence: 0.85 }
  ];

  test('should rank by severity by default', () => {
    const result = rankFindings([...findings], 'severity');
    expect(result[0].severity).toBe('CRITICAL');
    expect(result[result.length - 1].severity).toBe('LOW');
  });

  test('should rank by confidence', () => {
    const result = rankFindings([...findings], 'confidence');
    expect(result[0].confidence).toBe(0.9);
    expect(result[result.length - 1].confidence).toBe(0.7);
  });

  test('should rank by file', () => {
    const filesFindings = [
      { name: 'C', file: 'c.js' },
      { name: 'A', file: 'a.js' },
      { name: 'B', file: 'b.js' }
    ];

    const result = rankFindings(filesFindings, 'file');
    expect(result[0].file).toBe('a.js');
    expect(result[1].file).toBe('b.js');
    expect(result[2].file).toBe('c.js');
  });

  test('should handle missing severity gracefully', () => {
    const findingsWithMissing = [
      { name: 'Known', severity: 'CRITICAL', confidence: 0.8 },
      { name: 'Unknown', confidence: 0.9 } // No severity
    ];

    const result = rankFindings(findingsWithMissing, 'severity');
    expect(result[0].severity).toBe('CRITICAL');
  });
});

// ==================== Phase 8: Live-Exec Validator Tests ====================

describe('liveExecValidator', () => {
  const mockFindings = [
    {
      name: 'Command Injection',
      severity: 'CRITICAL',
      category: 'command-exec',
      file: 'api.js',
      line: 10,
      confidence: 0.9
    },
    {
      name: 'Safe Function',
      severity: 'LOW',
      category: 'utility',
      file: 'utils.js',
      line: 5,
      confidence: 0.5
    }
  ];

  test('should skip execution by default', async () => {
    const result = await liveExecValidator(mockFindings);

    result.forEach(finding => {
      expect(finding.execValidated).toBe(false);
      expect(finding.execStatus).toBe('skipped');
    });
  });

  test('should mark non-executable categories as not-applicable', async () => {
    const result = await liveExecValidator(mockFindings, { skipExec: false, sandboxEnabled: true });

    const utilityFinding = result.find(f => f.category === 'utility');
    expect(utilityFinding.execStatus).toBe('not-applicable');
  });

  test('should require sandbox for execution', async () => {
    const result = await liveExecValidator(mockFindings, { skipExec: false, sandboxEnabled: false });

    const commandFinding = result.find(f => f.category === 'command-exec');
    expect(commandFinding.execStatus).toBe('no-sandbox');
  });

  test('should include exec metadata on all findings', async () => {
    const result = await liveExecValidator(mockFindings);

    result.forEach(finding => {
      expect(finding.execValidated).toBeDefined();
      expect(finding.execStatus).toBeDefined();
      expect(finding.execMessage).toBeDefined();
    });
  });
});

// ==================== validateFindingSafely Tests ====================

describe('validateFindingSafely', () => {
  const commandFinding = {
    name: 'Command Injection',
    category: 'command-exec',
    severity: 'CRITICAL'
  };

  const safeFinding = {
    name: 'Info Disclosure',
    category: 'information',
    severity: 'LOW'
  };

  test('should return not-applicable for non-executable categories', async () => {
    const result = await validateFindingSafely(safeFinding, { sandboxEnabled: true, timeout: 5000 });
    expect(result.execStatus).toBe('not-applicable');
  });

  test('should return no-sandbox when sandbox disabled', async () => {
    const result = await validateFindingSafely(commandFinding, { sandboxEnabled: false, timeout: 5000 });
    expect(result.execStatus).toBe('no-sandbox');
  });

  test('should return not-implemented when sandbox enabled', async () => {
    const result = await validateFindingSafely(commandFinding, { sandboxEnabled: true, timeout: 5000 });
    expect(result.execStatus).toBe('not-implemented');
  });
});

// ==================== Phase 9: Dismissal Memory Tracking Tests ====================

describe('dismissalMemoryTracking', () => {
  const mockFindings = [
    {
      name: 'Confirmed Injection',
      severity: 'CRITICAL',
      category: 'injection',
      file: 'api.js',
      line: 10,
      confidence: 0.9,
      isDismissed: false,
      passedValidation: true
    },
    {
      name: 'Dismissed Finding',
      severity: 'LOW',
      category: 'file-access',
      file: 'utils.js',
      line: 5,
      confidence: 0.3,
      isDismissed: true,
      dismissalReason: 'Confidence below threshold'
    }
  ];

  const tempMemoryPath = path.join(__dirname, 'fixtures', 'test-memory.json');

  beforeEach(() => {
    // Ensure fixtures directory exists
    const fixturesDir = path.join(__dirname, 'fixtures');
    if (!fs.existsSync(fixturesDir)) {
      fs.mkdirSync(fixturesDir, { recursive: true });
    }
  });

  afterEach(() => {
    // Clean up test memory file
    if (fs.existsSync(tempMemoryPath)) {
      fs.unlinkSync(tempMemoryPath);
    }
  });

  test('should track dismissed findings', () => {
    const result = dismissalMemoryTracking(mockFindings);

    expect(result.dismissedCount).toBe(1);
    expect(result.confirmedCount).toBe(1);
  });

  test('should return memory object', () => {
    const result = dismissalMemoryTracking(mockFindings);

    expect(result.memory).toBeDefined();
    expect(result.memory.dismissedPatterns).toBeDefined();
    expect(result.memory.confirmedPatterns).toBeDefined();
  });

  test('should calculate stats', () => {
    const result = dismissalMemoryTracking(mockFindings);

    expect(result.stats).toBeDefined();
    expect(result.stats.totalDismissedPatterns).toBe(1);
    expect(result.stats.totalConfirmedPatterns).toBe(1);
  });

  test('should persist memory to file', () => {
    const result = dismissalMemoryTracking(mockFindings, { persistTo: tempMemoryPath });

    expect(fs.existsSync(tempMemoryPath)).toBe(true);

    const savedData = JSON.parse(fs.readFileSync(tempMemoryPath, 'utf-8'));
    expect(savedData.dismissedPatterns).toBeDefined();
    expect(savedData.confirmedPatterns).toBeDefined();
  });

  test('should load existing memory', () => {
    // First, save some memory
    dismissalMemoryTracking(mockFindings, { persistTo: tempMemoryPath });

    // Then load it
    const result = dismissalMemoryTracking(
      [
        {
          name: 'New Finding',
          severity: 'MEDIUM',
          category: 'test',
          file: 'test.js',
          line: 1,
          confidence: 0.5,
          isDismissed: false,
          passedValidation: true
        }
      ],
      { loadFrom: tempMemoryPath }
    );

    // Should have previous memory plus new finding
    expect(result.stats.totalDismissedPatterns).toBe(1);
  });
});

// ==================== loadMemory Tests ====================

describe('loadMemory', () => {
  const tempMemoryPath = path.join(__dirname, 'fixtures', 'test-load-memory.json');

  afterEach(() => {
    if (fs.existsSync(tempMemoryPath)) {
      fs.unlinkSync(tempMemoryPath);
    }
  });

  test('should return empty memory for non-existent file', () => {
    const memory = loadMemory('/nonexistent/path/memory.json');

    expect(memory.dismissedPatterns.size).toBe(0);
    expect(memory.confirmedPatterns.size).toBe(0);
  });

  test('should return empty memory for null path', () => {
    const memory = loadMemory(null);

    expect(memory.dismissedPatterns.size).toBe(0);
    expect(memory.confirmedPatterns.size).toBe(0);
  });

  test('should load valid memory file', () => {
    // Create a memory file
    const testData = {
      version: 1,
      dismissedPatterns: [
        ['sig1', { finding: { name: 'Test' }, count: 1, reasons: ['test reason'] }]
      ],
      confirmedPatterns: []
    };

    fs.writeFileSync(tempMemoryPath, JSON.stringify(testData));

    const memory = loadMemory(tempMemoryPath);

    expect(memory.dismissedPatterns.size).toBe(1);
    expect(memory.dismissedPatterns.get('sig1')).toBeDefined();
  });
});

// ==================== persistMemory Tests ====================

describe('persistMemory', () => {
  const tempMemoryPath = path.join(__dirname, 'fixtures', 'test-persist-memory.json');

  beforeEach(() => {
    const dir = path.dirname(tempMemoryPath);
    if (!fs.existsSync(dir)) {
      fs.mkdirSync(dir, { recursive: true });
    }
  });

  afterEach(() => {
    if (fs.existsSync(tempMemoryPath)) {
      fs.unlinkSync(tempMemoryPath);
    }
  });

  test('should persist memory to file', () => {
    const memory = {
      dismissedPatterns: new Map([['sig1', { finding: { name: 'Test' } }]]),
      confirmedPatterns: new Map([['sig2', { finding: { name: 'Confirmed' } }]]),
      version: 1,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };

    persistMemory(memory, tempMemoryPath);

    expect(fs.existsSync(tempMemoryPath)).toBe(true);

    const saved = JSON.parse(fs.readFileSync(tempMemoryPath, 'utf-8'));
    expect(saved.dismissedPatterns).toHaveLength(1);
    expect(saved.confirmedPatterns).toHaveLength(1);
  });

  test('should create directory if missing', () => {
    const nestedPath = path.join(__dirname, 'fixtures', 'nested', 'deep', 'memory.json');

    try {
      const memory = {
        dismissedPatterns: new Map(),
        confirmedPatterns: new Map(),
        version: 1,
        createdAt: new Date().toISOString(),
        updatedAt: new Date().toISOString()
      };

      persistMemory(memory, nestedPath);
      expect(fs.existsSync(nestedPath)).toBe(true);
    } finally {
      // Clean up
      if (fs.existsSync(nestedPath)) {
        fs.unlinkSync(nestedPath);
      }
      fs.rmdirSync(path.join(__dirname, 'fixtures', 'nested', 'deep'));
      fs.rmdirSync(path.join(__dirname, 'fixtures', 'nested'));
    }
  });
});

// ==================== calculateMemoryStats Tests ====================

describe('calculateMemoryStats', () => {
  test('should calculate category breakdown', () => {
    const memory = {
      dismissedPatterns: new Map([
        ['sig1', { finding: { category: 'injection' }, count: 1, reasons: [] }],
        ['sig2', { finding: { category: 'injection' }, count: 1, reasons: [] }],
        ['sig3', { finding: { category: 'xss' }, count: 1, reasons: [] }]
      ]),
      confirmedPatterns: new Map([
        ['sig4', { finding: { category: 'command-exec' }, confirmedAt: new Date().toISOString() }]
      ])
    };

    const stats = calculateMemoryStats(memory);

    expect(stats.dismissedByCategory.injection).toBe(2);
    expect(stats.dismissedByCategory.xss).toBe(1);
    expect(stats.confirmedByCategory['command-exec']).toBe(1);
  });

  test('should calculate top dismissal reasons', () => {
    const memory = {
      dismissedPatterns: new Map([
        ['sig1', { finding: {}, count: 1, reasons: ['Low confidence', 'False positive'] }],
        ['sig2', { finding: {}, count: 1, reasons: ['Low confidence'] }]
      ]),
      confirmedPatterns: new Map()
    };

    const stats = calculateMemoryStats(memory);

    expect(stats.topDismissalReasons.length).toBeGreaterThan(0);
    expect(stats.topDismissalReasons[0].reason).toBe('Low confidence');
  });

  test('should calculate average confidence', () => {
    const memory = {
      dismissedPatterns: new Map([
        ['sig1', { finding: { category: 'test' }, confidence: 0.3, reasons: [] }],
        ['sig2', { finding: { category: 'test' }, confidence: 0.4, reasons: [] }]
      ]),
      confirmedPatterns: new Map([
        ['sig3', { finding: { category: 'test' }, confidence: 0.8 }],
        ['sig4', { finding: { category: 'test' }, confidence: 0.9 }]
      ])
    };

    const stats = calculateMemoryStats(memory);

    expect(stats.avgDismissedConfidence).toBeCloseTo(0.35);
    expect(stats.avgConfirmedConfidence).toBeCloseTo(0.85);
  });

  test('should handle empty memory', () => {
    const memory = {
      dismissedPatterns: new Map(),
      confirmedPatterns: new Map()
    };

    const stats = calculateMemoryStats(memory);

    expect(stats.totalDismissedPatterns).toBe(0);
    expect(stats.totalConfirmedPatterns).toBe(0);
    expect(stats.avgDismissedConfidence).toBe(0);
    expect(stats.avgConfirmedConfidence).toBe(0);
  });
});

// ==================== applyMemoryToFindings Tests ====================

describe('applyMemoryToFindings', () => {
  const mockFindings = [
    {
      name: 'Known Dismissed',
      file: 'api.js',
      line: 10,
      category: 'injection',
      confidence: 0.6
    },
    {
      name: 'Known Confirmed',
      file: 'db.js',
      line: 5,
      category: 'injection',
      confidence: 0.7
    },
    {
      name: 'New Finding',
      file: 'utils.js',
      line: 1,
      category: 'file-access',
      confidence: 0.5
    }
  ];

  const mockMemory = {
    dismissedPatterns: new Map([
      [generateFindingSignature(mockFindings[0]), {
        finding: { name: 'Known Dismissed' },
        count: 3,
        reasons: ['False positive'],
        lastSeen: new Date().toISOString()
      }]
    ]),
    confirmedPatterns: new Map([
      [generateFindingSignature(mockFindings[1]), {
        finding: { name: 'Known Confirmed' },
        confirmedAt: new Date().toISOString(),
        execValidated: true
      }]
    ])
  };

  test('should reduce confidence for dismissed patterns', () => {
    const result = applyMemoryToFindings(mockFindings, mockMemory);
    const dismissedFinding = result.find(f => f.name === 'Known Dismissed');

    expect(dismissedFinding.confidence).toBeLessThan(mockFindings[0].confidence);
    expect(dismissedFinding.memoryMatch.type).toBe('dismissed');
  });

  test('should boost confidence for confirmed patterns', () => {
    const result = applyMemoryToFindings(mockFindings, mockMemory);
    const confirmedFinding = result.find(f => f.name === 'Known Confirmed');

    expect(confirmedFinding.confidence).toBeGreaterThan(mockFindings[1].confidence);
    expect(confirmedFinding.memoryMatch.type).toBe('confirmed');
  });

  test('should mark findings dismissed 3+ times for review', () => {
    const result = applyMemoryToFindings(mockFindings, mockMemory);
    const dismissedFinding = result.find(f => f.name === 'Known Dismissed');

    expect(dismissedFinding.shouldReview).toBe(true);
  });

  test('should leave new findings unchanged', () => {
    const result = applyMemoryToFindings(mockFindings, mockMemory);
    const newFinding = result.find(f => f.name === 'New Finding');

    expect(newFinding.memoryMatch).toBeUndefined();
    expect(newFinding.confidence).toBe(mockFindings[2].confidence);
  });
});

// ==================== runAggregationPipeline Tests ====================

describe('runAggregationPipeline', () => {
  const mockValidatedFindings = [
    {
      name: 'Test Finding',
      severity: 'HIGH',
      category: 'injection',
      file: 'test.js',
      line: 10,
      confidence: 0.8,
      isDismissed: false,
      passedValidation: true
    }
  ];

  test('should run all three phases', async () => {
    const result = await runAggregationPipeline(mockValidatedFindings);

    expect(result.findings).toBeDefined();
    expect(result.memoryResult).toBeDefined();
    expect(result.summary).toBeDefined();
  });

  test('should provide summary statistics', async () => {
    const result = await runAggregationPipeline(mockValidatedFindings);

    expect(result.summary.totalFindings).toBeDefined();
    expect(result.summary.confirmedVulnerabilities).toBeDefined();
    expect(result.summary.dismissedFindings).toBeDefined();
    expect(result.summary.memoryStats).toBeDefined();
  });
});