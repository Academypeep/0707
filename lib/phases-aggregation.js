/**
 * Mythos Agent - Aggregation and Memory (Phases 7-9)
 * Phase 7: Aggregation - Deduplicate and rank findings
 * Phase 8: Live-Exec Validator - Execute PoCs (optional)
 * Phase 9: Dismissal Memory Tracking - Learn from dismissals
 */

const crypto = require('crypto');

/**
 * Phase 7: Aggregation
 * Aggregate, deduplicate, and rank final findings
 *
 * @param {Array} validatedFindings - Findings from Phase 6
 * @param {Object} options - Aggregation options
 * @returns {Array} - Deduplicated, ranked findings
 */
function aggregateFindings(validatedFindings, options = {}) {
  const {
    dedupeBy = 'signature',
    sortBy = 'severity',
    includeDismissed = false
  } = options;

  // Filter out dismissed findings unless requested
  let findings = validatedFindings;
  if (!includeDismissed) {
    findings = validatedFindings.filter(f => !f.isDismissed);
  }

  // Deduplicate
  const deduped = deduplicateFindings(findings, dedupeBy);

  // Rank by severity and confidence
  const ranked = rankFindings(deduped, sortBy);

  return ranked;
}

/**
 * Generate a unique signature for a finding
 */
function generateFindingSignature(finding) {
  const parts = [
    finding.file || 'unknown',
    finding.line || '0',
    finding.name || finding.pattern || 'unknown',
    finding.category || 'unknown'
  ];

  const content = parts.join('|');
  return crypto.createHash('sha256').update(content).digest('hex').slice(0, 16);
}

/**
 * Deduplicate findings based on signature
 */
function deduplicateFindings(findings, dedupeBy) {
  if (dedupeBy === 'none') {
    return findings;
  }

  const seen = new Map();
  const deduped = [];

  for (const finding of findings) {
    let key;

    if (dedupeBy === 'file') {
      key = `${finding.file}:${finding.line}`;
    } else if (dedupeBy === 'category') {
      key = `${finding.file}:${finding.category}`;
    } else {
      // Default: signature-based deduplication
      key = generateFindingSignature(finding);
    }

    if (!seen.has(key)) {
      seen.set(key, finding);
      deduped.push(finding);
    } else {
      // Keep the finding with higher confidence
      const existing = seen.get(key);
      if (finding.confidence > existing.confidence) {
        seen.set(key, finding);
        // Update in deduped array
        const index = deduped.findIndex(f => generateFindingSignature(f) === key);
        if (index !== -1) {
          deduped[index] = finding;
        }
      }
    }
  }

  return deduped;
}

/**
 * Rank findings by severity and confidence
 */
function rankFindings(findings, sortBy) {
  const severityOrder = {
    'CRITICAL': 5,
    'HIGH': 4,
    'MEDIUM': 3,
    'LOW': 2,
    'INFO': 1
  };

  return findings.sort((a, b) => {
    if (sortBy === 'confidence') {
      return (b.confidence || 0) - (a.confidence || 0);
    }

    if (sortBy === 'severity') {
      const severityDiff = (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0);
      if (severityDiff !== 0) return severityDiff;
      // Tie-break by confidence
      return (b.confidence || 0) - (a.confidence || 0);
    }

    if (sortBy === 'file') {
      return (a.file || '').localeCompare(b.file || '');
    }

    // Default: severity then confidence
    const severityDiff = (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0);
    if (severityDiff !== 0) return severityDiff;
    return (b.confidence || 0) - (a.confidence || 0);
  });
}

/**
 * Phase 8: Live-Exec Validator
 * Execute proof-of-concept exploits to confirm exploitability
 *
 * NOTE: This is a stub implementation. Real exploit execution requires:
 * - Sandbox isolation
 * - Safety controls
 * - User consent
 * - Proper error handling
 *
 * @param {Array} findings - Findings to validate
 * @param {Object} options - Execution options
 * @returns {Promise<Array>} - Findings with execution results
 */
async function liveExecValidator(findings, options = {}) {
  const {
    skipExec = true,
    sandboxEnabled = false,
    timeout = 5000
  } = options;

  if (skipExec) {
    // Mark all findings as not execution-validated
    return findings.map(finding => ({
      ...finding,
      execValidated: false,
      execStatus: 'skipped',
      execMessage: 'Execution validation skipped (--skip-exec flag)',
      phase: 'aggregation-only'
    }));
  }

  // Warn about execution risks
  console.warn('⚠️  WARNING: Live execution validation is experimental.');
  console.warn('⚠️  Only run on code you trust in an isolated environment.');

  const validatedFindings = [];

  for (const finding of findings) {
    // Only validate certain categories safely
    const validationResult = await validateFindingSafely(finding, {
      sandboxEnabled,
      timeout
    });

    validatedFindings.push({
      ...finding,
      ...validationResult,
      phase: 'live-exec'
    });
  }

  return validatedFindings;
}

/**
 * Safely validate a finding (stub - real implementation needs sandbox)
 */
async function validateFindingSafely(finding, options) {
  const { sandboxEnabled, timeout } = options;

  // Categories that could potentially be execution-validated
  const executionValidatableCategories = [
    'command-exec',
    'code-exec',
    'injection'
  ];

  if (!executionValidatableCategories.includes(finding.category)) {
    return {
      execValidated: false,
      execStatus: 'not-applicable',
      execMessage: `Category '${finding.category}' not suitable for execution validation`
    };
  }

  if (!sandboxEnabled) {
    return {
      execValidated: false,
      execStatus: 'no-sandbox',
      execMessage: 'Sandbox not enabled - execution validation requires isolated environment'
    };
  }

  // Real implementation would:
  // 1. Set up isolated sandbox
  // 2. Construct minimal PoC
  // 3. Execute with timeout
  // 4. Capture output/errors
  // 5. Determine exploitability
  // 6. Clean up sandbox

  // Stub response for now
  return {
    execValidated: false,
    execStatus: 'not-implemented',
    execMessage: 'Live execution validation not yet implemented - stub for future development',
    wouldRequire: {
      sandbox: true,
      timeout,
      pocConstruction: true,
      outputCapture: true,
      cleanup: true
    }
  };
}

/**
 * Phase 9: Dismissal Memory Tracking
 * Track dismissed findings to improve future scans
 *
 * @param {Array} findings - All findings including dismissed
 * @param {Object} memoryOptions - Memory persistence options
 * @returns {Object} - Memory data and statistics
 */
function dismissalMemoryTracking(findings, memoryOptions = {}) {
  const {
    persistTo = null, // File path to persist memory
    loadFrom = null   // File path to load existing memory
  } = memoryOptions;

  // Load existing memory if specified
  let memory = loadMemory(loadFrom);

  // Track dismissed findings
  const dismissed = findings.filter(f => f.isDismissed);
  const confirmed = findings.filter(f => !f.isDismissed && (f.execValidated || f.passedValidation));

  // Add to memory
  for (const finding of dismissed) {
    const signature = generateFindingSignature(finding);
    const existingEntry = memory.dismissedPatterns.get(signature);

    if (existingEntry) {
      // Increment dismissal count
      existingEntry.count++;
      existingEntry.lastSeen = new Date().toISOString();
      existingEntry.reasons.push(finding.dismissalReason);
    } else {
      // New dismissed pattern
      memory.dismissedPatterns.set(signature, {
        finding: {
          name: finding.name,
          category: finding.category,
          severity: finding.severity,
          file: finding.file,
          line: finding.line
        },
        count: 1,
        firstSeen: new Date().toISOString(),
        lastSeen: new Date().toISOString(),
        reasons: [finding.dismissalReason],
        confidence: finding.confidence
      });
    }
  }

  // Add confirmed findings to memory
  for (const finding of confirmed) {
    const signature = generateFindingSignature(finding);
    memory.confirmedPatterns.set(signature, {
      finding: {
        name: finding.name,
        category: finding.category,
        severity: finding.severity,
        cwe: finding.cwe
      },
      confirmedAt: new Date().toISOString(),
      confidence: finding.confidence,
      execValidated: finding.execValidated || false
    });
  }

  // Calculate statistics
  const stats = calculateMemoryStats(memory);

  // Persist if requested
  if (persistTo) {
    persistMemory(memory, persistTo);
  }

  return {
    memory,
    stats,
    dismissedCount: dismissed.length,
    confirmedCount: confirmed.length
  };
}

/**
 * Load memory from file
 */
function loadMemory(filePath) {
  const fs = require('fs');
  const path = require('path');

  if (!filePath || !fs.existsSync(filePath)) {
    return {
      dismissedPatterns: new Map(),
      confirmedPatterns: new Map(),
      version: 1,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
  }

  try {
    const data = fs.readFileSync(filePath, 'utf-8');
    const parsed = JSON.parse(data);

    // Convert back to Maps
    const dismissedPatterns = new Map(
      (parsed.dismissedPatterns || []).map(([k, v]) => [k, v])
    );
    const confirmedPatterns = new Map(
      (parsed.confirmedPatterns || []).map(([k, v]) => [k, v])
    );

    return {
      dismissedPatterns,
      confirmedPatterns,
      version: parsed.version || 1,
      createdAt: parsed.createdAt || new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
  } catch (error) {
    console.warn(`⚠️  Failed to load memory from ${filePath}:`, error.message);
    return {
      dismissedPatterns: new Map(),
      confirmedPatterns: new Map(),
      version: 1,
      createdAt: new Date().toISOString(),
      updatedAt: new Date().toISOString()
    };
  }
}

/**
 * Persist memory to file
 */
function persistMemory(memory, filePath) {
  const fs = require('fs');
  const path = require('path');

  // Ensure directory exists
  const dir = path.dirname(filePath);
  if (!fs.existsSync(dir)) {
    fs.mkdirSync(dir, { recursive: true });
  }

  // Convert Maps to serializable format
  const serializable = {
    version: memory.version,
    createdAt: memory.createdAt,
    updatedAt: memory.updatedAt,
    dismissedPatterns: Array.from(memory.dismissedPatterns.entries()),
    confirmedPatterns: Array.from(memory.confirmedPatterns.entries())
  };

  fs.writeFileSync(filePath, JSON.stringify(serializable, null, 2));
  console.log(`💾 Dismissal memory persisted to ${filePath}`);
}

/**
 * Calculate statistics from memory
 */
function calculateMemoryStats(memory) {
  const dismissedPatterns = memory.dismissedPatterns;
  const confirmedPatterns = memory.confirmedPatterns;

  // Category breakdown
  const dismissedByCategory = {};
  dismissedPatterns.forEach((entry) => {
    const cat = entry.finding.category || 'unknown';
    dismissedByCategory[cat] = (dismissedByCategory[cat] || 0) + 1;
  });

  const confirmedByCategory = {};
  confirmedPatterns.forEach((entry) => {
    const cat = entry.finding.category || 'unknown';
    confirmedByCategory[cat] = (confirmedByCategory[cat] || 0) + 1;
  });

  // Top dismissal reasons
  const dismissalReasons = [];
  dismissedPatterns.forEach((entry) => {
    entry.reasons.forEach(reason => {
      dismissalReasons.push(reason);
    });
  });

  const reasonCounts = {};
  dismissalReasons.forEach(reason => {
    reasonCounts[reason] = (reasonCounts[reason] || 0) + 1;
  });

  const topDismissalReasons = Object.entries(reasonCounts)
    .sort((a, b) => b[1] - a[1])
    .slice(0, 5)
    .map(([reason, count]) => ({ reason, count }));

  // Average confidence of dismissed vs confirmed
  const dismissedConfs = [];
  dismissedPatterns.forEach(entry => dismissedConfs.push(entry.confidence));

  const confirmedConfs = [];
  confirmedPatterns.forEach(entry => confirmedConfs.push(entry.confidence));

  const avgDismissedConfidence = dismissedConfs.length > 0
    ? dismissedConfs.reduce((a, b) => a + b, 0) / dismissedConfs.length
    : 0;

  const avgConfirmedConfidence = confirmedConfs.length > 0
    ? confirmedConfs.reduce((a, b) => a + b, 0) / confirmedConfs.length
    : 0;

  return {
    totalDismissedPatterns: dismissedPatterns.size,
    totalConfirmedPatterns: confirmedPatterns.size,
    dismissedByCategory,
    confirmedByCategory,
    topDismissalReasons,
    avgDismissedConfidence,
    avgConfirmedConfidence,
    dismissalToConfirmationRatio: confirmedPatterns.size > 0
      ? dismissedPatterns.size / confirmedPatterns.size
      : dismissedPatterns.size
  };
}

/**
 * Use memory to filter/score future findings
 */
function applyMemoryToFindings(findings, memory) {
  return findings.map(finding => {
    const signature = generateFindingSignature(finding);
    const dismissedEntry = memory.dismissedPatterns.get(signature);

    if (dismissedEntry) {
      // This pattern was dismissed before
      return {
        ...finding,
        memoryMatch: {
          type: 'dismissed',
          count: dismissedEntry.count,
          reasons: dismissedEntry.reasons,
          lastSeen: dismissedEntry.lastSeen
        },
        // Reduce confidence based on dismissal history
        confidence: finding.confidence * 0.5,
        shouldReview: dismissedEntry.count >= 3 // Review if dismissed 3+ times
      };
    }

    const confirmedEntry = memory.confirmedPatterns.get(signature);
    if (confirmedEntry) {
      return {
        ...finding,
        memoryMatch: {
          type: 'confirmed',
          confirmedAt: confirmedEntry.confirmedAt,
          execValidated: confirmedEntry.execValidated
        },
        // Boost confidence based on confirmation history
        confidence: Math.min(1.0, finding.confidence * 1.2)
      };
    }

    return finding;
  });
}

/**
 * Combined aggregation pipeline (Phases 7-9)
 */
async function runAggregationPipeline(validatedFindings, options = {}) {
  console.log('🔄 Phase 7: Aggregation...');
  const aggregated = aggregateFindings(validatedFindings, options.aggregation || {});
  console.log(`   ${aggregated.length} findings after deduplication`);

  console.log('🔄 Phase 8: Live-Exec Validator...');
  const execValidated = await liveExecValidator(aggregated, options.exec || {});
  const validatedCount = execValidated.filter(f => f.execValidated).length;
  console.log(`   ${validatedCount} findings execution-validated`);

  console.log('🔄 Phase 9: Dismissal Memory Tracking...');
  const memoryResult = dismissalMemoryTracking(execValidated, options.memory || {});
  console.log(`   ${memoryResult.dismissedCount} dismissed, ${memoryResult.confirmedCount} confirmed`);

  return {
    findings: execValidated,
    memoryResult,
    summary: {
      totalFindings: execValidated.length,
      confirmedVulnerabilities: memoryResult.confirmedCount,
      dismissedFindings: memoryResult.dismissedCount,
      memoryStats: memoryResult.stats
    }
  };
}

module.exports = {
  // Phase functions
  aggregateFindings,
  liveExecValidator,
  dismissalMemoryTracking,
  runAggregationPipeline,

  // Helper functions (exported for testing)
  generateFindingSignature,
  deduplicateFindings,
  rankFindings,
  validateFindingSafely,
  loadMemory,
  persistMemory,
  calculateMemoryStats,
  applyMemoryToFindings
};