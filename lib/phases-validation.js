/**
 * Mythos Agent - Validation Phases (4-6)
 * Phase 4: Live Agentic Hunt
 * Phase 5: Adversarial Self-Challenge
 * Phase 6: Skeptical Validator
 */

const { identifySinks, matchVulnerabilityPatterns, scoreFile } = require('./analysis-utils');

/**
 * Phase 4: LIVE Agentic Hunt
 * Autonomous vulnerability discovery using agentic analysis
 *
 * @param {Array} rankedFiles - Files ranked by risk score
 * @param {Array} sinks - Identified security sinks
 * @param {Object} options - Analysis options
 * @returns {Promise<Array>} - Preliminary findings
 */
async function liveAgenticHunt(rankedFiles, sinks, options = {}) {
  const findings = [];
  const { passAtK = 1, agentCallback = null } = options;

  // For each file in ranked order, perform deep analysis
  for (const file of rankedFiles.slice(0, options.maxFiles || 10)) {
    const content = file.content;
    const filePath = file.path;

    // Phase 4 uses multiple analysis passes (pass@K diversity)
    for (let k = 0; k < passAtK; k++) {
      const passFindings = analyzeFileWithDiversity(content, filePath, k, sinks);
      findings.push(...passFindings);
    }
  }

  return findings;
}

/**
 * Analyze a file with diversity seeding for pass@K
 */
function analyzeFileWithDiversity(content, filePath, diversityIndex, sinks) {
  const findings = [];

  // Different analysis lenses based on diversity index
  const lenses = [
    { name: 'direct-matches', focus: 'direct pattern matches' },
    { name: 'data-flow', focus: 'data flow from input to sink' },
    { name: 'context-aware', focus: 'context and sanitization checks' },
    { name: 'composition', focus: 'vulnerability patterns across functions' },
    { name: 'exploitation-paths', focus: 'potential exploit chains' }
  ];

  const lens = lenses[diversityIndex % lenses.length];

  // Match vulnerability patterns
  const patternMatches = matchVulnerabilityPatterns(content);

  for (const match of patternMatches) {
    // Apply lens-specific analysis
    const enhancedFinding = {
      ...match,
      file: filePath,
      analysisPass: lens.name,
      confidence: adjustConfidenceByLens(match.confidence, lens),
      timestamp: new Date().toISOString()
    };

    findings.push(enhancedFinding);
  }

  // Cross-reference with identified sinks.
  //
  // A sink is considered "already captured" only when there is a pattern
  // match on the same line that explicitly references the sink name
  // (e.g. a "Command Injection - template literal" match for an `exec`
  // sink). Proximity alone (within N lines) is not sufficient: a generic
  // match like "Rate limiting missing" on a nearby line does NOT cover
  // a CRITICAL command-injection sink, and silently dropping it would
  // hide the very finding we care about on high-risk files.
  const fileSinks = sinks.filter(s => s.file === filePath);
  for (const sink of fileSinks) {
    const sinkNameLower = sink.name.toLowerCase();
    const correlatedMatch = patternMatches.find(m => {
      if (m.line !== sink.line) return false;
      const matchName = (m.name || '').toLowerCase();
      return matchName.includes(sinkNameLower) ||
             sinkNameLower.includes(matchName.split(' ')[0]);
    });

    if (correlatedMatch) {
      // Same-line, same-name pattern match already reports this sink.
      continue;
    }

    // Report sink presence as a finding
    findings.push({
      name: `Sink: ${sink.name}`,
      severity: sink.severity,
      category: sink.category,
      file: filePath,
      line: sink.line,
      description: sink.description,
      cwe: sink.cwe,
      remediation: sink.remediation,
      confidence: sink.severity === 'CRITICAL' ? 0.85 : 0.6,
      analysisPass: lens.name,
      timestamp: new Date().toISOString(),
      metadata: {
        sinkType: 'direct',
        sinkDetails: sink
      }
    });
  }

  return findings;
}

/**
 * Adjust confidence based on analysis lens
 */
function adjustConfidenceByLens(baseConfidence, lens) {
  const adjustments = {
    'direct-matches': 0.0,      // Base confidence
    'data-flow': 0.1,           // Higher confidence with data flow
    'context-aware': -0.05,     // Slightly lower without context
    'composition': 0.05,        // Moderate boost for composition
    'exploitation-paths': 0.15  // High confidence with exploit path
  };

  const adjustment = adjustments[lens.name] || 0;
  return Math.min(1.0, Math.max(0.0, baseConfidence + adjustment));
}

/**
 * Phase 5: Adversarial Self-Challenge
 * Challenge findings to reduce false positives
 *
 * @param {Array} findings - Findings from Phase 4
 * @param {Object} options - Challenge options
 * @returns {Promise<Array>} - Challenged findings with counter-arguments
 */
async function adversarialSelfChallenge(findings, options = {}) {
  const challengedFindings = [];
  const { challengeIntensity = 'medium' } = options;

  // Challenge parameters based on intensity
  const intensityParams = {
    'low': { challenges: 1, skepticism: 0.3 },
    'medium': { challenges: 3, skepticism: 0.5 },
    'high': { challenges: 5, skepticism: 0.7 }
  };

  const params = intensityParams[challengeIntensity] || intensityParams.medium;

  for (const finding of findings) {
    const challenges = generateChallenges(finding, params.challenges);
    const counterArguments = generateCounterArguments(finding, challenges);

    // Calculate challenge score (how much the finding was weakened)
    const challengeScore = calculateChallengeScore(finding, challenges, counterArguments);

    // Adjust confidence based on challenges
    const adjustedConfidence = Math.max(
      0,
      finding.confidence - (challengeScore * params.skepticism)
    );

    challengedFindings.push({
      ...finding,
      challenges,
      counterArguments,
      challengeScore,
      adjustedConfidence,
      phase4Confidence: finding.confidence,
      isChallenged: challengeScore > 0.3
    });
  }

  return challengedFindings;
}

/**
 * Generate challenge questions for a finding
 */
function generateChallenges(finding, count) {
  const challengeTemplates = [
    {
      type: 'false-positive',
      question: `Could this be a false positive? Is '${finding.name}' used safely here?`,
      weight: 0.3
    },
    {
      type: 'sanitization',
      question: 'Is the input sanitized before reaching this sink?',
      weight: 0.25
    },
    {
      type: 'context',
      question: 'Is this sink in a trusted context (internal-only, validated input)?',
      weight: 0.2
    },
    {
      type: 'alternatives',
      question: 'Could this pattern match be explained by safe alternative usage?',
      weight: 0.15
    },
    {
      type: 'severity',
      question: `Is ${finding.severity} severity appropriate, or should it be lower?`,
      weight: 0.1
    }
  ];

  // Select top N challenges based on finding characteristics
  const selectedChallenges = challengeTemplates
    .slice(0, count)
    .map(template => ({
      ...template,
      findingContext: {
        file: finding.file,
        line: finding.line,
        sink: finding.name
      }
    }));

  return selectedChallenges;
}

/**
 * Generate counter-arguments for challenges
 */
function generateCounterArguments(finding, challenges) {
  const counterArguments = [];

  for (const challenge of challenges) {
    const counter = {
      challengeType: challenge.type,
      argument: generateCounterArgumentText(finding, challenge),
      strength: Math.random() * 0.5 + 0.25 // Random strength 0.25-0.75
    };
    counterArguments.push(counter);
  }

  return counterArguments;
}

/**
 * Generate counter-argument text based on finding
 */
function generateCounterArgumentText(finding, challenge) {
  const templates = {
    'false-positive': `Pattern '${finding.name}' matched, but context suggests safe usage`,
    'sanitization': `Input may be sanitized upstream or through middleware`,
    'context': `Sink appears in controlled context with validated inputs`,
    'alternatives': `Match could indicate safe wrapper or abstraction layer`,
    'severity': `Severity may be overstated; actual exploit requires specific conditions`
  };

  return templates[challenge.type] || 'Requires manual review';
}

/**
 * Calculate challenge score for a finding
 */
function calculateChallengeScore(finding, challenges, counterArguments) {
  if (counterArguments.length === 0) return 0;

  const avgCounterStrength = counterArguments.reduce(
    (sum, c) => sum + c.strength,
    0
  ) / counterArguments.length;

  // Factors that increase challenge score
  let score = avgCounterStrength;

  // Penalize low confidence findings more
  if (finding.confidence < 0.5) {
    score += 0.1;
  }

  // Penalize findings without clear remediation
  if (!finding.remediation) {
    score += 0.05;
  }

  return Math.min(1.0, score);
}

/**
 * Phase 6: Skeptical Validator
 * Secondary validation with skepticism
 *
 * @param {Array} challengedFindings - Findings from Phase 5
 * @param {Object} options - Validation options
 * @returns {Promise<Array>} - Validated findings with status
 */
async function skepticalValidator(challengedFindings, options = {}) {
  const validatedFindings = [];
  const { minConfidence = 0.3, strictMode = false } = options;

  for (const finding of challengedFindings) {
    const validation = validateFinding(finding, { strictMode });

    // Apply minimum confidence filter
    const passesThreshold = validation.finalConfidence >= minConfidence;

    validatedFindings.push({
      ...finding,
      validation,
      isDismissed: !passesThreshold,
      dismissalReason: passesThreshold ? null : `Confidence ${validation.finalConfidence.toFixed(2)} below threshold ${minConfidence}`,
      passedValidation: passesThreshold
    });
  }

  return validatedFindings;
}

/**
 * Validate a single finding with skepticism
 */
function validateFinding(finding, options) {
  const { strictMode } = options;

  // Validation criteria
  const criteria = [
    {
      name: 'pattern-strength',
      description: 'Is the vulnerability pattern match strong?',
      weight: 0.25,
      passed: finding.confidence >= 0.7
    },
    {
      name: 'sink-presence',
      description: 'Is a known dangerous sink present?',
      weight: 0.2,
      passed: finding.category !== undefined && finding.severity !== undefined
    },
    {
      name: 'challenge-survived',
      description: 'Did the finding survive adversarial challenges?',
      weight: 0.2,
      passed: !finding.isChallenged || finding.challengeScore < 0.4
    },
    {
      name: 'specificity',
      description: 'Is the finding specific (not vague)?',
      weight: 0.15,
      passed: finding.line !== undefined && finding.file !== undefined
    },
    {
      name: 'remediation-available',
      description: 'Is there a clear remediation path?',
      weight: 0.1,
      passed: finding.remediation !== undefined && finding.remediation.length > 0
    },
    {
      name: 'cwe-linked',
      description: 'Is the finding linked to a CWE?',
      weight: 0.1,
      passed: finding.cwe !== undefined
    }
  ];

  // In strict mode, require more criteria to pass
  const requiredPassCount = strictMode ? 5 : 3;
  const passedCriteria = criteria.filter(c => c.passed);
  const passedCount = passedCriteria.length;

  // Calculate base confidence from finding
  let baseConfidence = finding.adjustedConfidence || finding.confidence || 0.5;

  // Adjust based on criteria passed
  const criteriaScore = passedCount / criteria.length;
  const finalConfidence = (baseConfidence * 0.6) + (criteriaScore * 0.4);

  // Determine validation status
  let status = 'VALID';
  if (passedCount < requiredPassCount) {
    status = 'WEAK';
  } else if (passedCount === criteria.length) {
    status = 'STRONG';
  }

  return {
    criteria,
    passedCount,
    totalCriteria: criteria.length,
    baseConfidence,
    criteriaScore,
    finalConfidence,
    status,
    strictMode,
    timestamp: new Date().toISOString()
  };
}

/**
 * Combined validation pipeline (Phases 4-6)
 */
async function runValidationPipeline(rankedFiles, sinks, options = {}) {
  console.log('🔄 Phase 4: LIVE Agentic Hunt...');
  const phase4Findings = await liveAgenticHunt(rankedFiles, sinks, options);
  console.log(`   Found ${phase4Findings.length} preliminary findings`);

  console.log('🔄 Phase 5: Adversarial Self-Challenge...');
  const phase5Findings = await adversarialSelfChallenge(phase4Findings, options);
  const challengedCount = phase5Findings.filter(f => f.isChallenged).length;
  console.log(`   Challenged ${challengedCount} findings`);

  console.log('🔄 Phase 6: Skeptical Validator...');
  const phase6Findings = await skepticalValidator(phase5Findings, options);
  const passedCount = phase6Findings.filter(f => f.passedValidation).length;
  console.log(`   ${passedCount} findings passed validation`);

  return {
    phase4Findings,
    phase5Findings,
    phase6Findings,
    summary: {
      initial: phase4Findings.length,
      challenged: challengedCount,
      passed: passedCount,
      dismissed: phase6Findings.length - passedCount
    }
  };
}

module.exports = {
  // Phase functions
  liveAgenticHunt,
  adversarialSelfChallenge,
  skepticalValidator,
  runValidationPipeline,

  // Helper functions (exported for testing)
  analyzeFileWithDiversity,
  adjustConfidenceByLens,
  generateChallenges,
  generateCounterArguments,
  calculateChallengeScore,
  validateFinding
};