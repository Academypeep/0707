// Mythos Agent - Node.js Implementation
// Based on Mythos Research Edition 8-phase vulnerability discovery scaffold

const fs = require('fs');
const path = require('path');

// File ranker — used in Phase 2 (fileRanking) to prioritize
// internet-facing and authentication code on the 1–5 scale.
const {
  rankFiles,
  rankFile,
  rankFilesFromList,
  filterByMinRank,
  groupByRank,
  printRankSummary,
  RANK_LABELS,
  DEFAULT_WEIGHTS
} = require('./lib/file-ranker');

// New multi-agent pipeline components
const { HunterAgent } = require('./lib/hunter-agent');
const { ValidatorAgent } = require('./lib/validator-agent');
const { ReportGenerator } = require('./lib/report-generator');
const { CodeBrowser } = require('./lib/code-browser');
const { SandboxExecutor } = require('./lib/sandbox-executor');

// Autonomous agent & T3MP3ST enhancement modules
const { EgressScopeContainment } = require('./lib/egress-scope');
const { LLMProvider } = require('./lib/llm-provider');
const { Arsenal } = require('./lib/arsenal');
const { MCPServer } = require('./lib/mcp-server');
const { SwarmCoordinator } = require('./lib/swarm-coordinator');
const { IntegrityLedger } = require('./lib/integrity-ledger');

/**
 * Mythos Agent - Implements the 8-phase vulnerability discovery scaffold
 * Based on Anthropic's Mythos Preview / Project Glasswing
 */
class MythosAgent {
  constructor(options = {}) {
    this.options = {
      targetDir: options.targetDir || process.cwd(),
      maxFiles: options.maxFiles || 10,
      budget: options.budget || 5.00,
      passAtK: options.passAtK || 1,
      minExecSeverity: options.minExecSeverity || 'HIGH',
      execBudget: options.execBudget || 3.00,
      skipExec: options.skipExec || false,
      // Phase 2 (fileRanking) options — forwarded to rankFiles()
      ranker: {
        // Only surface files at or above this rank (1–5) to downstream phases.
        // 4 keeps internet-facing + sink combinations and above.
        minRank: options.minRank ?? 1,
        // Print the per-tier summary table when running interactively.
        verbose: options.verbose ?? true,
        // Override scoring weights (see lib/file-ranker.js DEFAULT_WEIGHTS).
        weights: options.rankerWeights ?? null,
        ...(options.ranker || {})
      },
      // Azure AI Configuration Options
      azureOpenAIEndpoint: options.azureOpenAIEndpoint || process.env.AZURE_OPENAI_ENDPOINT,
      azureOpenAIKey: options.azureOpenAIKey || process.env.AZURE_OPENAI_KEY,
      azureOpenAIDeployment: options.azureOpenAIDeployment || process.env.AZURE_OPENAI_DEPLOYMENT || 'gpt-4',
      azureSearchEndpoint: options.azureSearchEndpoint || process.env.AZURE_SEARCH_ENDPOINT,
      azureSearchKey: options.azureSearchKey || process.env.AZURE_SEARCH_KEY,
      azureSearchIndex: options.azureSearchIndex || process.env.AZURE_SEARCH_INDEX || 'vulnerability-index',
      azureFormRecognizerEndpoint: options.azureFormRecognizerEndpoint || process.env.AZURE_FORM_RECOGNIZER_ENDPOINT,
      azureFormRecognizerKey: options.azureFormRecognizerKey || process.env.AZURE_FORM_RECOGNIZER_KEY,
      azureContentSafetyEndpoint: options.azureContentSafetyEndpoint || process.env.AZURE_CONTENT_SAFETY_ENDPOINT,
      azureContentSafetyKey: options.azureContentSafetyKey || process.env.AZURE_CONTENT_SAFETY_KEY,
      ...options
    };

    // Initialize Azure AI Service if credentials are provided
    this.azureAIService = null;
    if (this.options.azureOpenAIEndpoint && this.options.azureOpenAIKey ||
        this.options.azureSearchEndpoint && this.options.azureSearchKey ||
        this.options.azureFormRecognizerEndpoint && this.options.azureFormRecognizerKey ||
        this.options.azureContentSafetyEndpoint && this.options.azureContentSafetyKey) {
      try {
        const { AzureAIService } = require('./azure-ai-service');
        this.azureAIService = new AzureAIService({
          openAIEndpoint: this.options.azureOpenAIEndpoint,
          openAIKey: this.options.azureOpenAIKey,
          openAIDeployment: this.options.azureOpenAIDeployment,
          searchEndpoint: this.options.azureSearchEndpoint,
          searchKey: this.options.azureSearchKey,
          searchIndex: this.options.azureSearchIndex,
          formRecognizerEndpoint: this.options.azureFormRecognizerEndpoint,
          formRecognizerKey: this.options.azureFormRecognizerKey,
          contentSafetyEndpoint: this.options.azureContentSafetyEndpoint,
          contentSafetyKey: this.options.azureContentSafetyKey
        });
      } catch (error) {
        console.warn('⚠️  Failed to initialize Azure AI Service:', error.message);
        console.warn('⚠️  Continuing with standard Mythos Agent functionality');
      }
    }

    // Initialize multi-agent components
    this.codeBrowser = new CodeBrowser(this.options.targetDir, {
      includeHiddenDirs: this.options.includeHiddenDirs === true || (this.options.entryPoint || '').startsWith('.')
    });
    this.sandbox = new SandboxExecutor(this.options.sandbox || {});
    this.entryPoint = this.options.entryPoint || this.options.startPoint || null;
    this.hunterAgents = [];
    this.validator = new ValidatorAgent({
      targetDir: this.options.targetDir,
      model: this.options.model || 'claude-opus-4.5',
      apiKey: this.options.apiKey || process.env.ANTHROPIC_API_KEY,
      allowMock: this.options.allowMock
    });
    this.reportGenerator = new ReportGenerator({
      outputDir: this.options.reportDir || './reports',
      projectName: this.options.projectName || path.basename(this.options.targetDir),
      disclosureMode: this.options.disclosureMode || 'coordinated'
    });

    // Autonomous Agent & Swarm Components
    this.integrityLedger = new IntegrityLedger(this.options);
    this.swarmCoordinator = new SwarmCoordinator({
      targetDir: this.options.targetDir,
      target: this.options.target || this.options.targetDir,
      budget: this.options.budget,
      passAtK: this.options.passAtK,
      provider: this.options.provider,
      model: this.options.model,
      apiKey: this.options.apiKey,
      allowMock: this.options.allowMock
    });

    this.phases = [
      'languageDetection',
      'sinkGuidedSlicing',
      'fileRanking',
      'buildSandboxSetup',
      'liveAgenticHunt',
      'adversarialSelfChallenge',
      'skepticalValidator',
      'liveExecValidator',
      'aggregation',
      'dismissalMemoryTracking'
    ];

    this.findings = [];
    this.rankedFiles = [];           // populated by runFileRanking()
    this.dismissalMemory = new Set();
    this.costTracker = {
      total: 0,
      byPhase: {}
    };
  }

  /**
   * Phase 2 — File Ranking.
   *
   * Walks `options.targetDir`, scores every source file on a 1–5 scale,
   * and surfaces the ranked list. Internet-facing routes, controllers,
   * middleware, and authentication / authorization code are prioritized
   * (weights: internet-facing 1.2, auth 1.1, sinks 1.0, file-type 0.8).
   *
   * Result is stored on `this.rankedFiles` and also returned.
   *
   * @param {Object} [overrideOptions] — Override ranker options for this run
   * @returns {Array<{path, rank, score, breakdown, content}>}
   */
  runFileRanking(overrideOptions = {}) {
    const opts = { ...this.options.ranker, ...overrideOptions };

    const ranked = rankFiles(this.options.targetDir, {
      maxFiles: this.options.maxFiles,
      includeHiddenDirs: opts.includeHiddenDirs === true || this.options.includeHiddenDirs === true,
      ...(opts.weights ? { weights: opts.weights } : {})
    });

    // Apply minRank filter (default: keep everything ranked ≥ 1).
    const filtered = opts.minRank > 1 ? filterByMinRank(ranked, opts.minRank) : ranked;

    this.rankedFiles = filtered;

    // Track cost (Phase 2 ≈ $0.15 per scan, per README).
    this.costTracker.byPhase.fileRanking = 0.15;
    this.costTracker.total += 0.15;

    if (opts.verbose) {
      printRankSummary(ranked);
      const groups = groupByRank(filtered);
      const total = filtered.length;
      const highPriority = (groups[5]?.length || 0) + (groups[4]?.length || 0);
      console.log(`\n  → ${total} file(s) passed the minRank=${opts.minRank} filter`);
      console.log(`  → ${highPriority} file(s) are HIGH or CRITICAL (rank ≥ 4)`);
    }

    return filtered;
  }

  /**
   * Re-rank an already-discovered file list. Useful when the caller has
   * its own discovery pipeline (e.g. AST-aware scanner) and just wants
   * the 1–5 ranking + internet-facing/auth prioritization applied.
   *
   * @param {Array<{path, content}>} fileList
   * @param {Object} [overrideOptions]
   * @returns {Array}
   */
  rankFromList(fileList, overrideOptions = {}) {
    const opts = { ...this.options.ranker, ...overrideOptions };
    const ranked = rankFilesFromList(fileList, { maxFiles: this.options.maxFiles });
    const filtered = opts.minRank > 1 ? filterByMinRank(ranked, opts.minRank) : ranked;
    this.rankedFiles = filtered;
    return filtered;
  }

  /**
   * Rank a single file by path + content. Convenience wrapper for callers
   * that want to score individual files (e.g. on-demand analysis).
   *
   * @param {string} filePath
   * @param {string} content
   * @returns {{ path, rank, score, breakdown }}
   */
  rankOne(filePath, content) {
    return rankFile(filePath, content);
  }

  /**
   * NEW: Run VSP-guided hunting on a single file with multi-agent pass@k sampling
   * Uses HunterAgent + CodeBrowser + SandboxExecutor
   *
   * @param {string} filePath - Path to file (relative to targetDir)
   * @param {number} passAtK - Number of independent attempts (default: options.passAtK)
   * @returns {Promise<Array>} - Array of findings
   */
  async huntFile(filePath, passAtK = null) {
    const k = passAtK || this.options.passAtK || 1;
    console.log(`\n[MYTHOS] Hunting ${filePath} with pass@k=${k}`);

    const allFindings = [];

    for (let attempt = 0; attempt < k; attempt++) {
      console.log(`  [Attempt ${attempt + 1}/${k}]`);

      const hunter = new HunterAgent({
        targetDir: this.options.targetDir,
        model: this.options.model || 'claude-opus-4.5',
        apiKey: this.options.apiKey || process.env.ANTHROPIC_API_KEY,
        useThinkAndVerify: this.options.useThinkAndVerify !== false,
        entryPoint: this.entryPoint,
        staticAnalysis: this.options.staticAnalysis || {},
        allowMock: this.options.allowMock
      });

      try {
        const language = this._detectLanguage(filePath);
        const findings = await hunter.hunt(filePath, language);
        allFindings.push(...findings);

        // Track cost
        this.costTracker.total += hunter.costTracker.total;
      } catch (error) {
        console.error(`  [Error in attempt ${attempt + 1}]:`, error.message);
      }
    }

    return allFindings;
  }

  /**
   * NEW: Run full multi-file hunt using pass@k sampling
   * Prioritizes high-rank files first
   *
   * @returns {Promise<Object>} - Hunt summary with all findings
   */
  async runVSPHunt() {
    console.log(`\n[MYTHOS] Starting VSP-guided multi-agent hunt`);
    console.log(`[CONFIG] pass@k=${this.options.passAtK}, budget=$${this.options.budget}`);

    const allFindings = [];
    const startFiles = this.entryPoint ? this._resolveTargetFiles(this.entryPoint) : [];
    const rankedPaths = this.rankedFiles.map(f => f.path);
    const prioritizedFiles = this.entryPoint
      ? [...new Set([...startFiles, ...rankedPaths])]
      : rankedPaths;

    if (this.entryPoint && startFiles.length) {
      console.log(`[MYTHOS] Target entry point detected: ${this.entryPoint}`);
      console.log(`  → Starting scan from: ${startFiles.join(', ')}`);
    }

    for (const filePath of prioritizedFiles) {
      if (this.costTracker.total >= this.options.budget) {
        console.log(`[BUDGET] Reached cost limit ($${this.options.budget})`);
        break;
      }

      const findings = await this.huntFile(filePath, this.options.passAtK);
      allFindings.push(...findings);
    }

    return { totalFindings: allFindings.length, findings: allFindings };
  }

  /**
   * NEW: Validate findings using secondary validator agent
   * Reduces false positive rate
   *
   * @param {Array} findings - Array of findings to validate
   * @returns {Promise<Array>} - Validated findings only
   */
  async validateFindings(findings) {
    console.log(`\n[MYTHOS] Running secondary validation on ${findings.length} findings`);

    const validated = await this.validator.validateFindings(findings);

    const fpRate = this.validator.getFalsePositiveRate();
    console.log(`[VALIDATOR] False positive rate: ${fpRate}%`);
    console.log(`[VALIDATOR] Confirmed ${validated.length}/${findings.length} as real`);

    return validated;
  }

  /**
   * NEW: Generate structured report
   *
   * @param {Array} findings - Findings to report
   * @param {string} format - 'json', 'markdown', or 'csv'
   * @returns {string} - Path to saved report
   */
  generateReport(findings, format = 'json') {
    console.log(`\n[MYTHOS] Generating ${format.toUpperCase()} report`);

    const report = this.reportGenerator.generateReport(findings, {
      targetDir: this.options.targetDir,
      budget: this.options.budget,
      costUsed: this.costTracker.total
    });

    const filePath = this.reportGenerator.saveReport(report, format);
    return filePath;
  }

  /**
   * NEW: Run autonomous multi-operator mission
   */
  async runAutonomousMission(targetSpec = null, options = {}) {
    const coordinator = options.swarmCoordinator || this.swarmCoordinator;
    return await coordinator.executeMission(targetSpec || this.options.targetDir);
  }

  /**
   * Alias for runAutonomousMission
   */
  async runSwarmMission(targetSpec = null, options = {}) {
    return await this.runAutonomousMission(targetSpec, options);
  }

  /**
   * NEW: Verify claims against evidence via Integrity Ledger
   */
  verifyClaims(evidence = {}) {
    return this.integrityLedger.verifyClaims(evidence);
  }

  /**
   * Detect programming language from file extension
   */
 _resolveTargetFiles(point) {
    if (!point || typeof point !== 'string') {
      return [];
    }

    const normalized = point.trim();
    const fileSegment = normalized.replace(/^\/+|\\+$/g, '');
    const lineSpec = fileSegment.match(/^(.*?):(\d+)$/);
    const candidatePath = lineSpec ? lineSpec[1] : fileSegment;
    const resolvedPath = path.isAbsolute(candidatePath)
      ? path.relative(this.options.targetDir, candidatePath)
      : candidatePath;
    const fullPath = path.join(this.options.targetDir, resolvedPath);

    if (fs.existsSync(fullPath)) {
      return [resolvedPath.replace(/\\/g, '/')];
    }

    const references = this.codeBrowser.findReferences(normalized);
    if (references && Array.isArray(references.references) && references.references.length > 0) {
      return [...new Set(references.references.map(ref => ref.file))].slice(0, this.options.maxFiles);
    }

    return [resolvedPath.replace(/\\/g, '/')];
  }

  _detectLanguage(filePath) {
    const ext = filePath.split('.').pop().toLowerCase();
    const langMap = {
      js: 'javascript',
      ts: 'typescript',
      py: 'python',
      c: 'c',
      cpp: 'cpp',
      h: 'c',
      hpp: 'cpp',
      java: 'java',
      go: 'go',
      rs: 'rust',
      php: 'php',
      rb: 'ruby'
    };
    return langMap[ext] || 'unknown';
  }
}

module.exports = {
  MythosAgent,
  EgressScopeContainment,
  LLMProvider,
  Arsenal,
  MCPServer,
  SwarmCoordinator,
  IntegrityLedger,
  // Re-export file-ranker pieces so consumers can import everything
  // from the top-level entry point.
  rankFiles,
  rankFile,
  rankFilesFromList,
  filterByMinRank,
  groupByRank,
  printRankSummary,
  RANK_LABELS,
  DEFAULT_WEIGHTS
};
