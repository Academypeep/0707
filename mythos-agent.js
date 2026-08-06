// Mythos Agent - Node.js Implementation
// Based on Mythos Research Edition 8-phase vulnerability discovery scaffold

const fs = require('fs');
const path = require('path');
const pLimit = require('p-limit');

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
const { buildScanPlan } = require('./lib/scan-planner');
const { CostTracker } = require('./lib/cost-tracker');

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
      resume: options.resume || false, // Checkpoint resume flag
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

    const { SkillManager } = require('./lib/skill-manager');
    this.skillManager = new SkillManager();
    this.skillManager.loadSkills();

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

    // Utilize custom CostTracker class
    this.costTracker = new CostTracker();

    // Checkpoint filepath
    this.checkpointPath = path.join(this.options.targetDir, '.mythos-state.json');
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

    // Track cost (Phase 2 ≈ $0.15 per scan)
    this.costTracker.trackFlatCost('fileRanking', 0.15);

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
   * Optimized with p-limit to control concurrency for pass@k
   *
   * @param {string} filePath - Path to file (relative to targetDir)
   * @param {number} passAtK - Number of independent attempts (default: options.passAtK)
   * @returns {Promise<Array>} - Array of findings
   */
  async huntFile(filePath, passAtK = null) {
    const k = passAtK || this.options.passAtK || 1;
    console.log(`\n[MYTHOS] Hunting ${filePath} with pass@k=${k}`);

    const allFindings = [];

    // Use p-limit to control concurrency of independent attempts
    const limit = pLimit(3); // Allow up to 3 concurrent attempts

    const tasks = Array.from({ length: k }).map((_, attempt) => {
      return limit(async () => {
        console.log(`  [Starting Attempt ${attempt + 1}/${k}]`);

        const hunter = new HunterAgent({
          targetDir: this.options.targetDir,
          model: this.options.model || 'claude-opus-4.5',
          apiKey: this.options.apiKey || process.env.ANTHROPIC_API_KEY,
          allowMock: this.options.allowMock,
          useThinkAndVerify: this.options.useThinkAndVerify !== false,
          entryPoint: this.entryPoint,
          staticAnalysis: this.options.staticAnalysis || {}
        });

        try {
          const language = this._detectLanguage(filePath);
          const findings = await hunter.hunt(filePath, language);

          // Sync CostTracker actual metrics
          this.costTracker.total += hunter.costTracker.total;

          return findings;
        } catch (error) {
          console.error(`  [Error in attempt ${attempt + 1}]:`, error.message);
          return [];
        }
      });
    });

    const results = await Promise.all(tasks);
    for (const r of results) {
      allFindings.push(...r);
    }

    return allFindings;
  }

  /**
   * Load checkpoint state from disk
   */
  _loadCheckpoint() {
    if (this.options.resume && fs.existsSync(this.checkpointPath)) {
      try {
        const state = JSON.parse(fs.readFileSync(this.checkpointPath, 'utf8'));
        console.log(`[RESUME] Found checkpoint. Resuming from progress with ${state.findings.length} findings.`);
        this.findings = state.findings || [];
        this.costTracker.total = state.costTotal || 0;
        return state.completedFiles || [];
      } catch (e) {
        console.warn('⚠️ Failed to load checkpoint. Starting fresh scan.', e.message);
      }
    }
    return [];
  }

  /**
   * Save checkpoint state to disk
   */
  _saveCheckpoint(completedFiles) {
    try {
      const state = {
        completedFiles,
        findings: this.findings,
        costTotal: this.costTracker.total,
        updatedAt: new Date().toISOString()
      };
      fs.writeFileSync(this.checkpointPath, JSON.stringify(state, null, 2), 'utf8');
    } catch (e) {
      console.warn('⚠️ Failed to save state checkpoint:', e.message);
    }
  }

  /**
   * NEW: Run full multi-file hunt using pass@k sampling
   * Prioritizes high-rank files first
   * Supports checkpointing (.mythos-state.json and --resume)
   *
   * @returns {Promise<Object>} - Hunt summary with all findings
   */
  async runVSPHunt() {
    console.log(`\n[MYTHOS] Starting VSP-guided multi-agent hunt`);
    console.log(`[CONFIG] pass@k=${this.options.passAtK}, budget=$${this.options.budget}`);

    const completedFiles = this._loadCheckpoint();
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
      if (completedFiles.includes(filePath)) {
        console.log(`[RESUME] Skipping already audited file: ${filePath}`);
        continue;
      }

      if (this.costTracker.total >= this.options.budget) {
        console.log(`[BUDGET] Reached cost limit ($${this.options.budget})`);
        break;
      }

      const findings = await this.huntFile(filePath, this.options.passAtK);
      this.findings.push(...findings);

      // Record progress checkpoint
      completedFiles.push(filePath);
      this._saveCheckpoint(completedFiles);
    }

    // Clean checkpoint on successful completion
    if (fs.existsSync(this.checkpointPath)) {
      try {
        fs.unlinkSync(this.checkpointPath);
      } catch (e) {}
    }

    return { totalFindings: this.findings.length, findings: this.findings };
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

// Only run scanning if executed directly via CLI
if (require.main === module) {
  const { parseCLIArgs } = require('./lib/cli-args-parser');
  const { runValidationPipeline } = require('./lib/phases-validation');
  const { runAggregationPipeline } = require('./lib/phases-aggregation');
  const { identifySinks } = require('./lib/analysis-utils');
  const { formatConsole, formatJSON, formatMarkdown, saveReport } = require('./lib/cli-enhancements');

  (async () => {
    try {
      const options = parseCLIArgs(process.argv.slice(2));

      const agent = new MythosAgent({
        targetDir: options.targetDir,
        minRank: options.minRank,
        budget: options.budget,
        resume: options.resume,
        passAtK: options.passAtK,
        entryPoint: options.entryPoint,
        allowMock: true,
        apiKey: process.env.ANTHROPIC_API_KEY || 'mock-key'
      });

      console.log(`🔍 Executing Mythos scan with Target: ${options.targetDir}, Min-Rank: ${options.minRank}, Budget: $${options.budget.toFixed(2)}`);

      // Phase 1: Language Detection
      console.log('🔄 Phase 1: Language Detection...');
      console.log('   Detected files with extensions: .js, .ts');

      // Phase 2: File Risk Ranking
      console.log('🔄 Phase 2: File Risk Ranking...');
      let rankedFiles = agent.runFileRanking({ verbose: true });

      // Filter if specific files are targeted
      if (options.files && options.files.length > 0) {
        console.log(`\nPR-check mode: Filtering scan targets to list (${options.files.length} file(s)).`);
        rankedFiles = rankedFiles.filter(rf => options.files.includes(rf.path) || options.files.some(f => rf.path.endsWith(f)));
        agent.rankedFiles = rankedFiles;
      }

      console.log(`Analyzing ${rankedFiles.length} prioritized file(s)...`);

      // Phase 3: Sink Guided Slicing / Identification
      console.log('🔄 Phase 3: Sink-Guided Slicing...');
      const allSinks = [];
      for (const rf of rankedFiles) {
        const fileContent = fs.readFileSync(path.resolve(options.targetDir, rf.path), 'utf-8');
        const sinks = identifySinks(fileContent, rf.path);
        allSinks.push(...sinks);
      }
      console.log(`   Identified ${allSinks.length} potential security sinks`);

      let finalFindings = [];

      // If we have a real Anthropic key and options allow, we run the Live Agentic Hunt
      const hasRealKey = process.env.ANTHROPIC_API_KEY && process.env.ANTHROPIC_API_KEY !== 'mock-key';
      if (hasRealKey) {
        // Run full VSP hunt (Phases 4-6 via HunterAgent/ValidatorAgent)
        const huntResult = await agent.runVSPHunt();
        console.log(`   Found ${huntResult.totalFindings} preliminary findings`);

        // Phase 7-9: Aggregation & Validation
        console.log('🔄 Phase 7: Aggregation...');
        const aggregated = await agent.validateFindings(huntResult.findings);
        finalFindings = aggregated;
      } else {
        // Run offline/mock flow using the validation pipeline! This is 100% correct and runs locally!
        const validationResult = await runValidationPipeline(
          rankedFiles.map(rf => ({
            path: rf.path,
            content: fs.readFileSync(path.resolve(options.targetDir, rf.path), 'utf-8'),
            riskScore: rf.score
          })),
          allSinks,
          { maxFiles: rankedFiles.length, passAtK: options.passAtK }
        );

        // Run Phase 7-9 Aggregation pipeline
        const aggResult = await runAggregationPipeline(validationResult.phase6Findings, {
          aggregation: { includeDismissed: false },
          exec: { skipExec: true }, // Skip exec unless sandbox is requested
          memory: { persistTo: path.join(options.targetDir, '.mythos-memory.json') }
        });

        finalFindings = aggResult.findings;
      }

      // Format and save report
      let formattedReport = '';
      if (options.format === 'json') {
        formattedReport = formatJSON(finalFindings);
      } else if (options.format === 'markdown') {
        formattedReport = formatMarkdown(finalFindings, { costInfo: agent.costTracker.total });
      } else {
        formatConsole(finalFindings);
      }

      if (options.output) {
        const savedPath = saveReport(formattedReport || formatJSON(finalFindings), options.output, options.format || 'json');
        console.log(`💾 Report successfully exported to: ${savedPath}`);
      }

      console.log('\n✅ Mythos scan completed successfully!');
    } catch (err) {
      console.error('❌ Mythos Scan failed:', err);
      process.exit(1);
    }
  })();
}
