// Mythos Agent - Node.js Implementation
// Based on Mythos Research Edition 8-phase vulnerability discovery scaffold

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
