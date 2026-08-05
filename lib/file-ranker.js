/**
 * Mythos Agent - File Ranker
 *
 * Ranks source files on a 1–5 scale, prioritizing:
 *   1. Internet-facing code (routes, controllers, request handlers)
 *   2. Authentication / authorization code
 *   3. Files with known dangerous sinks
 *
 * Public API:
 *   rankFiles(targetDir, options) — discover and rank all files
 *   rankFile(filePath, content)     — rank a single file
 *   rankFilesFromList(fileList)     — rank a pre-discovered list
 */

const { scoreFile, discoverFiles, scoreToRank } = require('./analysis-utils');

// ─── Ranking Constants ───────────────────────────────────────────────────────

/**
 * Rank labels and descriptions for each tier.
 */
const RANK_LABELS = {
  5: { label: 'CRITICAL', tag: '🔴', description: 'Internet-facing + auth + dangerous sinks — highest priority' },
  4: { label: 'HIGH',     tag: '🟠', description: 'Internet-facing with auth concerns or known sinks' },
  3: { label: 'MEDIUM',   tag: '🟡', description: 'Internet-facing or auth code without heavy sink density' },
  2: { label: 'LOW',      tag: '🔵', description: 'Some risk indicators but likely low exploitability' },
  1: { label: 'MINIMAL',  tag: '⚪', description: 'Minimal risk — utility files, config, docs-related code' },
};

/**
 * Configurable weight multipliers for the four scoring dimensions.
 * Adjust these to change ranking behavior.
 */
const DEFAULT_WEIGHTS = {
  internetFacing: 1.2,  // Boost internet-facing code
  auth:           1.1,  // Slight boost for auth code
  sinks:          1.0,  // Base weight for sink presence
  fileType:       0.8,  // De-emphasize file-type heuristics
};

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Discover and rank all source files in a target directory.
 *
 * @param {string} targetDir — Root directory to scan
 * @param {Object} [options]
 * @param {number} [options.maxFiles=100] — Max files to discover
 * @param {string[]} [options.excludeDirs] — Directories to skip
 * @param {string[]} [options.includeExts] — File extensions to include
 * @param {Object} [options.weights] — Custom scoring weights
 * @param {boolean} [options.includeUnranked=false] — Include files that scored 0
 * @returns {Array<{path, rank, score, breakdown, content, ext}>} — Ranked files, highest first
 */
function rankFiles(targetDir, options = {}) {
  const files = discoverFiles(targetDir, options);

  const ranked = files
    .map(f => {
      if (f.error) return { ...f, rank: 0, score: 0, breakdown: {}, error: f.error };
      const { score, rank, breakdown } = scoreFile(f.content, f.path);
      return { ...f, rank, score: Math.round(score), breakdown };
    })
    .filter(f => {
      if (options.includeUnranked) return true;
      return f.rank > 0; // Drop files that couldn't be scored
    })
    .sort(byRankThenScore);

  // Limit to maxFiles after ranking
  return options.maxFiles ? ranked.slice(0, options.maxFiles) : ranked;
}

/**
 * Rank a single file given its path and content string.
 *
 * @param {string} filePath  — Absolute or relative file path
 * @param {string} content   — File contents
 * @returns {{ path, rank, score, breakdown }}
 */
function rankFile(filePath, content) {
  const { score, rank, breakdown } = scoreFile(content, filePath);
  return {
    path: filePath,
    content,
    rank,
    score: Math.round(score),
    breakdown,
  };
}

/**
 * Rank files from a pre-discovered list (returned by discoverFiles()).
 * Useful when you already have the file list and want to re-rank or filter.
 *
 * @param {Array<{path, content}>} fileList
 * @param {Object} [options]
 * @returns {Array} — Sorted, ranked file list
 */
function rankFilesFromList(fileList, options = {}) {
  return fileList
    .map(f => {
      const { score, rank, breakdown } = scoreFile(f.content, f.path);
      return { ...f, rank, score: Math.round(score), breakdown };
    })
    .filter(f => f.rank > 0)
    .sort(byRankThenScore)
    .slice(0, options.maxFiles || fileList.length);
}

// ─── Filtering Helpers ──────────────────────────────────────────────────────

/**
 * Return only files ranked at or above a minimum rank (1-5).
 */
function filterByMinRank(rankedFiles, minRank) {
  return rankedFiles.filter(f => f.rank >= minRank);
}

/**
 * Group ranked files by their rank tier.
 * @returns {Record<number, Array>} — { 5: [...], 4: [...], ... }
 */
function groupByRank(rankedFiles) {
  const groups = { 5: [], 4: [], 3: [], 2: [], 1: [], 0: [] };
  for (const f of rankedFiles) {
    (groups[f.rank] || groups[0]).push(f);
  }
  return groups;
}

/**
 * Print a summary table of ranked files to stdout.
 */
function printRankSummary(rankedFiles) {
  const groups = groupByRank(rankedFiles);

  console.log('\n📊 File Rank Summary');
  console.log('═'.repeat(64));

  for (let r = 5; r >= 1; r--) {
    const bucket = groups[r] || [];
    const tag = RANK_LABELS[r].tag;
    const label = RANK_LABELS[r].label;
    console.log(`\n  ${tag} Rank ${r} — ${label} (${bucket.length} files)`);
    console.log('  ' + '─'.repeat(40));
    for (const f of bucket) {
      console.log(`    • ${f.path}  (score: ${f.score})`);
    }
  }

  const unranked = groups[0]?.length || 0;
  if (unranked > 0) {
    console.log(`\n  ⚪ Unlisted: ${unranked} files (score 0 or failed to read)`);
  }

  console.log('\n' + '═'.repeat(64));
}

// ─── Internal Helpers ────────────────────────────────────────────────────────

/**
 * Sort comparator: highest rank first, then highest score within same rank.
 */
function byRankThenScore(a, b) {
  if (b.rank !== a.rank) return b.rank - a.rank;
  return b.score - a.score;
}

// ─── Exports ─────────────────────────────────────────────────────────────────

module.exports = {
  // Core ranking
  rankFiles,
  rankFile,
  rankFilesFromList,

  // Filtering & grouping
  filterByMinRank,
  groupByRank,
  printRankSummary,

  // Constants
  RANK_LABELS,
  DEFAULT_WEIGHTS,
};