const path = require('path');
const { discoverFiles, scoreFile } = require('./analysis-utils');

function estimateTaskResources(files) {
  const fileCount = files.length;
  const totalRank = files.reduce((sum, file) => sum + (file.rank || 1), 0);
  const avgRank = fileCount ? totalRank / fileCount : 1;
  const totalSizeKB = files.reduce((sum, file) => sum + Math.max(0, file.size || 0) / 1024, 0);
  const avgSizeKB = fileCount ? totalSizeKB / fileCount : 0;

  const baseSeconds = 6;
  const estimatedSeconds = Math.max(
    5,
    baseSeconds + fileCount * 1.5 + avgRank * 2 + Math.sqrt(totalSizeKB)
  );
  const varianceSeconds = Math.max(1, estimatedSeconds * 0.3);

  const estimatedCost = parseFloat((fileCount * 0.03 + avgRank * 0.01).toFixed(4));
  const costVariance = parseFloat((estimatedCost * 0.25).toFixed(4));

  return {
    fileCount,
    avgRank: parseFloat(avgRank.toFixed(2)),
    avgSizeKB: parseFloat(avgSizeKB.toFixed(2)),
    estimatedTimeSeconds: Math.round(estimatedSeconds),
    estimatedTimeRangeSeconds: [
      Math.round(Math.max(1, estimatedSeconds - varianceSeconds)),
      Math.round(estimatedSeconds + varianceSeconds)
    ],
    estimatedCostUSD: estimatedCost,
    estimatedCostRangeUSD: [
      parseFloat(Math.max(0, estimatedCost - costVariance).toFixed(4)),
      parseFloat((estimatedCost + costVariance).toFixed(4))
    ]
  };
}

function buildScanPlan(targetDir, options = {}) {
  const {
    maxFiles = 1000,
    chunkSize = 10,
    includeHiddenDirs = false,
    minRank = 1,
    weights = null,
    excludeDirs,
    includeExts
  } = options;

  const files = discoverFiles(targetDir, {
    maxFiles,
    includeHiddenDirs,
    excludeDirs,
    includeExts
  });

  const ranked = files
    .map((file) => {
      const scored = scoreFile(file.content, file.path);
      const relativePath = path.relative(targetDir, file.path).replace(/\\/g, '/');
      return {
        ...file,
        ...scored,
        path: relativePath,
        absolutePath: file.path
      };
    })
    .filter((file) => file.rank >= minRank)
    .sort((a, b) => {
      if (b.rank !== a.rank) return b.rank - a.rank;
      if (b.score !== a.score) return b.score - a.score;
      return a.path.localeCompare(b.path);
    });

  const plan = [];
  for (let index = 0; index < ranked.length; index += chunkSize) {
    const chunk = ranked.slice(index, index + chunkSize);
    const chunkDirs = [...new Set(chunk.map((file) => path.dirname(file.path)))].filter((dir) => dir && dir !== '.');
    const summary = chunkDirs.length > 0 ? chunkDirs.join(', ') : ['root'];
    const taskResources = estimateTaskResources(chunk);

    plan.push({
      id: `task-${Math.floor(index / chunkSize) + 1}`,
      priority: chunk.reduce((sum, file) => sum + file.rank, 0) / chunk.length,
      rankSummary: {
        highestRank: Math.max(...chunk.map((file) => file.rank)),
        lowestRank: Math.min(...chunk.map((file) => file.rank)),
        avgRank: taskResources.avgRank
      },
      files: chunk.map((file) => file.path),
      absolutePaths: chunk.map((file) => file.absolutePath),
      directories: chunkDirs,
      description: `Analyze ${chunk.length} file(s) in ${summary}`,
      ...taskResources
    });
  }

  return plan;
}

module.exports = {
  buildScanPlan,
  estimateTaskResources
};
